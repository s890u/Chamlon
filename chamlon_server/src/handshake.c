#include "handshake.h"
#include "vpn_crypto.h"
#include "vpn_log.h"
#include "packet.h"
#include "session.h"
#include "scheduler.h"
#include "rate_limiter.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sodium.h>
#include <pthread.h>

#define ED25519_SK_LEN  crypto_sign_SECRETKEYBYTES   /* 64 */
#define ED25519_PK_LEN  crypto_sign_PUBLICKEYBYTES   /* 32 */
#define KEY_FILE_LEN    (ED25519_SK_LEN + ED25519_PK_LEN + PUBKEY_LEN)

static uint8_t g_sign_sk[ED25519_SK_LEN];
static int     g_sign_sk_loaded = 0;

static void zero_sign_sk(void) {
    sodium_memzero(g_sign_sk, sizeof(g_sign_sk));
}

/*
 * load_or_create_server_key:
 *
 * Key file layout:
 *   [  0.. 63]  Ed25519 secret key  (64 bytes)
 *   [ 64.. 95]  Ed25519 public key  (32 bytes)
 *   [ 96..127]  X25519  public key  (32 bytes)
 *
 * Returns via parameters:
 *   sk:        X25519 secret key (for DH in handle_msg1)
 *   pk:        X25519 public key (used internally for DH)
 *   sign_pk:   Ed25519 public key (publish this on the website,
 *               pass to clients as the server_pk argument)
 */
int load_or_create_server_key(const char *path,
                               uint8_t sk[PRIVKEY_LEN],
                               uint8_t pk[PUBKEY_LEN],
                               uint8_t sign_pk[ED25519_PK_LEN])
{
    uint8_t ed_sk[ED25519_SK_LEN];
    uint8_t ed_pk[ED25519_PK_LEN];
    uint8_t kx_pk[PUBKEY_LEN];

    FILE *f = fopen(path, "rb");
    if (f) {
        size_t r = 0;
        r += fread(ed_sk, 1, ED25519_SK_LEN, f);
        r += fread(ed_pk, 1, ED25519_PK_LEN, f);
        r += fread(kx_pk, 1, PUBKEY_LEN,     f);
        fclose(f);

        if (r == KEY_FILE_LEN) {
            if (crypto_sign_ed25519_sk_to_curve25519(sk, ed_sk) != 0) {
                vpn_log("Failed to convert Ed25519 sk to X25519");
                sodium_memzero(ed_sk, sizeof(ed_sk));
                return -1;
            }
            memcpy(pk,      kx_pk, PUBKEY_LEN);
            memcpy(sign_pk, ed_pk, ED25519_PK_LEN);

            memcpy(g_sign_sk, ed_sk, ED25519_SK_LEN);
            g_sign_sk_loaded = 1;
            atexit(zero_sign_sk);

            sodium_memzero(ed_sk, sizeof(ed_sk));
            vpn_log("Loaded server keys from %s", path);
            return 0;
        }
        vpn_log("Key file %s is corrupt, regenerating", path);
    }

    /* Generate fresh Ed25519 keypair */
    if (crypto_sign_keypair(ed_pk, ed_sk) != 0) {
        vpn_log("crypto_sign_keypair failed");
        return -1;
    }

    /* Derive X25519 keypair */
    uint8_t kx_sk_derived[PRIVKEY_LEN];
    if (crypto_sign_ed25519_sk_to_curve25519(kx_sk_derived, ed_sk) != 0) {
        vpn_log("Ed25519 sk -> X25519 sk conversion failed");
        sodium_memzero(ed_sk, sizeof(ed_sk));
        return -1;
    }
    if (crypto_sign_ed25519_pk_to_curve25519(pk, ed_pk) != 0) {
        vpn_log("Ed25519 pk -> X25519 pk conversion failed");
        sodium_memzero(ed_sk, sizeof(ed_sk));
        sodium_memzero(kx_sk_derived, sizeof(kx_sk_derived));
        return -1;
    }
    memcpy(sk,      kx_sk_derived, PRIVKEY_LEN);
    memcpy(sign_pk, ed_pk,         ED25519_PK_LEN);
    sodium_memzero(kx_sk_derived, sizeof(kx_sk_derived));

    /* Sanity check */
    if (memcmp(pk, ed_pk, PUBKEY_LEN) == 0) {
        vpn_log("FATAL: X25519 pk equals Ed25519 pk, conversion failed");
        sodium_memzero(ed_sk, sizeof(ed_sk));
        return -1;
    }

    /* Persist: ed_sk(64) | ed_pk(32) | kx_pk(32) */
    f = fopen(path, "wb");
    if (!f) {
        perror("fopen");
        sodium_memzero(ed_sk, sizeof(ed_sk));
        return -1;
    }
    int ok = (fwrite(ed_sk, 1, ED25519_SK_LEN, f) == ED25519_SK_LEN) &&
             (fwrite(ed_pk, 1, ED25519_PK_LEN, f) == ED25519_PK_LEN) &&
             (fwrite(pk,    1, PUBKEY_LEN,     f) == PUBKEY_LEN);
    fclose(f);
    if (!ok) {
        perror("fwrite");
        sodium_memzero(ed_sk, sizeof(ed_sk));
        return -1;
    }
    chmod(path, S_IRUSR | S_IWUSR);

    memcpy(g_sign_sk, ed_sk, ED25519_SK_LEN);
    g_sign_sk_loaded = 1;
    atexit(zero_sign_sk);

    sodium_memzero(ed_sk, sizeof(ed_sk));
    vpn_log("Generated new server keys, saved to %s (chmod 600)", path);
    return 0;
}

#define SIG_LEN         crypto_sign_BYTES
#define MSG2_SIGNED_LEN (PUBKEY_LEN + 8 + PUBKEY_LEN + 8)
#undef  MSG2_LEN
#define MSG2_LEN        (PUBKEY_LEN + 8 + 4 + SIG_LEN)

int handle_msg1(int udp_sock, uint8_t *msg1, ssize_t len,
                struct sockaddr_in *src, uint8_t server_sk[PRIVKEY_LEN])
{
    if (!g_sign_sk_loaded) {
        vpn_log("Signing key not loaded, call load_or_create_server_key first");
        return -1;
    }

    metrics_record_handshake_initiated();
    int rate_check = check_handshake_rate_limit(&src->sin_addr);
    if (rate_check == RATE_LIMIT_BLACKLISTED) {
        vpn_log("Dropped handshake from blacklisted IP %s", inet_ntoa(src->sin_addr));
        metrics_record_handshake_failed();
        metrics_record_blacklist_event();
        return -1;
    }
    if (rate_check == RATE_LIMIT_EXCEEDED) {
        vpn_log("Handshake rate limit exceeded for IP %s", inet_ntoa(src->sin_addr));
        metrics_record_handshake_failed();
        return -1;
    }

    if (len != (ssize_t)(sizeof(proto_header_t) + MSG1_LEN + PARAMS)) return -1;

    uint8_t c_pub[PUBKEY_LEN];
    uint8_t c_nonce[8];
    memcpy(c_pub,   msg1 + sizeof(proto_header_t),              PUBKEY_LEN);
    memcpy(c_nonce, msg1 + sizeof(proto_header_t) + PUBKEY_LEN, 8);

    uint8_t s_pub[PUBKEY_LEN], s_priv[PRIVKEY_LEN];
    crypto_kx_keypair(s_pub, s_priv);

    uint8_t s_nonce[8];
    randombytes_buf(s_nonce, sizeof(s_nonce));

    session_t *s = allocate_session();
    if (!s) {
        vpn_log("Max clients reached");
        metrics_record_handshake_failed();
        sodium_memzero(s_priv, sizeof(s_priv));
        return -1;
    }
    assign_vpn_ip_to_session(s);

    s->argv_MBPS = 5; s->argv_FRAG = 1024; s->argv_CBR = 'N'; s->argv_PAD = 'N';
    memcpy(&s->argv_MBPS, msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8,     4);
    memcpy(&s->argv_FRAG, msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 4, 4);
    memcpy(&s->argv_CBR,  msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 8, 1);
    memcpy(&s->argv_PAD,  msg1 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 9, 1);
    if (s->argv_MBPS < CONFIG_MIN_MBPS || s->argv_MBPS > CONFIG_MAX_MBPS)
        s->argv_MBPS = CONFIG_DEFAULT_MBPS;
    if (s->argv_FRAG < CONFIG_MIN_FRAG_PARAM || s->argv_FRAG > CONFIG_MAX_FRAG_PARAM)
        s->argv_FRAG = CONFIG_DEFAULT_FRAG_PARAM;
    if (s->argv_CBR != 'Y' && s->argv_CBR != 'N') s->argv_CBR = 'N';
    if (s->argv_PAD != 'Y' && s->argv_PAD != 'N') s->argv_PAD = 'N';

    /* Build signed blob: s_pub | s_nonce | c_pub | c_nonce */
    uint8_t to_sign[MSG2_SIGNED_LEN];
    memcpy(to_sign,                                  s_pub,   PUBKEY_LEN);
    memcpy(to_sign + PUBKEY_LEN,                     s_nonce, 8);
    memcpy(to_sign + PUBKEY_LEN + 8,                 c_pub,   PUBKEY_LEN);
    memcpy(to_sign + PUBKEY_LEN + 8 + PUBKEY_LEN,   c_nonce, 8);

    uint8_t sig[SIG_LEN];
    if (crypto_sign_detached(sig, NULL, to_sign, MSG2_SIGNED_LEN, g_sign_sk) != 0) {
        vpn_log("Signing MSG2 failed");
        sodium_memzero(s_priv, sizeof(s_priv));
        free_session(s);
        return -1;
    }

    /* Build MSG2: proto_header | s_pub(32) | s_nonce(8) | vpn_ip(4) | sig(64) */
    uint8_t msg2[sizeof(proto_header_t) + MSG2_LEN];
    proto_header_t ph;
    ph.magic   = PKT_MAGIC;
    ph.version = PKT_VERSION;
    ph.type    = PKT_TYPE_HANDSHAKE;
    memcpy(msg2,                                                &ph,       sizeof(proto_header_t));
    memcpy(msg2 + sizeof(proto_header_t),                       s_pub,     PUBKEY_LEN);
    memcpy(msg2 + sizeof(proto_header_t) + PUBKEY_LEN,          s_nonce,   8);
    memcpy(msg2 + sizeof(proto_header_t) + PUBKEY_LEN + 8,      s->vpn_ip, 4);
    memcpy(msg2 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 4,  sig,       SIG_LEN);

    uint8_t dh1[DH_LEN], dh2[DH_LEN], shared[DH_LEN*2], context[16];
    if (crypto_scalarmult(dh1, s_priv,    c_pub) != 0) goto fail_dh;
    if (crypto_scalarmult(dh2, server_sk, c_pub) != 0) goto fail_dh;
    memcpy(shared,          dh1,     DH_LEN);
    memcpy(shared + DH_LEN, dh2,     DH_LEN);
    memcpy(context,         c_nonce, 8);
    memcpy(context + 8,     s_nonce, 8);

    uint8_t k1[AEAD_KEY_LEN], k2[AEAD_KEY_LEN];
    derive_two_keys(shared, sizeof(shared), context, sizeof(context), k1, k2);
    memcpy(s->k_recv, k1, AEAD_KEY_LEN);
    memcpy(s->k_send, k2, AEAD_KEY_LEN);
    s->s_udp_sock = udp_sock;
    uint8_t sid_input[DH_LEN*2 + 8 + 8 + PUBKEY_LEN + PUBKEY_LEN];
    memcpy(sid_input,                                shared,  DH_LEN*2);
    memcpy(sid_input + DH_LEN*2,                     c_nonce, 8);
    memcpy(sid_input + DH_LEN*2 + 8,                 s_nonce, 8);
    memcpy(sid_input + DH_LEN*2 + 8 + 8,             c_pub,   PUBKEY_LEN);
    memcpy(sid_input + DH_LEN*2 + 8 + 8 + PUBKEY_LEN, s_pub,  PUBKEY_LEN);
    crypto_generichash(s->session_id, SESSION_ID_LEN,
                       sid_input, sizeof(sid_input),
                       NULL, 0);
    sodium_memzero(sid_input, sizeof(sid_input));

    prepare_dummy_static_parts(s);
    s->send_seq       = 0;
    s->last_recv_seq  = 0;
    s->active         = 1;
    pthread_rwlock_wrlock(&sessions_rwlock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        session_t *old = &sessions[i];
        if (old == s) continue;
        if (!old->active) continue;
        if (old->client_addr.sin_addr.s_addr == src->sin_addr.s_addr &&
            old->client_addr.sin_port        == src->sin_port) {
            vpn_log("Re-handshake: freeing old session slot %d", i);
            sodium_memzero(old->k_recv,     AEAD_KEY_LEN);
            sodium_memzero(old->k_send,     AEAD_KEY_LEN);
            sodium_memzero(old->session_id, SESSION_ID_LEN);
            if (old->outq) { out_queue_destroy(old->outq); free(old->outq); old->outq = NULL; }
            old->active = 0;
            metrics_record_connection_closed();
            break;
        }
    }
    pthread_rwlock_unlock(&sessions_rwlock);
    s->client_addr    = *src;
    s->client_addrlen = sizeof(*src);
    pthread_mutex_init(&s->seq_lock, NULL);
    s->last_activity  = time(NULL);
    s->outq = malloc(sizeof(out_queue_t));
    if (!s->outq) { vpn_log("malloc failed for outq"); goto fail_dh; }
    out_queue_init(s->outq);
    scheduler_add_session(s->session_id);

    if (sendto(udp_sock, msg2, sizeof(msg2), 0,
               (struct sockaddr*)src, sizeof(*src)) != (ssize_t)sizeof(msg2)) {
        perror("sendto MSG2");
        sodium_memzero(s_priv, sizeof(s_priv));
        sodium_memzero(sig,    sizeof(sig));
        free_session(s);
        return -1;
    }

    vpn_log("Sent MSG2 (signed) to %s:%d assigned %u.%u.%u.%u",
            inet_ntoa(src->sin_addr), ntohs(src->sin_port),
            s->vpn_ip[0], s->vpn_ip[1], s->vpn_ip[2], s->vpn_ip[3]);

    metrics_record_handshake_completed();
    metrics_record_connection_established();
    vpn_log("New session %s:%d -> VPN %u.%u.%u.%u",
            inet_ntoa(src->sin_addr), ntohs(src->sin_port),
            s->vpn_ip[0], s->vpn_ip[1], s->vpn_ip[2], s->vpn_ip[3]);
    s->last_activity_keepalive = time(NULL);

    sodium_memzero(s_priv, sizeof(s_priv));
    sodium_memzero(dh1,    sizeof(dh1));
    sodium_memzero(dh2,    sizeof(dh2));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(k1,     sizeof(k1));
    sodium_memzero(k2,     sizeof(k2));
    sodium_memzero(sig,    sizeof(sig));
    return 0;

fail_dh:
    sodium_memzero(s_priv, sizeof(s_priv));
    sodium_memzero(dh1,    sizeof(dh1));
    sodium_memzero(dh2,    sizeof(dh2));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(sig,    sizeof(sig));
    free_session(s);
    return -1;
}


int handle_rehandshake_msg1(int udp_sock, uint8_t *msg1, ssize_t len,
                             struct sockaddr_in *src, uint8_t server_sk[PRIVKEY_LEN])
{
    if (len != (ssize_t)(sizeof(proto_header_t) + MSG1_LEN + PARAMS)) {
        vpn_log("Rehandshake MSG1: invalid length from %s", inet_ntoa(src->sin_addr));
        return -1;
    }
    
    session_t *s = NULL;
    pthread_rwlock_rdlock(&sessions_rwlock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (sessions[i].active &&
            sessions[i].client_addr.sin_addr.s_addr == src->sin_addr.s_addr &&
            sessions[i].client_addr.sin_port        == src->sin_port) {
            s = &sessions[i];
            break;
        }
    }
    pthread_rwlock_unlock(&sessions_rwlock);

    if (!s) {
        // No existing session, fall back to normal handshake
        vpn_log("Rehandshake: no existing session for %s, using normal handshake", 
                inet_ntoa(src->sin_addr));
        return handle_msg1(udp_sock, msg1, len, src, server_sk);
    }

    vpn_log("Rehandshake: initiating key rotation for session %s:%d (VPN %u.%u.%u.%u)",
            inet_ntoa(src->sin_addr), ntohs(src->sin_port),
            s->vpn_ip[0], s->vpn_ip[1], s->vpn_ip[2], s->vpn_ip[3]);

    // Generate new ephemeral keypair and nonce
    uint8_t s_pub[PUBKEY_LEN], s_priv[PRIVKEY_LEN];
    uint8_t s_nonce[8];
    crypto_kx_keypair(s_pub, s_priv);
    randombytes_buf(s_nonce, sizeof(s_nonce));

    uint8_t c_pub[PUBKEY_LEN], c_nonce[8];
    memcpy(c_pub,   msg1 + sizeof(proto_header_t),               PUBKEY_LEN);
    memcpy(c_nonce, msg1 + sizeof(proto_header_t) + PUBKEY_LEN,  8);

    // Do all crypto before sending MSG2
    uint8_t dh1[DH_LEN], dh2[DH_LEN], shared[DH_LEN*2], context[16];
    if (crypto_scalarmult(dh1, s_priv,    c_pub) != 0) goto fail;
    if (crypto_scalarmult(dh2, server_sk, c_pub) != 0) goto fail;
    memcpy(shared,          dh1,     DH_LEN);
    memcpy(shared + DH_LEN, dh2,     DH_LEN);
    memcpy(context,         c_nonce, 8);
    memcpy(context + 8,     s_nonce, 8);

    uint8_t k1[AEAD_KEY_LEN], k2[AEAD_KEY_LEN];
    derive_two_keys(shared, sizeof(shared), context, sizeof(context), k1, k2);

    uint8_t new_sid[SESSION_ID_LEN];
    uint8_t sid_input[DH_LEN*2 + 8 + 8 + PUBKEY_LEN + PUBKEY_LEN];
    memcpy(sid_input,                                  shared,  DH_LEN*2);
    memcpy(sid_input + DH_LEN*2,                       c_nonce, 8);
    memcpy(sid_input + DH_LEN*2 + 8,                   s_nonce, 8);
    memcpy(sid_input + DH_LEN*2 + 8 + 8,               c_pub,   PUBKEY_LEN);
    memcpy(sid_input + DH_LEN*2 + 8 + 8 + PUBKEY_LEN,  s_pub,   PUBKEY_LEN);
    crypto_generichash(new_sid, SESSION_ID_LEN,
                       sid_input, sizeof(sid_input), NULL, 0);
    sodium_memzero(sid_input, sizeof(sid_input));

    // Sign MSG2
    uint8_t to_sign[MSG2_SIGNED_LEN];
    memcpy(to_sign,                                s_pub,   PUBKEY_LEN);
    memcpy(to_sign + PUBKEY_LEN,                   s_nonce, 8);
    memcpy(to_sign + PUBKEY_LEN + 8,               c_pub,   PUBKEY_LEN);
    memcpy(to_sign + PUBKEY_LEN + 8 + PUBKEY_LEN,  c_nonce, 8);
    uint8_t sig[SIG_LEN];
    if (crypto_sign_detached(sig, NULL, to_sign, MSG2_SIGNED_LEN, g_sign_sk) != 0)
        goto fail;

    // Build MSG2
    uint8_t msg2[sizeof(proto_header_t) + MSG2_LEN];
    proto_header_t ph = { PKT_MAGIC, PKT_VERSION, PKT_TYPE_HANDSHAKE };
    memcpy(msg2,                                               &ph,      sizeof(proto_header_t));
    memcpy(msg2 + sizeof(proto_header_t),                      s_pub,    PUBKEY_LEN);
    memcpy(msg2 + sizeof(proto_header_t) + PUBKEY_LEN,         s_nonce,  8);
    memcpy(msg2 + sizeof(proto_header_t) + PUBKEY_LEN + 8,     s->vpn_ip, 4); // SAME vpn_ip
    memcpy(msg2 + sizeof(proto_header_t) + PUBKEY_LEN + 8 + 4, sig,      SIG_LEN);

    // Atomically swap keys on the EXISTING session
    pthread_rwlock_wrlock(&sessions_rwlock);
    memcpy(s->k_recv,     k1,      AEAD_KEY_LEN);
    memcpy(s->k_send,     k2,      AEAD_KEY_LEN);
    memcpy(s->session_id, new_sid, SESSION_ID_LEN);

    if (s->outq) {
        out_queue_destroy(s->outq);
        free(s->outq);
        s->outq = NULL;
    }
    s->outq = malloc(sizeof(out_queue_t));
    if (s->outq) {
        out_queue_init(s->outq);
    } else {
        vpn_log("Rehandshake: failed to reallocate outq for session");
    }

    prepare_dummy_static_parts(s);
    atomic_store(&s->send_seq, 0);
    memset(&s->rw, 0, sizeof(s->rw));  // ← reset replay window
    s->last_recv_seq = 0;               // ← reset last recv seq
    s->last_activity = time(NULL);
    pthread_rwlock_unlock(&sessions_rwlock);

    scheduler_add_session(s->session_id);

    vpn_log("Rehandshake: new k_recv[0..3]: %02x %02x %02x %02x",
        k1[0], k1[1], k1[2], k1[3]);

    // NOW send MSG2, session already has new keys active
    if (sendto(udp_sock, msg2, sizeof(msg2), 0,
               (struct sockaddr*)src, sizeof(*src)) < 0) {
        perror("sendto rehandshake MSG2");
    }
    
    vpn_log("Rehandshake: MSG2 sent, keys rotated for %s:%d",
            inet_ntoa(src->sin_addr), ntohs(src->sin_port));

    sodium_memzero(s_priv, sizeof(s_priv));
    sodium_memzero(k1,     sizeof(k1));
    sodium_memzero(k2,     sizeof(k2));
    sodium_memzero(shared, sizeof(shared));
    sodium_memzero(sig,    sizeof(sig));
    return 0;

fail:
    vpn_log("Rehandshake: cryptography failed for %s:%d, falling back to normal handshake",
            inet_ntoa(src->sin_addr), ntohs(src->sin_port));
    sodium_memzero(s_priv, sizeof(s_priv));
    sodium_memzero(k1,     sizeof(k1));
    sodium_memzero(k2,     sizeof(k2));
    sodium_memzero(shared, sizeof(shared));
    return handle_msg1(udp_sock, msg1, len, src, server_sk);
}
