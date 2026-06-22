#ifndef CONFIG_H
#define CONFIG_H

/**
 * VPN Server Configuration
 * All tunable parameters and configuration constants are defined here.
 */

/*  NETWORK & BUFFER CONFIGURATION  */
/** Maximum buffer size for UDP packets (bytes) */
#define CONFIG_BUFFER_SIZE              1600

/** Maximum fragment size (bytes) */
#define CONFIG_MAX_FRAG                 1600

/** Packet payload size (bytes) */
#define CONFIG_PACKET_LENGTH            1024

/** Maximum packet size for reassembly (bytes) */
#define CONFIG_MAX_PACKET_SIZE          2500

/*  SESSION MANAGEMENT  */
/** Maximum number of concurrent client sessions */
#define CONFIG_MAX_CLIENTS              250

/** Session inactivity timeout (seconds) */
#define CONFIG_SESSION_TIMEOUT_SEC      60

/** Keepalive interval (seconds) */
#define CONFIG_KEEPALIVE_INTERVAL_SEC   10

/*  GRACEFUL SHUTDOWN  */
/** Graceful shutdown timeout (seconds) */
#define CONFIG_GRACEFUL_SHUTDOWN_TIMEOUT_SEC  10

/*  REPLAY WINDOW  */
/** Sliding window size for packet reassembly */
#define CONFIG_SLIDING_WINDOW_SIZE      128

/** Replay window size (RFC 4303 minimum is 64) */
#define CONFIG_WINDOW_SIZE              64

/** Word size for bitmap operations (bits) */
#define CONFIG_WORD_SIZE                64

/** Number of bitmap words for replay window */
#define CONFIG_BITMAP_WORDS             (CONFIG_WINDOW_SIZE / CONFIG_WORD_SIZE)

/*  FRAGMENTATION & REASSEMBLY  */
/** Maximum reassembly entries per session */
#define CONFIG_MAX_REASSEMBLY_ENTRIES   256

/** Reassembly timeout (seconds) */
#define CONFIG_REASSEMBLY_TIMEOUT_SEC   20

/*  CLIENT PARAMETER VALIDATION  */
/** Minimum bitrate parameter (Mbps) */
#define CONFIG_MIN_MBPS                 1

/** Maximum bitrate parameter (Mbps) */
#define CONFIG_MAX_MBPS                 15

/** Default bitrate parameter (Mbps) */
#define CONFIG_DEFAULT_MBPS             5

/** Minimum fragment size parameter (bytes) */
#define CONFIG_MIN_FRAG_PARAM           64

/** Maximum fragment size parameter (bytes) */
#define CONFIG_MAX_FRAG_PARAM           1200

/** Default fragment size parameter (bytes) */
#define CONFIG_DEFAULT_FRAG_PARAM       1024

/*  CRYPTOGRAPHIC CONSTANTS  */
/** Session ID length (bytes) */
#define CONFIG_SESSION_ID_LEN           16

/*  RATE LIMITING & FLAGS  */
/** Maximum relays allowed for a node */
#define CONFIG_MAX_RELAYS_ALLOWED       0x02

/*  PACKET PROTOCOL CONSTANTS  */
/** Packet magic number for validation */
#define CONFIG_PKT_MAGIC                0x77E1DAu

/** Packet protocol version */
#define CONFIG_PKT_VERSION              1

/** Packet type for handshake messages */
#define CONFIG_PKT_TYPE_HANDSHAKE       222

/** Packet type for data messages */
#define CONFIG_PKT_TYPE_DATA            111

/* MACROS */
/** Validate MBPS parameter is within acceptable range */
#define IS_VALID_MBPS(mbps) \
    ((mbps) >= CONFIG_MIN_MBPS && (mbps) <= CONFIG_MAX_MBPS)

/** Validate fragment parameter is within acceptable range */
#define IS_VALID_FRAG_PARAM(frag) \
    ((frag) >= CONFIG_MIN_FRAG_PARAM && (frag) <= CONFIG_MAX_FRAG_PARAM)

#endif /* CONFIG_H */
