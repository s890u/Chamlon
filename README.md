# Chamlon VPN

A lightweight, encrypted VPN built from scratch in C and Python. Chamlon tunnels IP traffic over UDP using modern authenticated encryption (ChaCha20-Poly1305), with a graphical client interface built in PyQt5.

---

## Installation

Clone the repository and run the setup script. It will install all system and Python dependencies, then compile both the server and client:

```bash
git clone <repo-url>
chmod +x setup.sh
./setup.sh
```

This installs `libsodium`, builds `chamlon_server` and `chamlon_client` via `make`, and installs the Python GUI dependencies.

---

## Project Structure

```
chamlon/
├── chamlon_server/       # VPN server (C)
├── chamlon_client/       # VPN client (C)
├── chamlon_utilities/    # Shared utilities
├── chamlon.py            # Graphical client launcher (PyQt5)
└── setup.sh              # One-shot installer and builder
```

---

## How It Works

### Overview

Chamlon creates an encrypted tunnel between a client and a server. All traffic is sent over UDP and encrypted end-to-end. The server assigns each connected client a private IP address in the `10.10.0.0/24` subnet and forwards their traffic to the internet using NAT.

```
[Client App]
     │  (plain IP traffic)
     ▼
[TUN interface]
     │  encrypt + fragment
     ▼
[UDP socket] ──────────────────► [UDP socket]
                                       │  decrypt + reassemble
                                       ▼
                                 [TUN interface]
                                       │  (plain IP traffic → Internet)
                                       ▼
                                  [NAT / Internet]
```

### Handshake

Before any data is exchanged, client and server perform a cryptographic handshake to establish a shared session key:

1. **Client → Server (MSG1):** The client sends its ephemeral X25519 public key and a random nonce.
2. **Server → Client (MSG2):** The server replies with its own ephemeral public key, nonce, the assigned VPN IP, and a signature over both sides' keys and nonces using its long-term Ed25519 identity key. The client verifies this signature to authenticate the server.
3. **Both sides** independently derive two symmetric session keys (send and receive) from the Diffie-Hellman shared secret using BLAKE2b, and a unique `session_id` used to identify all future packets.

This design provides:
- **Server authentication** via the Ed25519 signature
- **Forward secrecy** via ephemeral X25519 keys (past sessions cannot be decrypted if the server's long-term key is later compromised)

### Data Transfer

Once the session is established:

- Each packet is **fragmented** if it exceeds the configured MTU.
- Each fragment is **encrypted** with ChaCha20-Poly1305 (AEAD), with the `session_id` and sequence number as authenticated data. This prevents tampering and replay attacks.
- The server maintains a **sliding window** per session to detect and discard duplicate or replayed packets.

### Session Management

- The server supports up to **250 simultaneous clients**.
- Each client is assigned a VPN IP from `10.10.0.2` to `10.10.0.251`.
- Sessions inactive for more than **60 seconds** are cleaned up automatically.
- The server sends **keepalive packets** every 10 seconds to maintain sessions through NAT.

### Rate Limiting & Security

- Handshake attempts per IP are rate-limited to prevent abuse.
- Data packet rates are also limited per session.
- IPs that exceed limits are temporarily blacklisted.
- Cryptographic material (session keys, session IDs) is zeroed from memory when a session ends.

---

## Requirements

- Linux (tested on Ubuntu/Debian)
- `sudo` / root privileges (required for TUN interface and iptables)
- `libsodium-dev`
- `python3`, `pip3`, `PyQt5`

---

## Running the Server

The server requires root to manage the TUN interface and iptables NAT rules.

```bash
cd chamlon_server
sudo ./chamlon_server <bind-ip> <port>

# Example: listen on all interfaces, port 55555
sudo ./chamlon_server 0.0.0.0 55555
```

On startup, the server will print its **Ed25519 public key**. Copy this since clients need it to verify the server's identity.

---

## Running the Client

### Graphical interface

```bash
sudo python3 chamlon.py
```

Enter the server's IP, port, and public key in the GUI to connect.

### Command-line client

```bash
cd chamlon_client
sudo ./chamlon_client <server-ip> <port> <server-public-key> [options]

# Example: listen on all interfaces, port 55555
sudo ./chamlon_client <server-ip> <port> <server-public-key> MBPS:5 FRAG:Y:900 CBR:N PAD:Y REHANDSHAKE:120 TUN:interface_client

```

Once connected, the client is assigned a VPN IP (e.g. `10.10.0.2`) and all traffic is tunnelled through the server.

---

## Configuration

Core parameters are defined at compile time in `chamlon_server/include/config.h`:

| Parameter | Default | Description |
|---|---|---|
| `MAX_CLIENTS` | 250 | Maximum simultaneous clients |
| `SESSION_TIMEOUT_SEC` | 60 | Seconds before idle session is dropped |
| `KEEPALIVE_INTERVAL_SEC` | 10 | Keepalive interval |
| `MAX_FRAG` | 1600 | Maximum encrypted fragment size (bytes) |
| `WINDOW_SIZE` | 64 | Replay detection window |

---

## Security Notes

- The server's long-term identity key is stored in `server_static.key` (auto-generated on first run). **Keep this file private.**
- The NAT output interface is currently hardcoded in `tun.c`. If your server's public interface is not `enp0s3`, edit `setup_nat()` accordingly before building.
- Chamlon uses only [libsodium](https://libsodium.org) for all cryptographic operations.

---

## Dependencies

| Component | Technology |
|---|---|
| Server & Client | C (C17), libsodium |
| GUI | Python 3, PyQt5 |
| Encryption | ChaCha20-Poly1305 (AEAD) |
| Key exchange | X25519 (Diffie-Hellman) |
| Server auth | Ed25519 signatures |
| Key derivation | BLAKE2b |
| Network | UDP + Linux TUN + iptables NAT |
