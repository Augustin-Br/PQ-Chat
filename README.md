# PQ-Chat: Post-Quantum Secure Chat

PQ-Chat is a secure instant messaging client and server written in Go, implementing a network architecture protected by hybrid cryptography (Post-Quantum and Symmetric).

This project demonstrates the integration of Key Encapsulation Mechanisms (KEM) resistant to quantum computers, along with a robust implementation of an encrypted and authenticated communication tunnel.

## Cryptographic Architecture

The security protocol is divided into two distinct phases:

### 1\. Post-Quantum Handshake (KEM)

The establishment of the shared secret relies on the **Kyber1024** algorithm (via the Cloudflare Circl library).

- The server generates an ephemeral Kyber key pair for each new connection.

- The client uses the server's public key to encapsulate a 32-byte shared secret.

- The server decapsulates this secret using its private key.

### 2\. Secure Transport (AES-256-GCM)

Once the 32-byte secret is established, the communication switches to **AES-256-GCM** symmetric encryption.

- **Confidentiality & Integrity:** The GCM mode authenticates every message, ensuring it has not been tampered with in transit.

- **Anti-Replay (Stateful Nonces):** 12-byte nonces are generated from strict sequence counters (`sendCounter` / `recvCounter`) protected by `sync.Mutex`. This prevents replay attacks without needing to transmit the nonce over the network.

## Network & Security Features

- **Cryptographic Router:** The architecture uses a Client-Server model. The server decrypts incoming messages and individually re-encrypts them for each recipient using their unique session key.

- **Anti-Spoofing (Zero Trust):** The server actively manages user identities. Instead of trusting the `Sender` field provided by the client, the server binds the TCP connection to a username upon the first message. It then systematically overwrites the sender field of all subsequent messages with this stored username, completely preventing identity spoofing.

- **Secure JSON Serialization:** The network protocol relies on streaming JSON (`json.Encoder`/`Decoder`). Encrypted binary payloads are encoded in Base64 to maintain protocol compatibility.

## Roadmap

While the current architecture ensures a secure transport layer (client-server encryption), the next major steps aim to evolve the system to improve security and usability:

- End-to-end encryption (E2EE): Modify the architecture so that the key exchange (handshake) takes place directly between clients. The server will no longer be able to decrypt messages and will act strictly as a blind relay (zero-knowledge).

- Direct messaging (1-to-1): Replace the current global broadcast system with targeted routing. This will enable exclusive private conversations between two clients, without sending encrypted packets to all connected users.

## Project Structure

- `cmd/server/`: Source code for the central router (handles concurrency, cryptographic sessions, and identity enforcement).

- `cmd/client/`: Terminal user interface managing local encryption/decryption and asynchronous display.

- `internal/crypto/`: Cryptographic engine encapsulating Kyber1024 KEM and AES-GCM logic.

- `internal/network/`: Definition of the network exchange protocol structures.

## How to Run

This project requires Go 1.24.4 or higher.

**1\. Start the Server**

Open a terminal and start the server, which will listen on port `:8080`:

```bash
go run cmd/server/main.go
```

**2\. Start the Clients**

Open one or multiple other terminals to start the clients:

```bash
go run cmd/client/main.go
```

