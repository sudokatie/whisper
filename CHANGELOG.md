# Changelog

All notable changes to Whisper will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-07

### Added

#### Identity
- Ed25519 keypair generation and management
- Passphrase-encrypted keypair storage (Argon2 + XChaCha20-Poly1305)
- Contact management with alias support
- Trust levels: Unknown, Verified, Trusted, Blocked

#### Cryptography
- Sealed box encryption for direct messages (X25519 + XChaCha20-Poly1305)
- Symmetric encryption for group messages (XChaCha20-Poly1305)
- X25519 key exchange for shared secrets
- Key serialization and import/export

#### Messaging
- Text messages with unique IDs
- Delivery receipts (Delivered, Read)
- Message status tracking (Pending, Sent, Delivered, Read, Failed)
- Offline message queue with per-peer FIFO
- Message sync with deduplication and merge

#### Networking
- libp2p swarm with TCP transport
- Noise protocol for secure connections
- mDNS for local peer discovery
- Kademlia DHT for global peer discovery
- Relay support for NAT traversal
- Request-response protocol for message exchange

#### Storage
- SQLite database for messages and contacts
- Message history with peer filtering
- Contact persistence with trust levels

#### Interface
- Terminal UI with ratatui
- Chat, Contacts, and Input modes
- Keyboard navigation
- Status bar with peer count

#### CLI
- `init` - Create new identity
- `send` - Send message to contact
- `chat` - Interactive chat session
- `contacts` - List all contacts
- `add` - Add new contact
- `trust` - Mark contact as trusted
- `block` - Block a contact
- `status` - Show network status

### Notes

This is the initial release of Whisper. The core messaging functionality is complete, but the interactive chat mode is still in development.

---

## Future Plans

- [ ] Interactive TUI chat mode
- [ ] File transfer support
- [ ] Voice messages
- [ ] Group chat creation
- [ ] Contact verification via QR codes
- [ ] Mobile companion app
