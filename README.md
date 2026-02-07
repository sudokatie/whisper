# Whisper

Decentralized peer-to-peer messaging. No servers. No tracking. Just you and whoever you're talking to.

## Why This Exists

Every major messaging app routes your conversations through someone else's servers. Even "encrypted" ones see your metadata: who you talk to, when, how often. They store your messages on their infrastructure, subject to their policies, their security, their decisions about what to do with your data.

Whisper doesn't work that way. Your messages travel directly between you and your contacts using libp2p. There are no servers to compromise, no metadata to harvest, no terms of service to accept. Your identity is a keypair you control. Your messages are encrypted end-to-end with keys only you and your recipient possess.

## Features

- **True P2P**: Messages travel directly between peers. No servers required.
- **End-to-end encryption**: Every message encrypted with libsodium sealed boxes.
- **Self-sovereign identity**: Your identity is an Ed25519 keypair you generate and control.
- **Local discovery**: Find contacts on your local network via mDNS.
- **Global discovery**: Connect with anyone using Kademlia DHT.
- **NAT traversal**: Works behind firewalls using relay nodes.
- **Offline queuing**: Messages wait until your contact comes online.
- **Terminal UI**: Clean, fast interface that works anywhere.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/sudokatie/whisper
cd whisper

# Build release binary
cargo build --release

# Install (optional)
cargo install --path .
```

### Requirements

- Rust 1.75+ (for async features)
- libsodium (bundled via sodiumoxide)

## Quick Start

```bash
# Initialize your identity
whisper init

# Add a contact (they give you their peer ID)
whisper add alice 12D3KooW...

# Send a message
whisper send alice "Hey, this is pretty cool"

# Open interactive chat
whisper chat alice

# Check network status
whisper status
```

## Security Model

### Identity
Your identity is an Ed25519 keypair stored locally, encrypted with your passphrase using Argon2 key derivation and XChaCha20-Poly1305.

### Transport
All peer connections use the Noise protocol via libp2p, providing mutual authentication and forward secrecy.

### Messages
Direct messages use X25519 sealed boxes (libsodium), providing:
- Asymmetric encryption (only recipient can decrypt)
- Anonymous sender (recipient verifies via other channels)
- No key exchange required (uses recipient's public key directly)

Group messages use XChaCha20-Poly1305 with a shared symmetric key distributed to members.

### Storage
Messages are stored in SQLite. The database can be encrypted at rest using SQLCipher (optional).

## Commands

| Command | Description |
|---------|-------------|
| `init` | Create a new identity |
| `send <alias> <msg>` | Send a message |
| `chat <alias>` | Interactive chat |
| `contacts` | List contacts |
| `add <alias> <peer_id>` | Add contact |
| `trust <alias>` | Mark as trusted |
| `block <alias>` | Block contact |
| `status` | Network status |

### Options

```
--data-dir <path>     Data directory (default: ~/.whisper)
--passphrase <pass>   Keypair passphrase (or set WHISPER_PASSPHRASE)
```

## Architecture

```
whisper/
├── src/
│   ├── identity/      # Keypair generation, contact management
│   ├── crypto/        # Encryption, key exchange, group keys
│   ├── message/       # Message types, queue, sync
│   ├── network/       # libp2p behaviour, discovery, relay
│   ├── storage/       # SQLite database
│   ├── ui/            # Terminal interface (ratatui)
│   └── cli/           # Command handlers
├── tests/             # Integration tests
└── docs/              # Build documentation
```

### Key Dependencies

- **libp2p**: P2P networking (mDNS, Kademlia, relay)
- **sodiumoxide**: Cryptography (sealed boxes, secretbox)
- **rusqlite**: SQLite database
- **ratatui**: Terminal UI
- **tokio**: Async runtime

## Development

```bash
# Run tests
cargo test

# Run with logging
RUST_LOG=whisper=debug cargo run -- status

# Check for issues
cargo clippy
```

## Contributing

Pull requests welcome. Please run tests and clippy before submitting.

## License

MIT

## Author

Katie

---

*Your messages. Your keys. Your network.*
