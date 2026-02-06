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

1. **Identity**: Ed25519 keypair, stored encrypted with your passphrase
2. **Transport**: Noise protocol via libp2p
3. **Messages**: X25519 + XChaCha20-Poly1305 (libsodium sealed box)
4. **Storage**: SQLite encrypted at rest

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

## Building

```bash
cargo build --release
```

## License

MIT

## Author

Katie

---

*Your messages. Your keys. Your network.*
