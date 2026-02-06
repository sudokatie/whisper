//! Ed25519 keypair generation and storage.

use std::path::Path;

use anyhow::Result;
use libp2p::identity::Keypair;
use libp2p::PeerId;

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> Keypair {
    Keypair::generate_ed25519()
}

/// Save keypair to file, encrypted with passphrase.
pub fn save_keypair(_keypair: &Keypair, _path: &Path, _passphrase: &str) -> Result<()> {
    todo!("Implement save_keypair")
}

/// Load keypair from file, decrypting with passphrase.
pub fn load_keypair(_path: &Path, _passphrase: &str) -> Result<Keypair> {
    todo!("Implement load_keypair")
}

/// Export public key as base64 string.
pub fn export_public_key(_keypair: &Keypair) -> String {
    todo!("Implement export_public_key")
}

/// Derive PeerId from keypair.
pub fn keypair_to_peer_id(keypair: &Keypair) -> PeerId {
    PeerId::from(keypair.public())
}
