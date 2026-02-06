//! Ed25519 keypair generation and storage.

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use libp2p::identity::Keypair;
use libp2p::PeerId;
use sodiumoxide::crypto::pwhash;
use sodiumoxide::crypto::secretbox;

/// Generate a new Ed25519 keypair.
pub fn generate_keypair() -> Keypair {
    Keypair::generate_ed25519()
}

/// Derive encryption key from passphrase using Argon2.
fn derive_key(passphrase: &str, salt: &pwhash::Salt) -> Result<secretbox::Key> {
    let mut key_bytes = [0u8; secretbox::KEYBYTES];
    pwhash::derive_key(
        &mut key_bytes,
        passphrase.as_bytes(),
        salt,
        pwhash::OPSLIMIT_INTERACTIVE,
        pwhash::MEMLIMIT_INTERACTIVE,
    )
    .map_err(|_| anyhow!("Failed to derive key from passphrase"))?;
    Ok(secretbox::Key(key_bytes))
}

/// Save keypair to file, encrypted with passphrase.
///
/// Format: salt (32 bytes) || nonce (24 bytes) || ciphertext
pub fn save_keypair(keypair: &Keypair, path: &Path, passphrase: &str) -> Result<()> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to init sodiumoxide"))?;

    // Get the secret key bytes
    let keypair_bytes = keypair
        .to_protobuf_encoding()
        .context("Failed to encode keypair")?;

    // Generate salt and derive key
    let salt = pwhash::gen_salt();
    let key = derive_key(passphrase, &salt)?;

    // Encrypt
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(&keypair_bytes, &nonce, &key);

    // Write: salt || nonce || ciphertext
    let mut output = Vec::with_capacity(32 + 24 + ciphertext.len());
    output.extend_from_slice(&salt.0);
    output.extend_from_slice(&nonce.0);
    output.extend_from_slice(&ciphertext);

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, &output).context("Failed to write keypair file")?;
    Ok(())
}

/// Load keypair from file, decrypting with passphrase.
pub fn load_keypair(path: &Path, passphrase: &str) -> Result<Keypair> {
    sodiumoxide::init().map_err(|_| anyhow!("Failed to init sodiumoxide"))?;

    let data = fs::read(path).context("Failed to read keypair file")?;

    if data.len() < 32 + 24 + 1 {
        return Err(anyhow!("Invalid keypair file: too short"));
    }

    // Parse: salt || nonce || ciphertext
    let salt = pwhash::Salt::from_slice(&data[..32]).ok_or_else(|| anyhow!("Invalid salt"))?;
    let nonce =
        secretbox::Nonce::from_slice(&data[32..56]).ok_or_else(|| anyhow!("Invalid nonce"))?;
    let ciphertext = &data[56..];

    // Derive key and decrypt
    let key = derive_key(passphrase, &salt)?;
    let plaintext = secretbox::open(ciphertext, &nonce, &key)
        .map_err(|_| anyhow!("Failed to decrypt keypair: wrong passphrase?"))?;

    // Parse keypair from protobuf
    Keypair::from_protobuf_encoding(&plaintext).context("Failed to decode keypair")
}

/// Export public key as base64 string.
pub fn export_public_key(keypair: &Keypair) -> String {
    let public = keypair.public();
    let bytes = public.encode_protobuf();
    BASE64.encode(&bytes)
}

/// Import public key from base64 string.
pub fn import_public_key(encoded: &str) -> Result<libp2p::identity::PublicKey> {
    let bytes = BASE64
        .decode(encoded)
        .context("Invalid base64 encoding")?;
    libp2p::identity::PublicKey::try_decode_protobuf(&bytes).context("Invalid public key format")
}

/// Derive PeerId from keypair.
pub fn keypair_to_peer_id(keypair: &Keypair) -> PeerId {
    PeerId::from(keypair.public())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_keypair_works() {
        let kp = generate_keypair();
        let peer_id = keypair_to_peer_id(&kp);
        assert!(!peer_id.to_string().is_empty());
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.bin");

        let original = generate_keypair();
        let passphrase = "test-password-123";

        save_keypair(&original, &path, passphrase).unwrap();
        let loaded = load_keypair(&path, passphrase).unwrap();

        assert_eq!(
            keypair_to_peer_id(&original),
            keypair_to_peer_id(&loaded)
        );
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.bin");

        let original = generate_keypair();
        save_keypair(&original, &path, "correct").unwrap();

        let result = load_keypair(&path, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn export_public_key_produces_base64() {
        let kp = generate_keypair();
        let exported = export_public_key(&kp);
        assert!(!exported.is_empty());
        // Should be valid base64
        assert!(BASE64.decode(&exported).is_ok());
    }

    #[test]
    fn export_import_roundtrip() {
        let kp = generate_keypair();
        let exported = export_public_key(&kp);
        let imported = import_public_key(&exported).unwrap();
        assert_eq!(kp.public(), imported);
    }

    #[test]
    fn peer_id_consistent() {
        let kp = generate_keypair();
        let id1 = keypair_to_peer_id(&kp);
        let id2 = keypair_to_peer_id(&kp);
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_keypairs_different_ids() {
        let kp1 = generate_keypair();
        let kp2 = generate_keypair();
        assert_ne!(keypair_to_peer_id(&kp1), keypair_to_peer_id(&kp2));
    }

    #[test]
    fn creates_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nested").join("dirs").join("key.bin");

        let kp = generate_keypair();
        save_keypair(&kp, &path, "pass").unwrap();
        assert!(path.exists());
    }

    #[test]
    fn empty_passphrase_works() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.bin");

        let original = generate_keypair();
        save_keypair(&original, &path, "").unwrap();
        let loaded = load_keypair(&path, "").unwrap();

        assert_eq!(
            keypair_to_peer_id(&original),
            keypair_to_peer_id(&loaded)
        );
    }

    #[test]
    fn invalid_file_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.bin");
        fs::write(&path, b"too short").unwrap();

        let result = load_keypair(&path, "pass");
        assert!(result.is_err());
    }
}
