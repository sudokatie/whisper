//! Message encryption with sealed boxes and symmetric encryption.

use anyhow::{anyhow, Result};
use sodiumoxide::crypto::sealedbox;
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};

/// Encrypt a message for a recipient using sealed box (anonymous sender).
/// 
/// Uses libsodium sealed_box which combines X25519-XSalsa20-Poly1305.
/// The sender's identity is not revealed in the ciphertext.
pub fn encrypt_message(plaintext: &[u8], recipient_pk: &PublicKey) -> Result<Vec<u8>> {
    let ciphertext = sealedbox::seal(plaintext, recipient_pk);
    Ok(ciphertext)
}

/// Decrypt a message using our keypair.
/// 
/// Returns error if decryption fails (wrong key or corrupted ciphertext).
pub fn decrypt_message(ciphertext: &[u8], public_key: &PublicKey, secret_key: &SecretKey) -> Result<Vec<u8>> {
    sealedbox::open(ciphertext, public_key, secret_key)
        .map_err(|_| anyhow!("Decryption failed: invalid ciphertext or wrong key"))
}

/// Generate a random symmetric key for group encryption.
/// 
/// Returns a 32-byte key suitable for secretbox.
pub fn generate_group_key() -> Vec<u8> {
    let key = secretbox::gen_key();
    key.0.to_vec()
}

/// Encrypt a message for a group using symmetric encryption.
/// 
/// Uses XSalsa20-Poly1305 (secretbox).
/// Nonce is prepended to ciphertext.
pub fn encrypt_for_group(plaintext: &[u8], group_key: &[u8]) -> Result<Vec<u8>> {
    let key = secretbox::Key::from_slice(group_key)
        .ok_or_else(|| anyhow!("Invalid group key: must be {} bytes", secretbox::KEYBYTES))?;
    
    let nonce = secretbox::gen_nonce();
    let ciphertext = secretbox::seal(plaintext, &nonce, &key);
    
    // Prepend nonce to ciphertext
    let mut result = nonce.0.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a message from a group using symmetric encryption.
/// 
/// Expects nonce prepended to ciphertext.
pub fn decrypt_from_group(ciphertext: &[u8], group_key: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.len() < secretbox::NONCEBYTES {
        return Err(anyhow!("Ciphertext too short: missing nonce"));
    }
    
    let key = secretbox::Key::from_slice(group_key)
        .ok_or_else(|| anyhow!("Invalid group key: must be {} bytes", secretbox::KEYBYTES))?;
    
    let nonce = secretbox::Nonce::from_slice(&ciphertext[..secretbox::NONCEBYTES])
        .ok_or_else(|| anyhow!("Invalid nonce"))?;
    
    let encrypted = &ciphertext[secretbox::NONCEBYTES..];
    
    secretbox::open(encrypted, &nonce, &key)
        .map_err(|_| anyhow!("Group decryption failed: invalid ciphertext or wrong key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::box_;

    fn init() {
        let _ = sodiumoxide::init();
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        init();
        let (pk, sk) = box_::gen_keypair();
        let plaintext = b"Hello, World!";
        
        let ciphertext = encrypt_message(plaintext, &pk).unwrap();
        let decrypted = decrypt_message(&ciphertext, &pk, &sk).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn wrong_key_fails_decryption() {
        init();
        let (pk1, _sk1) = box_::gen_keypair();
        let (pk2, sk2) = box_::gen_keypair();
        let plaintext = b"Secret message";
        
        let ciphertext = encrypt_message(plaintext, &pk1).unwrap();
        let result = decrypt_message(&ciphertext, &pk2, &sk2);
        
        assert!(result.is_err());
    }

    #[test]
    fn empty_message_works() {
        init();
        let (pk, sk) = box_::gen_keypair();
        let plaintext = b"";
        
        let ciphertext = encrypt_message(plaintext, &pk).unwrap();
        let decrypted = decrypt_message(&ciphertext, &pk, &sk).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn large_message_works() {
        init();
        let (pk, sk) = box_::gen_keypair();
        let plaintext: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        
        let ciphertext = encrypt_message(&plaintext, &pk).unwrap();
        let decrypted = decrypt_message(&ciphertext, &pk, &sk).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn group_encrypt_decrypt_roundtrip() {
        init();
        let group_key = generate_group_key();
        let plaintext = b"Group message";
        
        let ciphertext = encrypt_for_group(plaintext, &group_key).unwrap();
        let decrypted = decrypt_from_group(&ciphertext, &group_key).unwrap();
        
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn group_wrong_key_fails() {
        init();
        let key1 = generate_group_key();
        let key2 = generate_group_key();
        let plaintext = b"Secret group message";
        
        let ciphertext = encrypt_for_group(plaintext, &key1).unwrap();
        let result = decrypt_from_group(&ciphertext, &key2);
        
        assert!(result.is_err());
    }

    #[test]
    fn ciphertext_is_different_each_time() {
        init();
        let (pk, _sk) = box_::gen_keypair();
        let plaintext = b"Same message";
        
        let ct1 = encrypt_message(plaintext, &pk).unwrap();
        let ct2 = encrypt_message(plaintext, &pk).unwrap();
        
        // Sealed box uses random nonce, so ciphertexts should differ
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn group_ciphertext_is_different_each_time() {
        init();
        let group_key = generate_group_key();
        let plaintext = b"Same group message";
        
        let ct1 = encrypt_for_group(plaintext, &group_key).unwrap();
        let ct2 = encrypt_for_group(plaintext, &group_key).unwrap();
        
        // Random nonce, so ciphertexts should differ
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn generate_group_key_correct_length() {
        init();
        let key = generate_group_key();
        assert_eq!(key.len(), secretbox::KEYBYTES);
    }

    #[test]
    fn invalid_group_key_rejected() {
        init();
        let plaintext = b"Test";
        let bad_key = vec![0u8; 16]; // Wrong length
        
        let result = encrypt_for_group(plaintext, &bad_key);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_ciphertext_rejected() {
        init();
        let group_key = generate_group_key();
        let short_ciphertext = vec![0u8; 10]; // Too short for nonce
        
        let result = decrypt_from_group(&short_ciphertext, &group_key);
        assert!(result.is_err());
    }

    #[test]
    fn corrupted_ciphertext_rejected() {
        init();
        let group_key = generate_group_key();
        let plaintext = b"Test message";
        
        let mut ciphertext = encrypt_for_group(plaintext, &group_key).unwrap();
        // Corrupt a byte in the encrypted portion
        if let Some(byte) = ciphertext.last_mut() {
            *byte ^= 0xFF;
        }
        
        let result = decrypt_from_group(&ciphertext, &group_key);
        assert!(result.is_err());
    }
}
