//! Key exchange and shared secrets.

use anyhow::{anyhow, Result};
use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use sodiumoxide::crypto::scalarmult;

/// Derive a shared secret from our secret key and their public key.
/// 
/// Uses X25519 (Curve25519) for key exchange.
/// The shared secret is symmetric: A with B = B with A.
pub fn derive_shared_secret(our_sk: &SecretKey, their_pk: &PublicKey) -> Vec<u8> {
    // Convert to scalarmult types
    let scalar = scalarmult::Scalar::from_slice(&our_sk.0)
        .expect("SecretKey should be valid scalar");
    let point = scalarmult::GroupElement::from_slice(&their_pk.0)
        .expect("PublicKey should be valid group element");
    
    // Perform X25519
    let shared = scalarmult::scalarmult(&scalar, &point)
        .expect("Scalarmult should not fail with valid inputs");
    
    shared.0.to_vec()
}

/// Convert a public key to bytes.
pub fn public_key_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.0.to_vec()
}

/// Parse a public key from bytes.
pub fn public_key_from_bytes(bytes: &[u8]) -> Result<PublicKey> {
    PublicKey::from_slice(bytes)
        .ok_or_else(|| anyhow!("Invalid public key: expected {} bytes", box_::PUBLICKEYBYTES))
}

/// Convert a secret key to bytes.
pub fn secret_key_to_bytes(sk: &SecretKey) -> Vec<u8> {
    sk.0.to_vec()
}

/// Parse a secret key from bytes.
pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<SecretKey> {
    SecretKey::from_slice(bytes)
        .ok_or_else(|| anyhow!("Invalid secret key: expected {} bytes", box_::SECRETKEYBYTES))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init() {
        let _ = sodiumoxide::init();
    }

    #[test]
    fn shared_secret_is_symmetric() {
        init();
        let (pk_a, sk_a) = box_::gen_keypair();
        let (pk_b, sk_b) = box_::gen_keypair();
        
        let secret_ab = derive_shared_secret(&sk_a, &pk_b);
        let secret_ba = derive_shared_secret(&sk_b, &pk_a);
        
        assert_eq!(secret_ab, secret_ba);
    }

    #[test]
    fn different_keys_give_different_secrets() {
        init();
        let (pk_a, sk_a) = box_::gen_keypair();
        let (pk_b, _sk_b) = box_::gen_keypair();
        let (pk_c, _sk_c) = box_::gen_keypair();
        
        let secret_ab = derive_shared_secret(&sk_a, &pk_b);
        let secret_ac = derive_shared_secret(&sk_a, &pk_c);
        
        assert_ne!(secret_ab, secret_ac);
    }

    #[test]
    fn public_key_serialization_roundtrip() {
        init();
        let (pk, _sk) = box_::gen_keypair();
        
        let bytes = public_key_to_bytes(&pk);
        let recovered = public_key_from_bytes(&bytes).unwrap();
        
        assert_eq!(pk, recovered);
    }

    #[test]
    fn secret_key_serialization_roundtrip() {
        init();
        let (_pk, sk) = box_::gen_keypair();
        
        let bytes = secret_key_to_bytes(&sk);
        let recovered = secret_key_from_bytes(&bytes).unwrap();
        
        assert_eq!(sk, recovered);
    }

    #[test]
    fn invalid_public_key_bytes_rejected() {
        init();
        let bad_bytes = vec![0u8; 16]; // Wrong length
        
        let result = public_key_from_bytes(&bad_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_secret_key_bytes_rejected() {
        init();
        let bad_bytes = vec![0u8; 16]; // Wrong length
        
        let result = secret_key_from_bytes(&bad_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn empty_bytes_rejected() {
        init();
        
        assert!(public_key_from_bytes(&[]).is_err());
        assert!(secret_key_from_bytes(&[]).is_err());
    }

    #[test]
    fn shared_secret_has_correct_length() {
        init();
        let (pk_a, sk_a) = box_::gen_keypair();
        let (pk_b, _sk_b) = box_::gen_keypair();
        
        let secret = derive_shared_secret(&sk_a, &pk_b);
        
        assert_eq!(secret.len(), scalarmult::GROUPELEMENTBYTES);
    }
}
