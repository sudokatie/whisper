//! Message encryption with sealed boxes.

use anyhow::Result;

/// Encrypt a message for a recipient.
pub fn encrypt_message(_plaintext: &[u8], _recipient_pk: &[u8]) -> Result<Vec<u8>> {
    todo!("Implement encrypt_message")
}

/// Decrypt a message.
pub fn decrypt_message(_ciphertext: &[u8], _secret_key: &[u8]) -> Result<Vec<u8>> {
    todo!("Implement decrypt_message")
}
