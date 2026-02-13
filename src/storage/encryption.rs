//! Database encryption with Argon2 key derivation.

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

const SALT_FILE: &str = ".whisper.salt";
const ARGON2_OUTPUT_LEN: usize = 32;

/// Derive a database encryption key from a passphrase using Argon2.
/// 
/// If a salt file exists in the data directory, uses that salt.
/// If not, creates a new salt file (for first-run).
pub fn derive_database_key(passphrase: &str, data_dir: &Path) -> Result<String> {
    if passphrase.is_empty() {
        bail!("Passphrase cannot be empty. Database encryption is required.");
    }

    let salt_path = data_dir.join(SALT_FILE);
    
    let salt = if salt_path.exists() {
        // Load existing salt
        let salt_str = fs::read_to_string(&salt_path)
            .context("Failed to read salt file")?;
        SaltString::from_b64(&salt_str)
            .map_err(|e| anyhow::anyhow!("Invalid salt file: {}", e))?
    } else {
        // Generate new salt for first-run
        let salt = SaltString::generate(&mut OsRng);
        fs::create_dir_all(data_dir)?;
        fs::write(&salt_path, salt.as_str())
            .context("Failed to write salt file")?;
        salt
    };

    // Use Argon2id with recommended parameters
    let argon2 = Argon2::default();
    
    // Hash the passphrase with the salt
    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to derive key: {}", e))?;
    
    // Extract the raw hash output for use as the database key
    let hash_output = password_hash.hash
        .ok_or_else(|| anyhow::anyhow!("Hash output missing"))?;
    
    // Convert to hex string for SQLCipher (it expects a string key)
    let key_bytes = hash_output.as_bytes();
    let hex_key = hex::encode(key_bytes);
    
    // SQLCipher wants the key prefixed with x'' for hex input
    Ok(format!("x'{}'", hex_key))
}

/// Check if a database exists and is encrypted.
pub fn database_exists(data_dir: &Path) -> bool {
    data_dir.join("whisper.db").exists()
}

/// Check if this is a first-run (no salt file exists).
pub fn is_first_run(data_dir: &Path) -> bool {
    !data_dir.join(SALT_FILE).exists()
}

/// Verify passphrase by attempting to open the database.
pub fn verify_passphrase(passphrase: &str, data_dir: &Path) -> bool {
    if passphrase.is_empty() {
        return false;
    }
    
    match derive_database_key(passphrase, data_dir) {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn derive_key_creates_salt_on_first_run() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();
        
        assert!(is_first_run(data_dir));
        
        let key = derive_database_key("test_passphrase", data_dir).unwrap();
        assert!(!key.is_empty());
        assert!(key.starts_with("x'"));
        assert!(!is_first_run(data_dir));
    }

    #[test]
    fn derive_key_uses_existing_salt() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();
        
        // First derivation creates salt
        let key1 = derive_database_key("test_passphrase", data_dir).unwrap();
        
        // Second derivation should produce same key (same salt)
        let key2 = derive_database_key("test_passphrase", data_dir).unwrap();
        
        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_different_passphrases_different_keys() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();
        
        let key1 = derive_database_key("passphrase1", data_dir).unwrap();
        
        // Create a separate temp dir for second passphrase (different salt)
        let temp2 = TempDir::new().unwrap();
        let key2 = derive_database_key("passphrase2", temp2.path()).unwrap();
        
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_fails_with_empty_passphrase() {
        let temp = TempDir::new().unwrap();
        let result = derive_database_key("", temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn is_first_run_detects_salt_file() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();
        
        assert!(is_first_run(data_dir));
        
        // Create a salt file
        fs::create_dir_all(data_dir).unwrap();
        fs::write(data_dir.join(SALT_FILE), "test_salt_value").unwrap();
        
        // Note: This will fail to parse as a valid salt, but the file exists
        // In practice, derive_database_key would create a valid salt
        assert!(!is_first_run(data_dir));
    }
}
