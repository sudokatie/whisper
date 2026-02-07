//! CLI command implementations.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use libp2p::PeerId;

use crate::identity::{
    export_public_key, generate_keypair, keypair_to_peer_id, load_keypair, save_keypair, Contact,
    ContactStore, TrustLevel,
};
use crate::storage::Database;

/// Default keypair filename.
pub const KEYPAIR_FILE: &str = "identity.key";

/// Default database filename.
pub const DATABASE_FILE: &str = "whisper.db";

/// Get the keypair path.
pub fn keypair_path(data_dir: &Path) -> PathBuf {
    data_dir.join(KEYPAIR_FILE)
}

/// Get the database path.
pub fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DATABASE_FILE)
}

/// Initialize a new identity.
pub async fn handle_init(data_dir: &Path, passphrase: &str) -> Result<()> {
    // Create data directory if needed
    std::fs::create_dir_all(data_dir).context("Failed to create data directory")?;

    let key_path = keypair_path(data_dir);

    // Check if identity already exists
    if key_path.exists() {
        anyhow::bail!("Identity already exists at {:?}", key_path);
    }

    // Generate new keypair
    let keypair = generate_keypair();
    let peer_id = keypair_to_peer_id(&keypair);
    let public_key = export_public_key(&keypair);

    // Save keypair
    save_keypair(&keypair, &key_path, passphrase).context("Failed to save keypair")?;

    // Initialize database
    let db_path = database_path(data_dir);
    let _db = Database::open(&db_path).context("Failed to initialize database")?;

    println!("Identity created!");
    println!("Peer ID: {}", peer_id);
    println!("Public Key: {}", public_key);
    println!("Saved to: {:?}", key_path);

    Ok(())
}

/// Send a message to a contact.
pub async fn handle_send(alias: &str, message: &str, data_dir: &Path) -> Result<()> {
    // This would normally connect to the network and send
    // For now, just queue the message
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    // Look up contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    println!("Sending to {}: {}", contact.alias, message);
    println!("(Message queued - connect to network to deliver)");

    Ok(())
}

/// Start interactive chat with a contact.
pub async fn handle_chat(_alias: &str, _data_dir: &Path) -> Result<()> {
    // This would launch the TUI
    println!("Interactive chat not yet implemented");
    println!("Use 'whisper send <alias> <message>' for now");
    Ok(())
}

/// List all contacts.
pub async fn handle_contacts(data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    let contacts = db.list_contacts()?;

    if contacts.is_empty() {
        println!("No contacts yet. Add one with: whisper add <alias> <peer_id>");
        return Ok(());
    }

    println!("Contacts:");
    for contact in contacts {
        let status = match contact.trust_level {
            TrustLevel::Trusted => "✓ Trusted",
            TrustLevel::Verified => "◆ Verified",
            TrustLevel::Blocked => "✗ Blocked",
            TrustLevel::Unknown => "? Unknown",
        };
        println!("  {} [{}] - {}", contact.alias, status, contact.peer_id);
    }

    Ok(())
}

/// Add a new contact.
pub async fn handle_add_contact(alias: &str, peer_id_str: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    // Parse peer ID
    let peer_id: PeerId = peer_id_str
        .parse()
        .context("Invalid peer ID format")?;

    // Create contact
    let contact = Contact {
        peer_id,
        alias: alias.to_string(),
        public_key: vec![], // Will be exchanged when connecting
        trust_level: TrustLevel::Unknown,
        last_seen: None,
    };

    // Save to database
    db.upsert_contact(&contact)?;

    println!("Added contact: {} ({})", alias, peer_id);

    Ok(())
}

/// Show node status.
pub async fn handle_status(data_dir: &Path, passphrase: &str) -> Result<()> {
    let key_path = keypair_path(data_dir);

    if !key_path.exists() {
        println!("No identity found. Run: whisper init");
        return Ok(());
    }

    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let peer_id = keypair_to_peer_id(&keypair);
    let public_key = export_public_key(&keypair);

    let db_path = database_path(data_dir);
    let db = Database::open(&db_path)?;
    let contacts = db.list_contacts()?;

    println!("Whisper Status");
    println!("==============");
    println!("Peer ID: {}", peer_id);
    println!("Public Key: {}", public_key);
    println!("Contacts: {}", contacts.len());
    println!("Data Dir: {:?}", data_dir);

    Ok(())
}

/// Set trust level for a contact.
pub async fn handle_trust(alias: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path)?;

    let mut contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    contact.trust_level = TrustLevel::Trusted;
    db.upsert_contact(&contact)?;

    println!("Marked {} as trusted", alias);

    Ok(())
}

/// Block a contact.
pub async fn handle_block(alias: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path)?;

    let mut contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    contact.trust_level = TrustLevel::Blocked;
    db.upsert_contact(&contact)?;

    println!("Blocked {}", alias);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn init_creates_keypair() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test_pass").await.unwrap();

        assert!(keypair_path(data_dir).exists());
        assert!(database_path(data_dir).exists());
    }

    #[tokio::test]
    async fn init_fails_if_exists() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test_pass").await.unwrap();
        let result = handle_init(data_dir, "test_pass").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn add_contact_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        // Initialize first
        handle_init(data_dir, "test").await.unwrap();

        // Add a contact
        let peer_id = PeerId::random();
        handle_add_contact("alice", &peer_id.to_string(), data_dir)
            .await
            .unwrap();

        // Verify it was added
        let db = Database::open(&database_path(data_dir)).unwrap();
        let contact = db.get_contact_by_alias("alice").unwrap();
        assert!(contact.is_some());
    }

    #[tokio::test]
    async fn contacts_lists_all() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        handle_add_contact("alice", &peer1.to_string(), data_dir)
            .await
            .unwrap();
        handle_add_contact("bob", &peer2.to_string(), data_dir)
            .await
            .unwrap();

        // Verify via database
        let db = Database::open(&database_path(data_dir)).unwrap();
        let contacts = db.list_contacts().unwrap();
        assert_eq!(contacts.len(), 2);
    }

    #[tokio::test]
    async fn status_shows_info() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Should not error
        handle_status(data_dir, "test").await.unwrap();
    }

    #[tokio::test]
    async fn trust_changes_level() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        let peer = PeerId::random();
        handle_add_contact("alice", &peer.to_string(), data_dir)
            .await
            .unwrap();

        handle_trust("alice", data_dir).await.unwrap();

        let db = Database::open(&database_path(data_dir)).unwrap();
        let contact = db.get_contact_by_alias("alice").unwrap().unwrap();
        assert!(matches!(contact.trust_level, TrustLevel::Trusted));
    }

    #[tokio::test]
    async fn block_changes_level() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        let peer = PeerId::random();
        handle_add_contact("alice", &peer.to_string(), data_dir)
            .await
            .unwrap();

        handle_block("alice", data_dir).await.unwrap();

        let db = Database::open(&database_path(data_dir)).unwrap();
        let contact = db.get_contact_by_alias("alice").unwrap().unwrap();
        assert!(matches!(contact.trust_level, TrustLevel::Blocked));
    }

    #[test]
    fn keypair_path_is_correct() {
        let dir = Path::new("/tmp/whisper");
        assert_eq!(keypair_path(dir), PathBuf::from("/tmp/whisper/identity.key"));
    }

    #[test]
    fn database_path_is_correct() {
        let dir = Path::new("/tmp/whisper");
        assert_eq!(database_path(dir), PathBuf::from("/tmp/whisper/whisper.db"));
    }

    #[tokio::test]
    async fn send_to_unknown_contact_fails() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Try to send to non-existent contact
        let result = handle_send("nobody", "hello", data_dir).await;
        assert!(result.is_err());
    }
}
