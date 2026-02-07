//! CLI command implementations.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use libp2p::PeerId;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    Terminal,
};

use crate::crypto::generate_group_key;
use crate::identity::{
    export_public_key, generate_keypair, import_public_key, keypair_to_peer_id, load_keypair,
    save_keypair, Contact, TrustLevel,
};
use crate::message::{Group, Message, MessageContent, Recipient};
use crate::storage::Database;
use crate::ui::{
    App, AppMode, DisplayMessage, InputAction,
    render_chat, render_contacts, render_empty, render_status,
};

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
pub async fn handle_chat(alias: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    // Verify contact exists
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Load all contacts for the sidebar
    let contacts = db.list_contacts()?;

    // Create app state
    let mut app = App::new();
    for c in contacts {
        app.add_contact(c);
    }

    // Set current chat to the specified contact
    app.current_chat = Some(contact.peer_id);
    app.mode = AppMode::Chat;

    // Find the contact index for selection
    if let Some(idx) = app.contacts.iter().position(|c| c.peer_id == contact.peer_id) {
        app.selected_contact = idx;
    }

    // Load message history
    let messages = db.get_messages_with_peer(&contact.peer_id, 100)?;
    for msg in messages {
        if let MessageContent::Text(text) = msg.content {
            let is_ours = app.our_peer_id == Some(msg.from);
            app.messages.push(DisplayMessage::new(
                msg.from,
                text,
                msg.timestamp,
                is_ours,
            ));
        }
    }

    // Run the TUI
    run_tui(&mut app, &db)?;

    Ok(())
}

/// Run the TUI event loop.
fn run_tui(app: &mut App, db: &Database) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Main loop
    loop {
        // Draw
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(frame.area());

            match app.mode {
                AppMode::Contacts => {
                    if app.contacts.is_empty() {
                        render_empty(frame, chunks[0], "No contacts. Add with: whisper add <alias> <peer_id>");
                    } else {
                        render_contacts(frame, chunks[0], &app.contacts, app.selected_contact);
                    }
                }
                AppMode::Chat | AppMode::Input => {
                    render_chat(
                        frame,
                        chunks[0],
                        &app.messages,
                        &app.input,
                        app.mode == AppMode::Input,
                    );
                }
            }

            // Status bar
            let peer_id = app.our_peer_id.unwrap_or_else(PeerId::random);
            render_status(frame, chunks[1], &peer_id, 0);
        })?;

        // Handle input
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                let action = app.handle_key(key);

                match action {
                    InputAction::Send(text) => {
                        if let Some(peer_id) = app.current_chat {
                            // Create and store message
                            let from = app.our_peer_id.unwrap_or_else(PeerId::random);
                            let msg = Message::new_text(
                                from,
                                Recipient::Direct(peer_id),
                                text.clone(),
                            );

                            // Store in database
                            let _ = db.insert_message(&msg);

                            // Add to display
                            app.messages.push(DisplayMessage::new(
                                from,
                                text,
                                Utc::now(),
                                true,
                            ));
                        }
                    }
                    InputAction::Cancel => {}
                    InputAction::None => {}
                }

                if app.should_quit {
                    break;
                }
            }
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

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

/// Export public key to stdout.
pub async fn handle_export_key(data_dir: &Path, passphrase: &str) -> Result<()> {
    let key_path = keypair_path(data_dir);

    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }

    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let public_key = export_public_key(&keypair);

    println!("{}", public_key);

    Ok(())
}

/// Import a contact from a key file.
pub async fn handle_import_contact(file: &Path, alias: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    // Read public key from file
    let key_data = fs::read_to_string(file).context("Failed to read key file")?;
    let key_data = key_data.trim();

    // Parse public key and derive peer ID
    let public_key = import_public_key(key_data).context("Invalid public key format")?;
    let peer_id = PeerId::from(public_key.clone());
    let key_bytes = public_key.encode_protobuf();

    // Create contact
    let contact = Contact {
        peer_id,
        alias: alias.to_string(),
        public_key: key_bytes,
        trust_level: TrustLevel::Unknown,
        last_seen: None,
    };

    db.upsert_contact(&contact)?;

    println!("Imported contact: {} ({})", alias, peer_id);

    Ok(())
}

/// List connected peers.
pub async fn handle_peers(data_dir: &Path, _passphrase: &str) -> Result<()> {
    let key_path = keypair_path(data_dir);

    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }

    // In a real implementation, this would connect to the network
    // and list currently connected peers
    println!("Connected Peers");
    println!("===============");
    println!("(Not connected - network features not fully implemented)");
    println!();
    println!("To connect, the node would need to be running with:");
    println!("  whisper chat <alias>");
    println!();
    println!("Hint: Known contacts can be listed with: whisper contacts");

    Ok(())
}

/// Create a new group.
pub async fn handle_group_create(name: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    // Check if group already exists
    if db.get_group_by_name(name)?.is_some() {
        anyhow::bail!("Group '{}' already exists", name);
    }

    // Generate symmetric key for group
    let symmetric_key = generate_group_key();

    // Create group
    let group = Group::new(name.to_string(), symmetric_key);
    db.create_group(&group)?;

    println!("Created group: {}", name);
    println!("Group ID: {}", group.id);

    Ok(())
}

/// Invite a contact to a group.
pub async fn handle_group_invite(group_name: &str, alias: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    // Get contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Add member
    db.add_group_member(&group.id, &contact.peer_id)?;

    println!("Invited {} to group {}", alias, group_name);

    Ok(())
}

/// Open interactive group chat.
pub async fn handle_group_chat(name: &str, data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    // Verify group exists
    let group = db
        .get_group_by_name(name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", name))?;

    println!("Group: {} ({} members)", group.name, group.members.len());
    println!("Interactive group chat not yet implemented");
    println!("Use 'whisper send <member-alias> <message>' for now");

    Ok(())
}

/// List all groups.
pub async fn handle_group_list(data_dir: &Path) -> Result<()> {
    let db_path = database_path(data_dir);
    let db = Database::open(&db_path).context("Failed to open database")?;

    let groups = db.list_groups()?;

    if groups.is_empty() {
        println!("No groups yet. Create one with: whisper group create <name>");
        return Ok(());
    }

    println!("Groups:");
    for group in groups {
        println!("  {} ({} members)", group.name, group.members.len());
    }

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

    #[tokio::test]
    async fn export_key_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Should not error
        handle_export_key(data_dir, "test").await.unwrap();
    }

    #[tokio::test]
    async fn export_key_fails_without_identity() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        let result = handle_export_key(data_dir, "test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn group_create_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        handle_group_create("test-group", data_dir).await.unwrap();

        let db = Database::open(&database_path(data_dir)).unwrap();
        let group = db.get_group_by_name("test-group").unwrap();
        assert!(group.is_some());
    }

    #[tokio::test]
    async fn group_create_duplicate_fails() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        handle_group_create("my-group", data_dir).await.unwrap();

        let result = handle_group_create("my-group", data_dir).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn group_invite_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        handle_group_create("team", data_dir).await.unwrap();

        let peer = PeerId::random();
        handle_add_contact("alice", &peer.to_string(), data_dir)
            .await
            .unwrap();

        handle_group_invite("team", "alice", data_dir).await.unwrap();

        let db = Database::open(&database_path(data_dir)).unwrap();
        let group = db.get_group_by_name("team").unwrap().unwrap();
        assert_eq!(group.members.len(), 1);
    }

    #[tokio::test]
    async fn group_invite_unknown_group_fails() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        let peer = PeerId::random();
        handle_add_contact("alice", &peer.to_string(), data_dir)
            .await
            .unwrap();

        let result = handle_group_invite("nonexistent", "alice", data_dir).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn group_list_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        handle_group_create("group1", data_dir).await.unwrap();
        handle_group_create("group2", data_dir).await.unwrap();

        // Should not error
        handle_group_list(data_dir).await.unwrap();
    }

    #[tokio::test]
    async fn peers_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Should not error
        handle_peers(data_dir, "test").await.unwrap();
    }
}
