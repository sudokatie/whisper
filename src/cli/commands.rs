//! CLI command implementations.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
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
use tokio::sync::Mutex;

use crate::crypto::{
    decrypt_message, ed25519_pk_to_x25519, encrypt_message, generate_group_key,
    keypair_to_encryption_keys,
};

/// Wire message prefix for receipts.
const RECEIPT_PREFIX: &[u8] = b"RCPT:";

/// Parse a wire message to check if it's a receipt.
/// Returns Some((message_id, receipt_type)) if it's a receipt, None otherwise.
fn parse_receipt(data: &[u8]) -> Option<(uuid::Uuid, crate::message::ReceiptType)> {
    if !data.starts_with(RECEIPT_PREFIX) {
        return None;
    }
    let payload = &data[RECEIPT_PREFIX.len()..];
    // Format: "D:<uuid>" for delivered, "R:<uuid>" for read
    if payload.len() < 38 {
        return None;
    }
    let receipt_type = match payload[0] {
        b'D' => crate::message::ReceiptType::Delivered,
        b'R' => crate::message::ReceiptType::Read,
        _ => return None,
    };
    if payload[1] != b':' {
        return None;
    }
    let uuid_str = std::str::from_utf8(&payload[2..38]).ok()?;
    let id = uuid::Uuid::parse_str(uuid_str).ok()?;
    Some((id, receipt_type))
}

/// Create a wire receipt message.
fn create_receipt(message_id: &uuid::Uuid, receipt_type: crate::message::ReceiptType) -> Vec<u8> {
    let type_char = match receipt_type {
        crate::message::ReceiptType::Delivered => 'D',
        crate::message::ReceiptType::Read => 'R',
    };
    format!("RCPT:{}:{}", type_char, message_id).into_bytes()
}
use crate::identity::{
    export_public_key, generate_keypair, import_public_key, keypair_to_peer_id, load_keypair,
    save_keypair, Contact, TrustLevel,
};
use crate::message::{Group, Message, MessageContent, MessageStatus, Recipient};
use crate::network::{NodeEvent, WhisperNode};
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

/// Open the database with encrypted passphrase.
/// Uses Argon2 key derivation for secure encryption.
fn open_database(data_dir: &Path, passphrase: &str) -> Result<Database> {
    let path = database_path(data_dir);
    Database::open_with_passphrase(&path, passphrase, data_dir)
        .context("Failed to open database - incorrect passphrase?")
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

    // Initialize encrypted database
    let _db = open_database(data_dir, passphrase)?;

    println!("Identity created!");
    println!("Peer ID: {}", peer_id);
    println!("Public Key: {}", public_key);
    println!("Saved to: {:?}", key_path);

    Ok(())
}

/// Send a message to a contact.
pub async fn handle_send(alias: &str, message: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let our_peer_id = keypair_to_peer_id(&keypair);

    // Look up contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Create and store the message
    let msg = Message::new_text(
        our_peer_id,
        Recipient::Direct(contact.peer_id),
        message.to_string(),
    );
    db.insert_message(&msg)?;

    // Encrypt the message
    let encrypted_data = if !contact.public_key.is_empty() {
        match ed25519_pk_to_x25519(&contact.public_key) {
            Ok(recipient_pk) => {
                encrypt_message(message.as_bytes(), &recipient_pk)
                    .unwrap_or_else(|_| message.as_bytes().to_vec())
            }
            Err(_) => message.as_bytes().to_vec(),
        }
    } else {
        message.as_bytes().to_vec()
    };

    // Store in persistent queue (survives restarts)
    db.queue_pending_message(&msg.id, &contact.peer_id, &encrypted_data)?;

    // Try to send now
    let mut node = WhisperNode::new(keypair).await.context("Failed to create network node")?;
    node.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    node.send_message(contact.peer_id, encrypted_data);

    println!("Message to {}: {}", contact.alias, message);
    println!("(Queued persistently - will deliver when recipient connects.)");

    Ok(())
}

/// Start interactive chat with a contact.
pub async fn handle_chat(alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let our_peer_id = keypair_to_peer_id(&keypair);

    // Verify contact exists
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Load all contacts for the sidebar
    let contacts = db.list_contacts()?;

    // Create app state
    let mut app = App::new();
    app.set_peer_id(our_peer_id);
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
            let is_ours = our_peer_id == msg.from;
            app.messages.push(DisplayMessage::new(
                msg.from,
                text,
                msg.timestamp,
                is_ours,
            ));
        }
    }

    // Derive encryption keys from our identity keypair
    let (our_enc_pk, our_enc_sk) = keypair_to_encryption_keys(&keypair)
        .context("Failed to derive encryption keys")?;

    // Create and start the network node
    let mut node = WhisperNode::new(keypair).await.context("Failed to create network node")?;
    
    // Listen on a random port
    node.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    
    // Share the node for the TUI to send messages
    let node = Arc::new(Mutex::new(node));

    // Run the TUI with network integration
    run_tui_with_network(&mut app, &db, node, &our_enc_pk, &our_enc_sk).await?;

    Ok(())
}

/// Run the TUI event loop with network integration.
async fn run_tui_with_network(
    app: &mut App,
    db: &Database,
    node: Arc<Mutex<WhisperNode>>,
    our_enc_pk: &sodiumoxide::crypto::box_::PublicKey,
    our_enc_sk: &sodiumoxide::crypto::box_::SecretKey,
) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Track connected peers for status bar
    let mut connected_count = 0usize;

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

            // Status bar with connected peer count
            let peer_id = app.our_peer_id.unwrap_or_else(PeerId::random);
            render_status(frame, chunks[1], &peer_id, connected_count);
        })?;

        // Poll for keyboard input (non-blocking)
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                let action = app.handle_key(key);

                match action {
                    InputAction::Send(text) => {
                        if let Some(peer_id) = app.current_chat {
                            // Get contact's public key for encryption
                            let contact_opt = db.get_contact(&peer_id).ok().flatten();
                            
                            // Create and store message (plaintext in our local DB)
                            let from = app.our_peer_id.unwrap_or_else(PeerId::random);
                            let msg = Message::new_text(
                                from,
                                Recipient::Direct(peer_id),
                                text.clone(),
                            );

                            // Store in database
                            let _ = db.insert_message(&msg);

                            // Encrypt and send over network
                            {
                                let mut node = node.lock().await;
                                
                                // Try to encrypt with contact's public key
                                let data = if let Some(contact) = contact_opt {
                                    if !contact.public_key.is_empty() {
                                        // Convert Ed25519 public key to X25519 for encryption
                                        match ed25519_pk_to_x25519(&contact.public_key) {
                                            Ok(recipient_pk) => {
                                                match encrypt_message(text.as_bytes(), &recipient_pk) {
                                                    Ok(encrypted) => encrypted,
                                                    Err(_) => text.as_bytes().to_vec(), // Fallback
                                                }
                                            }
                                            Err(_) => text.as_bytes().to_vec(), // Fallback
                                        }
                                    } else {
                                        // No public key stored, send unencrypted (for now)
                                        text.as_bytes().to_vec()
                                    }
                                } else {
                                    // Contact not found, send unencrypted
                                    text.as_bytes().to_vec()
                                };
                                
                                node.send_message(peer_id, data);
                            }

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

        // Poll network for events (with timeout so we don't block)
        {
            let mut node = node.lock().await;
            // Use tokio::select with a timeout to poll network without blocking
            let poll_result = tokio::time::timeout(
                Duration::from_millis(10),
                node.poll_event()
            ).await;

            if let Ok(Some(event)) = poll_result {
                match event {
                    NodeEvent::PeerConnected(peer_id) => {
                        connected_count += 1;
                        // Update last_seen for this contact if we have them
                        if let Ok(Some(mut contact)) = db.get_contact(&peer_id) {
                            contact.last_seen = Some(Utc::now());
                            let _ = db.upsert_contact(&contact);
                        }
                        
                        // Flush pending messages for this peer from persistent queue
                        if let Ok(pending) = db.get_pending_for_peer(&peer_id) {
                            for (msg_id, encrypted_data) in pending {
                                node.send_message(peer_id, encrypted_data);
                                // Remove from queue after sending
                                let _ = db.remove_pending_message(&msg_id);
                            }
                        }
                    }
                    NodeEvent::PeerDisconnected(_) => {
                        connected_count = connected_count.saturating_sub(1);
                    }
                    NodeEvent::MessageReceived { from, data } => {
                        // Try to decrypt with our secret key, fall back to plaintext
                        let decrypted = match decrypt_message(&data, our_enc_pk, our_enc_sk) {
                            Ok(plaintext) => plaintext,
                            Err(_) => data.clone(), // Not encrypted or wrong key
                        };

                        // Check if this is a receipt
                        if let Some((msg_id, receipt_type)) = parse_receipt(&decrypted) {
                            // Update the message status in our database
                            let new_status = match receipt_type {
                                crate::message::ReceiptType::Delivered => MessageStatus::Delivered,
                                crate::message::ReceiptType::Read => MessageStatus::Read,
                            };
                            let _ = db.update_message_status(&msg_id, &new_status);
                            // Don't display receipts in chat
                            continue;
                        }

                        // Regular text message
                        let text = String::from_utf8_lossy(&decrypted).to_string();

                        // Store in database
                        let msg = Message::new_text(
                            from,
                            Recipient::Direct(app.our_peer_id.unwrap_or_else(PeerId::random)),
                            text.clone(),
                        );
                        let _ = db.insert_message(&msg);

                        // Send delivery receipt back to sender
                        let receipt = create_receipt(&msg.id, crate::message::ReceiptType::Delivered);
                        node.send_message(from, receipt);

                        // Add to display if it's from current chat
                        if app.current_chat == Some(from) {
                            app.messages.push(DisplayMessage::new(
                                from,
                                text,
                                Utc::now(),
                                false,
                            ));
                        }
                    }
                    NodeEvent::Listening(addr) => {
                        // Could display this somewhere
                        let _ = addr;
                    }
                    NodeEvent::MessageSent { .. } => {
                        // Message confirmed sent
                    }
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

/// Run the TUI event loop for group chat with multicast.
async fn run_group_tui_with_network(
    app: &mut App,
    db: &Database,
    node: Arc<Mutex<WhisperNode>>,
    group: &Group,
    our_enc_pk: &sodiumoxide::crypto::box_::PublicKey,
    our_enc_sk: &sodiumoxide::crypto::box_::SecretKey,
) -> Result<()> {
    use crate::crypto::{encrypt_for_group, decrypt_from_group};
    
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut connected_count = 0usize;

    loop {
        // Draw
        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(3)])
                .split(frame.area());

            render_chat(
                frame,
                chunks[0],
                &app.messages,
                &app.input,
                app.mode == AppMode::Input,
            );

            let peer_id = app.our_peer_id.unwrap_or_else(PeerId::random);
            render_status(frame, chunks[1], &peer_id, connected_count);
        })?;

        // Poll keyboard
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                let action = app.handle_key(key);

                match action {
                    InputAction::Send(text) => {
                        let from = app.our_peer_id.unwrap_or_else(PeerId::random);
                        
                        // Store message with group recipient
                        let msg = Message::new_text(
                            from,
                            Recipient::Group(group.id),
                            text.clone(),
                        );
                        let _ = db.insert_message(&msg);

                        // Encrypt with group's symmetric key
                        let encrypted = encrypt_for_group(text.as_bytes(), &group.symmetric_key)
                            .unwrap_or_else(|_| text.as_bytes().to_vec());

                        // Send to ALL group members (multicast)
                        {
                            let mut node = node.lock().await;
                            for member_peer_id in &group.members {
                                // Don't send to ourselves
                                if *member_peer_id != from {
                                    node.send_message(*member_peer_id, encrypted.clone());
                                }
                            }
                        }

                        // Add to display
                        app.messages.push(DisplayMessage::new(
                            from,
                            text,
                            Utc::now(),
                            true,
                        ));
                    }
                    InputAction::Cancel => {}
                    InputAction::None => {}
                }

                if app.should_quit {
                    break;
                }
            }
        }

        // Poll network
        {
            let mut node = node.lock().await;
            let poll_result = tokio::time::timeout(
                Duration::from_millis(10),
                node.poll_event()
            ).await;

            if let Ok(Some(event)) = poll_result {
                match event {
                    NodeEvent::PeerConnected(peer_id) => {
                        connected_count += 1;
                        if let Ok(Some(mut contact)) = db.get_contact(&peer_id) {
                            contact.last_seen = Some(Utc::now());
                            let _ = db.upsert_contact(&contact);
                        }
                        
                        // Flush pending messages for this peer from persistent queue
                        if let Ok(pending) = db.get_pending_for_peer(&peer_id) {
                            for (msg_id, encrypted_data) in pending {
                                node.send_message(peer_id, encrypted_data);
                                let _ = db.remove_pending_message(&msg_id);
                            }
                        }
                    }
                    NodeEvent::PeerDisconnected(_) => {
                        connected_count = connected_count.saturating_sub(1);
                    }
                    NodeEvent::MessageReceived { from, data } => {
                        // Try group decryption first, then DM decryption, then plaintext
                        let decrypted = if let Ok(plaintext) = decrypt_from_group(&data, &group.symmetric_key) {
                            plaintext
                        } else if let Ok(plaintext) = decrypt_message(&data, our_enc_pk, our_enc_sk) {
                            plaintext
                        } else {
                            data.clone()
                        };

                        // Check if this is a receipt
                        if let Some((msg_id, receipt_type)) = parse_receipt(&decrypted) {
                            let new_status = match receipt_type {
                                crate::message::ReceiptType::Delivered => MessageStatus::Delivered,
                                crate::message::ReceiptType::Read => MessageStatus::Read,
                            };
                            let _ = db.update_message_status(&msg_id, &new_status);
                            continue;
                        }

                        let text = String::from_utf8_lossy(&decrypted).to_string();

                        // Store in database
                        let msg = Message::new_text(
                            from,
                            Recipient::Group(group.id),
                            text.clone(),
                        );
                        let _ = db.insert_message(&msg);

                        // Send delivery receipt back to sender
                        let receipt = create_receipt(&msg.id, crate::message::ReceiptType::Delivered);
                        node.send_message(from, receipt);

                        // Add to display (all group messages shown)
                        app.messages.push(DisplayMessage::new(
                            from,
                            text,
                            Utc::now(),
                            false,
                        ));
                    }
                    NodeEvent::Listening(_) | NodeEvent::MessageSent { .. } => {}
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
pub async fn handle_contacts(data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

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
pub async fn handle_add_contact(alias: &str, peer_id_str: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

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

    let db = open_database(data_dir, passphrase)?;
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
pub async fn handle_trust(alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    let mut contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    contact.trust_level = TrustLevel::Trusted;
    db.upsert_contact(&contact)?;

    println!("Marked {} as trusted", alias);

    Ok(())
}

/// Block a contact.
pub async fn handle_block(alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

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
pub async fn handle_import_contact(file: &Path, alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Read public key from file
    let key_data = fs::read_to_string(file).context("Failed to read key file")?;
    let key_data = key_data.trim();

    // Parse public key and derive peer ID
    let public_key = import_public_key(key_data).context("Invalid public key format")?;
    let peer_id = PeerId::from(public_key.clone());
    
    // Extract raw Ed25519 bytes (32 bytes) for encryption key derivation
    let key_bytes = public_key.clone()
        .try_into_ed25519()
        .map(|ed_pk| ed_pk.to_bytes().to_vec())
        .unwrap_or_else(|_| public_key.encode_protobuf()); // Fallback to protobuf if not Ed25519

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
/// 
/// Since Whisper doesn't run a background daemon, this shows:
/// 1. Contacts with recent last_seen timestamps (recently online)
/// 2. Pending messages waiting for delivery
pub async fn handle_peers(data_dir: &Path, passphrase: &str) -> Result<()> {
    let key_path = keypair_path(data_dir);

    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }

    let db = open_database(data_dir, passphrase)?;

    println!("Peer Status");
    println!("===========");
    println!();

    // Show contacts with last_seen info
    let contacts = db.list_contacts()?;
    let now = Utc::now();

    println!("Known Contacts:");
    if contacts.is_empty() {
        println!("  (none)");
    } else {
        for contact in &contacts {
            let status = match contact.last_seen {
                Some(seen) => {
                    let ago = now.signed_duration_since(seen);
                    if ago.num_minutes() < 5 {
                        "recently online".to_string()
                    } else if ago.num_hours() < 1 {
                        format!("{}m ago", ago.num_minutes())
                    } else if ago.num_hours() < 24 {
                        format!("{}h ago", ago.num_hours())
                    } else {
                        format!("{}d ago", ago.num_days())
                    }
                }
                None => "never seen".to_string(),
            };
            println!("  {} - {}", contact.alias, status);
        }
    }

    // Show pending messages
    let pending = db.get_all_pending()?;
    println!();
    println!("Pending Messages: {}", pending.len());
    if !pending.is_empty() {
        // Group by peer
        let mut by_peer: std::collections::HashMap<PeerId, usize> = std::collections::HashMap::new();
        for (_, peer_id, _) in &pending {
            *by_peer.entry(*peer_id).or_insert(0) += 1;
        }
        for (peer_id, count) in by_peer {
            // Try to find alias
            let alias = contacts.iter()
                .find(|c| c.peer_id == peer_id)
                .map(|c| c.alias.as_str())
                .unwrap_or("unknown");
            println!("  {} messages for {}", count, alias);
        }
    }

    println!();
    println!("Note: Whisper connects when you start a chat session.");
    println!("Use 'whisper chat <alias>' to connect and deliver pending messages.");

    Ok(())
}

/// Create a new group.
pub async fn handle_group_create(name: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

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
/// 
/// This adds them to the group AND sends them the encrypted group key.
pub async fn handle_group_invite(group_name: &str, alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    // Get contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Add member to local database
    db.add_group_member(&group.id, &contact.peer_id)?;

    // Send encrypted group key to the invited member
    // Format: "GROUP_INVITE:<group_name>:<group_id>:<encrypted_symmetric_key>"
    if !contact.public_key.is_empty() {
        if let Ok(recipient_pk) = ed25519_pk_to_x25519(&contact.public_key) {
            // Encrypt the symmetric key with the recipient's public key
            let encrypted_key = encrypt_message(&group.symmetric_key, &recipient_pk)
                .context("Failed to encrypt group key")?;
            
            // Create invite payload
            let invite_payload = format!(
                "GROUP_INVITE:{}:{}:",
                group.name,
                group.id
            );
            let mut invite_data = invite_payload.into_bytes();
            invite_data.extend_from_slice(&encrypted_key);

            // Queue for delivery
            let invite_id = uuid::Uuid::new_v4();
            db.queue_pending_message(&invite_id, &contact.peer_id, &invite_data)?;

            // Try to send now
            let mut node = WhisperNode::new(keypair).await.context("Failed to create network node")?;
            node.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
            node.send_message(contact.peer_id, invite_data);

            println!("Invited {} to group {} (group key sent encrypted)", alias, group_name);
        } else {
            println!("Invited {} to group {} (no public key - key exchange needed)", alias, group_name);
        }
    } else {
        println!("Invited {} to group {} (no public key - key exchange needed)", alias, group_name);
    }

    Ok(())
}

/// Open interactive group chat.
pub async fn handle_group_chat(name: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let our_peer_id = keypair_to_peer_id(&keypair);

    // Verify group exists
    let group = db
        .get_group_by_name(name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", name))?;

    if group.members.is_empty() {
        println!("Group '{}' has no members. Invite contacts with: whisper group invite {} <alias>", name, name);
        return Ok(());
    }

    // Load all contacts for the sidebar
    let contacts = db.list_contacts()?;

    // Create app state
    let mut app = App::new();
    app.set_peer_id(our_peer_id);
    for c in contacts {
        app.add_contact(c);
    }

    // Set mode to chat
    app.mode = AppMode::Chat;

    // Derive encryption keys from our identity keypair (for fallback DM decryption)
    let (our_enc_pk, our_enc_sk) = keypair_to_encryption_keys(&keypair)
        .context("Failed to derive encryption keys")?;

    // Create and start the network node
    let mut node = WhisperNode::new(keypair).await.context("Failed to create network node")?;
    node.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    let node = Arc::new(Mutex::new(node));

    // Run the group TUI with multicast to all members
    run_group_tui_with_network(&mut app, &db, node, &group, &our_enc_pk, &our_enc_sk).await?;

    Ok(())
}

/// List all groups.
pub async fn handle_group_list(data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

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
        handle_add_contact("alice", &peer_id.to_string(), data_dir, "test")
            .await
            .unwrap();

        // Verify it was added
        let db = open_database(data_dir, "test").unwrap();
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

        handle_add_contact("alice", &peer1.to_string(), data_dir, "test")
            .await
            .unwrap();
        handle_add_contact("bob", &peer2.to_string(), data_dir, "test")
            .await
            .unwrap();

        // Verify via database
        let db = open_database(data_dir, "test").unwrap();
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
        handle_add_contact("alice", &peer.to_string(), data_dir, "test")
            .await
            .unwrap();

        handle_trust("alice", data_dir, "test").await.unwrap();

        let db = open_database(data_dir, "test").unwrap();
        let contact = db.get_contact_by_alias("alice").unwrap().unwrap();
        assert!(matches!(contact.trust_level, TrustLevel::Trusted));
    }

    #[tokio::test]
    async fn block_changes_level() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        let peer = PeerId::random();
        handle_add_contact("alice", &peer.to_string(), data_dir, "test")
            .await
            .unwrap();

        handle_block("alice", data_dir, "test").await.unwrap();

        let db = open_database(data_dir, "test").unwrap();
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
        let result = handle_send("nobody", "hello", data_dir, "test").await;
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
        handle_group_create("test-group", data_dir, "test").await.unwrap();

        let db = open_database(data_dir, "test").unwrap();
        let group = db.get_group_by_name("test-group").unwrap();
        assert!(group.is_some());
    }

    #[tokio::test]
    async fn group_create_duplicate_fails() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        handle_group_create("my-group", data_dir, "test").await.unwrap();

        let result = handle_group_create("my-group", data_dir, "test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn group_invite_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        handle_group_create("team", data_dir, "test").await.unwrap();

        let peer = PeerId::random();
        handle_add_contact("alice", &peer.to_string(), data_dir, "test")
            .await
            .unwrap();

        handle_group_invite("team", "alice", data_dir, "test").await.unwrap();

        let db = open_database(data_dir, "test").unwrap();
        let group = db.get_group_by_name("team").unwrap().unwrap();
        assert_eq!(group.members.len(), 1);
    }

    #[tokio::test]
    async fn group_invite_unknown_group_fails() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        let peer = PeerId::random();
        handle_add_contact("alice", &peer.to_string(), data_dir, "test")
            .await
            .unwrap();

        let result = handle_group_invite("nonexistent", "alice", data_dir, "test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn group_list_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        handle_group_create("group1", data_dir, "test").await.unwrap();
        handle_group_create("group2", data_dir, "test").await.unwrap();

        // Should not error
        handle_group_list(data_dir, "test").await.unwrap();
    }

    #[tokio::test]
    async fn peers_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Should not error
        handle_peers(data_dir, "test").await.unwrap();
    }

    // Receipt tests

    #[test]
    fn create_and_parse_delivered_receipt() {
        let msg_id = uuid::Uuid::new_v4();
        let receipt = create_receipt(&msg_id, crate::message::ReceiptType::Delivered);
        
        let parsed = parse_receipt(&receipt);
        assert!(parsed.is_some());
        
        let (parsed_id, parsed_type) = parsed.unwrap();
        assert_eq!(parsed_id, msg_id);
        assert!(matches!(parsed_type, crate::message::ReceiptType::Delivered));
    }

    #[test]
    fn create_and_parse_read_receipt() {
        let msg_id = uuid::Uuid::new_v4();
        let receipt = create_receipt(&msg_id, crate::message::ReceiptType::Read);
        
        let parsed = parse_receipt(&receipt);
        assert!(parsed.is_some());
        
        let (parsed_id, parsed_type) = parsed.unwrap();
        assert_eq!(parsed_id, msg_id);
        assert!(matches!(parsed_type, crate::message::ReceiptType::Read));
    }

    #[test]
    fn parse_receipt_rejects_non_receipts() {
        let text_msg = b"Hello, world!";
        assert!(parse_receipt(text_msg).is_none());
    }

    #[test]
    fn parse_receipt_rejects_malformed() {
        // Wrong prefix
        assert!(parse_receipt(b"RECEIPT:D:12345").is_none());
        // Too short
        assert!(parse_receipt(b"RCPT:D:123").is_none());
        // Invalid type
        assert!(parse_receipt(b"RCPT:X:12345678-1234-1234-1234-123456789012").is_none());
    }
}
