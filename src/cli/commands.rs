//! CLI command implementations.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bincode;
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

/// Wire message prefix for file chunks.
const FILE_CHUNK_PREFIX: &[u8] = b"FILE:";

/// Wire message prefix for file transfer completion.
const FILE_COMPLETE_PREFIX: &[u8] = b"FDNE:";

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

                        // Check if this is a file chunk
                        if decrypted.starts_with(FILE_CHUNK_PREFIX) {
                            if let Ok(chunk) = bincode::deserialize::<crate::message::FileChunk>(&decrypted[FILE_CHUNK_PREFIX.len()..]) {
                                // Verify checksum
                                if chunk.verify() {
                                    // Save chunk to database
                                    let _ = db.insert_file_chunk(&chunk);
                                    // Update transfer progress if it exists
                                    if let Ok(Some(mut transfer)) = db.get_file_transfer(&chunk.transfer_id) {
                                        transfer.chunks_received = transfer.chunks_received.saturating_add(1);
                                        let _ = db.update_file_transfer_progress(&transfer.id, transfer.chunks_received);
                                    }
                                }
                            }
                            continue;
                        }

                        // Check if this is a file transfer completion
                        if decrypted.starts_with(FILE_COMPLETE_PREFIX) {
                            if let Ok(complete) = bincode::deserialize::<FileTransferComplete>(&decrypted[FILE_COMPLETE_PREFIX.len()..]) {
                                // Create incoming transfer record if not exists
                                let transfer = FileTransfer::new_incoming(
                                    complete.transfer_id,
                                    from,
                                    Recipient::Direct(app.our_peer_id.unwrap_or_else(PeerId::random)),
                                    complete.filename.clone(),
                                    complete.total_size,
                                    ((complete.total_size as usize).div_ceil(crate::message::FileChunk::CHUNK_SIZE)) as u32,
                                    complete.file_checksum,
                                );
                                let _ = db.insert_file_transfer(&transfer);
                                // Try to reassemble if we have all chunks
                                if let Ok(chunks) = db.get_file_chunks(&complete.transfer_id) {
                                    if chunks.len() as u32 >= transfer.total_chunks {
                                        // Reassemble and verify
                                        if let Ok(data) = crate::message::FileTransfer::reassemble_file(&chunks) {
                                            use sha2::{Sha256, Digest};
                                            let mut hasher = Sha256::new();
                                            hasher.update(&data);
                                            let checksum: [u8; 32] = hasher.finalize().into();
                                            if checksum == complete.file_checksum {
                                                // File verified! Mark as complete
                                                let _ = db.update_file_transfer_status(&complete.transfer_id, FileTransferStatus::Complete);
                                            }
                                        }
                                    }
                                }
                            }
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
                            for member in &group.members {
                                // Don't send to ourselves
                                if member.peer_id != from {
                                    node.send_message(member.peer_id, encrypted.clone());
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

    // Load our keypair to get our peer ID (we become the owner)
    let key_path = keypair_path(data_dir);
    if !key_path.exists() {
        anyhow::bail!("No identity found. Run: whisper init");
    }
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let my_peer_id = keypair_to_peer_id(&keypair);

    // Check if group already exists
    if db.get_group_by_name(name)?.is_some() {
        anyhow::bail!("Group '{}' already exists", name);
    }

    // Generate symmetric key for group
    let symmetric_key = generate_group_key();

    // Create group with us as owner
    let group = Group::new(name.to_string(), symmetric_key, Some(my_peer_id));
    db.create_group(&group)?;

    println!("Created group: {}", name);
    println!("Group ID: {}", group.id);
    println!("You are the owner of this group.");

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
        let owner_str = if group.owner.is_some() { " [owner]" } else { "" };
        println!("  {} ({} members){}", group.name, group.members.len(), owner_str);
        if let Some(desc) = &group.description {
            println!("    {}", desc);
        }
    }

    Ok(())
}

/// Kick a member from a group (owner/admin only).
pub async fn handle_group_kick(group_name: &str, alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let my_peer_id = keypair_to_peer_id(&keypair);

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    // Check permissions
    if !group.can_manage(&my_peer_id) {
        anyhow::bail!("You don't have permission to kick members from this group");
    }

    // Get contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Can't kick the owner
    if group.is_owner(&contact.peer_id) {
        anyhow::bail!("Cannot kick the group owner");
    }

    // Remove member
    if db.remove_group_member(&group.id, &contact.peer_id)? {
        println!("Kicked {} from group '{}'", alias, group_name);
    } else {
        println!("{} is not a member of group '{}'", alias, group_name);
    }

    Ok(())
}

/// Promote a member to admin (owner only).
pub async fn handle_group_promote(group_name: &str, alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    use crate::message::MemberRole;
    
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let my_peer_id = keypair_to_peer_id(&keypair);

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    // Only owner can promote
    if !group.is_owner(&my_peer_id) {
        anyhow::bail!("Only the group owner can promote members to admin");
    }

    // Get contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Check if they're a member
    if !group.is_member(&contact.peer_id) {
        anyhow::bail!("{} is not a member of group '{}'", alias, group_name);
    }

    // Promote
    if db.set_member_role(&group.id, &contact.peer_id, MemberRole::Admin)? {
        println!("Promoted {} to admin in group '{}'", alias, group_name);
    } else {
        anyhow::bail!("Failed to promote {}", alias);
    }

    Ok(())
}

/// Demote an admin to member (owner only).
pub async fn handle_group_demote(group_name: &str, alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    use crate::message::MemberRole;
    
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let my_peer_id = keypair_to_peer_id(&keypair);

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    // Only owner can demote
    if !group.is_owner(&my_peer_id) {
        anyhow::bail!("Only the group owner can demote admins");
    }

    // Get contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Demote
    if db.set_member_role(&group.id, &contact.peer_id, MemberRole::Member)? {
        println!("Demoted {} from admin in group '{}'", alias, group_name);
    } else {
        anyhow::bail!("{} is not a member of group '{}'", alias, group_name);
    }

    Ok(())
}

/// Transfer group ownership (owner only).
pub async fn handle_group_transfer(group_name: &str, alias: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let my_peer_id = keypair_to_peer_id(&keypair);

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    // Only owner can transfer
    if !group.is_owner(&my_peer_id) {
        anyhow::bail!("Only the group owner can transfer ownership");
    }

    // Get contact
    let contact = db
        .get_contact_by_alias(alias)?
        .ok_or_else(|| anyhow::anyhow!("Contact '{}' not found", alias))?;

    // Check if they're a member
    if !group.is_member(&contact.peer_id) {
        anyhow::bail!("{} is not a member of group '{}'. Invite them first.", alias, group_name);
    }

    // Transfer ownership
    if db.transfer_group_ownership(&group.id, &contact.peer_id)? {
        println!("Transferred ownership of group '{}' to {}", group_name, alias);
    } else {
        anyhow::bail!("Failed to transfer ownership");
    }

    Ok(())
}

/// Update group settings (owner/admin only).
pub async fn handle_group_settings(
    group_name: &str,
    new_name: Option<&str>,
    description: Option<&str>,
    data_dir: &Path,
    passphrase: &str,
) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Load our keypair
    let key_path = keypair_path(data_dir);
    let keypair = load_keypair(&key_path, passphrase).context("Failed to load keypair")?;
    let my_peer_id = keypair_to_peer_id(&keypair);

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    // Check permissions
    if !group.can_manage(&my_peer_id) {
        anyhow::bail!("You don't have permission to modify this group's settings");
    }

    // Update settings
    let desc_update = description.map(|d| if d.is_empty() { None } else { Some(d) });
    
    if db.update_group_settings(&group.id, new_name, desc_update)? {
        if let Some(n) = new_name {
            println!("Updated group name to: {}", n);
        }
        if let Some(d) = description {
            if d.is_empty() {
                println!("Cleared group description");
            } else {
                println!("Updated group description: {}", d);
            }
        }
    } else {
        println!("No changes made");
    }

    Ok(())
}

/// Show group info including members and their roles.
pub async fn handle_group_info(group_name: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    // Get group
    let group = db
        .get_group_by_name(group_name)?
        .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

    println!("Group: {}", group.name);
    println!("ID: {}", group.id);
    if let Some(desc) = &group.description {
        println!("Description: {}", desc);
    }
    println!("Created: {}", group.created_at);
    
    println!("\nMembers ({}):", group.members.len());
    
    // Try to resolve member names from contacts
    for member in &group.members {
        let is_owner = group.is_owner(&member.peer_id);
        let alias = db.get_contact(&member.peer_id)?
            .map(|c| c.alias)
            .unwrap_or_else(|| member.peer_id.to_string());
        
        let role_str = if is_owner {
            "owner"
        } else {
            match member.role {
                crate::message::MemberRole::Admin => "admin",
                crate::message::MemberRole::Member => "member",
            }
        };
        
        println!("  {} [{}]", alias, role_str);
    }

    Ok(())
}

// === File Transfer Commands ===

use crate::message::{FileTransfer, FileTransferComplete, FileTransferStatus};

/// Send a file to a contact.
pub async fn handle_file_send(alias: &str, file_path: &Path, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;
    let keypair = load_keypair(&keypair_path(data_dir), passphrase)?;
    let our_peer_id = keypair_to_peer_id(&keypair);

    // Find the contact
    let contact = db.get_contact_by_alias(alias)?
        .with_context(|| format!("Contact '{}' not found", alias))?;

    // Read the file
    let file_data = fs::read(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

    let filename = file_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Create the transfer record
    let transfer = FileTransfer::new_outgoing(
        our_peer_id,
        Recipient::Direct(contact.peer_id),
        filename.clone(),
        &file_data,
    );

    // Save to database
    db.insert_file_transfer(&transfer)?;

    // Create chunks and save them
    let chunks = FileTransfer::create_chunks(transfer.id, &file_data);
    for chunk in &chunks {
        db.insert_file_chunk(chunk)?;
    }

    println!("File transfer created:");
    println!("  ID: {}", transfer.id);
    println!("  File: {}", filename);
    println!("  Size: {} bytes", file_data.len());
    println!("  Chunks: {}", chunks.len());
    println!();

    // Try to send over network if contact has public key
    if !contact.public_key.is_empty() {
        println!("Sending file to {}...", alias);
        
        // Convert Ed25519 public key to X25519 for encryption
        let recipient_pk = match ed25519_pk_to_x25519(&contact.public_key) {
            Ok(pk) => pk,
            Err(_) => {
                println!("Warning: Could not convert contact's public key. Chunks stored locally only.");
                println!("Transfer queued. Use 'whisper file status {}' to check progress.", transfer.id);
                return Ok(());
            }
        };

        // Create and start network node
        let mut node = WhisperNode::new(keypair.clone()).await.context("Failed to create network node")?;
        node.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        
        // Send each chunk
        let total = chunks.len();
        for (i, chunk) in chunks.iter().enumerate() {
            // Serialize the chunk
            let chunk_data = bincode::serialize(chunk)?;
            
            // Create wire message: FILE:<chunk_data>
            let mut wire_msg = FILE_CHUNK_PREFIX.to_vec();
            wire_msg.extend_from_slice(&chunk_data);
            
            // Encrypt for recipient
            let encrypted = encrypt_message(&wire_msg, &recipient_pk)?;
            
            // Send via network
            node.send_message(contact.peer_id, encrypted);
            
            // Progress indicator
            let progress = ((i + 1) as f32 / total as f32 * 100.0) as u32;
            print!("\r  Sending chunk {}/{} ({}%)", i + 1, total, progress);
            io::Write::flush(&mut io::stdout())?;
        }
        
        // Send completion notification
        let complete = FileTransferComplete {
            transfer_id: transfer.id,
            filename: filename.clone(),
            total_size: transfer.total_size,
            file_checksum: transfer.file_checksum,
        };
        let complete_data = bincode::serialize(&complete)?;
        let mut wire_msg = FILE_COMPLETE_PREFIX.to_vec();
        wire_msg.extend_from_slice(&complete_data);
        let encrypted = encrypt_message(&wire_msg, &recipient_pk)?;
        node.send_message(contact.peer_id, encrypted);
        
        println!("\n  File transfer queued for delivery.");
        println!("  Chunks will be sent when peer is online.");
    } else {
        println!("Warning: Contact has no public key stored. Cannot encrypt file.");
        println!("Use 'whisper import-contact' to add their public key.");
    }

    println!();
    println!("Use 'whisper file status {}' to check progress.", transfer.id);

    Ok(())
}

/// List file transfers.
pub async fn handle_file_list(data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    let transfers = db.list_file_transfers(None)?;

    if transfers.is_empty() {
        println!("No file transfers.");
        return Ok(());
    }

    println!("File transfers:");
    println!();

    for transfer in transfers {
        let status_str = match transfer.status {
            FileTransferStatus::Pending => "Pending",
            FileTransferStatus::InProgress => "In Progress",
            FileTransferStatus::Complete => "Complete",
            FileTransferStatus::Failed => "Failed",
            FileTransferStatus::Cancelled => "Cancelled",
        };

        let direction = if transfer.chunks_received == 0 && transfer.status == FileTransferStatus::Pending {
            "outgoing"
        } else {
            "incoming"
        };

        println!("  {} [{}] ({}) - {:.1}%",
            transfer.filename,
            status_str,
            direction,
            transfer.progress()
        );
        println!("    ID: {}", transfer.id);
        println!("    Size: {} bytes ({} chunks)", transfer.total_size, transfer.total_chunks);
        println!();
    }

    Ok(())
}

/// Show status of a specific transfer.
pub async fn handle_file_status(id_str: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    let id = uuid::Uuid::parse_str(id_str)
        .with_context(|| format!("Invalid transfer ID: {}", id_str))?;

    let transfer = db.get_file_transfer(&id)?
        .with_context(|| format!("Transfer not found: {}", id))?;

    let status_str = match transfer.status {
        FileTransferStatus::Pending => "Pending",
        FileTransferStatus::InProgress => "In Progress",
        FileTransferStatus::Complete => "Complete",
        FileTransferStatus::Failed => "Failed",
        FileTransferStatus::Cancelled => "Cancelled",
    };

    println!("File Transfer Status:");
    println!();
    println!("  ID: {}", transfer.id);
    println!("  File: {}", transfer.filename);
    println!("  Size: {} bytes", transfer.total_size);
    println!("  Status: {}", status_str);
    println!("  Progress: {:.1}% ({}/{} chunks)",
        transfer.progress(),
        transfer.chunks_received,
        transfer.total_chunks
    );
    println!("  Created: {}", transfer.created_at);

    if transfer.status == FileTransferStatus::Complete {
        println!();
        println!("Transfer complete. File can be reassembled.");
    }

    Ok(())
}

/// Cancel an in-progress transfer.
pub async fn handle_file_cancel(id_str: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;

    let id = uuid::Uuid::parse_str(id_str)
        .with_context(|| format!("Invalid transfer ID: {}", id_str))?;

    let transfer = db.get_file_transfer(&id)?
        .with_context(|| format!("Transfer not found: {}", id))?;

    match transfer.status {
        FileTransferStatus::Complete => {
            println!("Transfer already complete. Cannot cancel.");
            return Ok(());
        }
        FileTransferStatus::Cancelled => {
            println!("Transfer already cancelled.");
            return Ok(());
        }
        _ => {}
    }

    // Update status to cancelled
    db.update_file_transfer(&id, transfer.chunks_received, &FileTransferStatus::Cancelled)?;

    println!("Transfer cancelled: {}", transfer.filename);

    Ok(())
}

/// Resume an interrupted file transfer.
pub async fn handle_file_resume(id_str: &str, data_dir: &Path, passphrase: &str) -> Result<()> {
    let db = open_database(data_dir, passphrase)?;
    let keypair = load_keypair(&keypair_path(data_dir), passphrase)?;

    let id = uuid::Uuid::parse_str(id_str)
        .with_context(|| format!("Invalid transfer ID: {}", id_str))?;

    let transfer = db.get_file_transfer(&id)?
        .with_context(|| format!("Transfer not found: {}", id))?;

    // Check if resumable
    match transfer.status {
        FileTransferStatus::Complete => {
            println!("Transfer already complete.");
            return Ok(());
        }
        FileTransferStatus::Cancelled => {
            println!("Transfer was cancelled. Cannot resume.");
            return Ok(());
        }
        _ => {}
    }

    // Get existing chunks
    let existing_chunks = db.get_file_chunks(&id)?;
    let existing_indices: std::collections::HashSet<u32> = existing_chunks.iter()
        .map(|c| c.chunk_index)
        .collect();

    // Find missing chunk indices
    let missing: Vec<u32> = (0..transfer.total_chunks)
        .filter(|i| !existing_indices.contains(i))
        .collect();

    if missing.is_empty() {
        println!("All chunks present. Marking as complete.");
        db.update_file_transfer_status(&id, FileTransferStatus::Complete)?;
        return Ok(());
    }

    // Get recipient from transfer
    let recipient_peer_id = match &transfer.to {
        Recipient::Direct(peer_id) => *peer_id,
        Recipient::Group(_) => {
            println!("Group file transfers not yet supported for resume.");
            return Ok(());
        }
    };

    // Find contact with matching peer_id to get their public key
    let contacts = db.list_contacts()?;
    let contact = contacts.iter()
        .find(|c| c.peer_id == recipient_peer_id)
        .with_context(|| "Recipient contact not found")?;

    if contact.public_key.is_empty() {
        println!("Contact has no public key. Cannot encrypt.");
        return Ok(());
    }

    let recipient_pk = ed25519_pk_to_x25519(&contact.public_key)?;

    // Create network node
    let mut node = WhisperNode::new(keypair).await.context("Failed to create network node")?;
    node.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Resend missing chunks
    println!("Resuming transfer: {} missing chunks of {}", missing.len(), transfer.total_chunks);

    for (i, chunk_index) in missing.iter().enumerate() {
        // Get the chunk data - we need to recreate it from the original file
        // For now, we can only resume if we have all chunks stored locally
        if let Ok(Some(chunk)) = db.get_file_chunk(&id, *chunk_index) {
            let chunk_data = bincode::serialize(&chunk)?;
            let mut wire_msg = FILE_CHUNK_PREFIX.to_vec();
            wire_msg.extend_from_slice(&chunk_data);
            let encrypted = encrypt_message(&wire_msg, &recipient_pk)?;
            node.send_message(recipient_peer_id, encrypted);

            let progress = ((i + 1) as f32 / missing.len() as f32 * 100.0) as u32;
            print!("\r  Resending chunk {}/{} ({}%)", i + 1, missing.len(), progress);
            io::Write::flush(&mut io::stdout())?;
        } else {
            println!("\nWarning: Chunk {} not found locally. Cannot resume fully.", chunk_index);
        }
    }

    // Update status to in progress
    db.update_file_transfer_status(&id, FileTransferStatus::InProgress)?;

    println!("\n  Resume complete. Missing chunks queued for delivery.");

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

    // File transfer tests

    #[tokio::test]
    async fn file_list_empty() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();
        
        // Should not error on empty list
        handle_file_list(data_dir, "test").await.unwrap();
    }

    #[tokio::test]
    async fn file_send_creates_transfer() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Add a contact first
        let peer_id = PeerId::random();
        handle_add_contact("bob", &peer_id.to_string(), data_dir, "test")
            .await
            .unwrap();

        // Create a test file
        let test_file = temp.path().join("test.txt");
        fs::write(&test_file, "Hello, this is test content!").unwrap();

        // Send the file
        handle_file_send("bob", &test_file, data_dir, "test")
            .await
            .unwrap();

        // Verify transfer was created
        let db = open_database(data_dir, "test").unwrap();
        let transfers = db.list_file_transfers(None).unwrap();
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].filename, "test.txt");
    }

    #[tokio::test]
    async fn file_status_shows_transfer() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Add a contact
        let peer_id = PeerId::random();
        handle_add_contact("bob", &peer_id.to_string(), data_dir, "test")
            .await
            .unwrap();

        // Create and send a file
        let test_file = temp.path().join("data.bin");
        fs::write(&test_file, vec![0u8; 1000]).unwrap();
        handle_file_send("bob", &test_file, data_dir, "test").await.unwrap();

        // Get the transfer ID
        let db = open_database(data_dir, "test").unwrap();
        let transfers = db.list_file_transfers(None).unwrap();
        let transfer_id = transfers[0].id.to_string();

        // Check status (should not error)
        handle_file_status(&transfer_id, data_dir, "test").await.unwrap();
    }

    #[tokio::test]
    async fn file_cancel_works() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Add a contact
        let peer_id = PeerId::random();
        handle_add_contact("bob", &peer_id.to_string(), data_dir, "test")
            .await
            .unwrap();

        // Create and send a file
        let test_file = temp.path().join("cancel_test.txt");
        fs::write(&test_file, "test content").unwrap();
        handle_file_send("bob", &test_file, data_dir, "test").await.unwrap();

        // Get the transfer ID
        let db = open_database(data_dir, "test").unwrap();
        let transfers = db.list_file_transfers(None).unwrap();
        let transfer_id = transfers[0].id.to_string();
        drop(db);

        // Cancel it
        handle_file_cancel(&transfer_id, data_dir, "test").await.unwrap();

        // Verify status changed
        let db = open_database(data_dir, "test").unwrap();
        let transfer = db.get_file_transfer(&transfers[0].id).unwrap().unwrap();
        assert_eq!(transfer.status, FileTransferStatus::Cancelled);
    }

    #[tokio::test]
    async fn file_send_fails_unknown_contact() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        let test_file = temp.path().join("test.txt");
        fs::write(&test_file, "content").unwrap();

        // Should fail - contact doesn't exist
        let result = handle_file_send("unknown", &test_file, data_dir, "test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn file_resume_cancelled_fails() {
        let temp = TempDir::new().unwrap();
        let data_dir = temp.path();

        handle_init(data_dir, "test").await.unwrap();

        // Add a contact
        let peer_id = PeerId::random();
        handle_add_contact("bob", &peer_id.to_string(), data_dir, "test")
            .await
            .unwrap();

        // Create and send a file
        let test_file = temp.path().join("resume_test.txt");
        fs::write(&test_file, "test content for resume").unwrap();
        handle_file_send("bob", &test_file, data_dir, "test").await.unwrap();

        // Get the transfer ID and cancel it
        let db = open_database(data_dir, "test").unwrap();
        let transfers = db.list_file_transfers(None).unwrap();
        let transfer_id = transfers[0].id.to_string();
        drop(db);

        handle_file_cancel(&transfer_id, data_dir, "test").await.unwrap();

        // Resuming a cancelled transfer should print message but not error
        let result = handle_file_resume(&transfer_id, data_dir, "test").await;
        assert!(result.is_ok());
    }
}
