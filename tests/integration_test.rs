//! Integration tests for Whisper.
//!
//! Tests end-to-end flows combining multiple modules.

use libp2p::PeerId;
use tempfile::TempDir;

use whisper::cli;
use whisper::crypto::{decrypt_from_group, decrypt_message, encrypt_for_group, encrypt_message, generate_group_key};
use whisper::identity::{generate_keypair, keypair_to_peer_id, TrustLevel};
use whisper::message::{Message, MessageQueue, Recipient};
use whisper::storage::Database;

/// Test: Create identity and save to disk.
#[tokio::test]
async fn create_identity_and_save() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path();

    // Initialize identity
    cli::handle_init(data_dir, "test_passphrase").await.unwrap();

    // Verify files were created
    let key_path = data_dir.join("identity.key");
    let db_path = data_dir.join("whisper.db");

    assert!(key_path.exists(), "Keypair file should exist");
    assert!(db_path.exists(), "Database file should exist");
}

/// Test: Add contact and verify it appears in list.
#[tokio::test]
async fn add_contact_and_list() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path();

    // Initialize
    cli::handle_init(data_dir, "test").await.unwrap();

    // Add contact
    let peer = PeerId::random();
    cli::handle_add_contact("alice", &peer.to_string(), data_dir)
        .await
        .unwrap();

    // Verify via database
    let db = Database::open(&data_dir.join("whisper.db")).unwrap();
    let contacts = db.list_contacts().unwrap();

    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].alias, "alice");
    assert_eq!(contacts[0].peer_id, peer);
}

/// Test: Encrypt message for contact using sealed box.
#[tokio::test]
async fn encrypt_message_for_contact() {
    use sodiumoxide::crypto::box_;

    // Generate recipient keypair (sodiumoxide, not libp2p)
    let (recipient_pk, recipient_sk) = box_::gen_keypair();

    // Encrypt message
    let plaintext = b"Hello, Alice!";
    let ciphertext = encrypt_message(plaintext, &recipient_pk).unwrap();

    // Decrypt with recipient's keypair
    let decrypted = decrypt_message(&ciphertext, &recipient_pk, &recipient_sk).unwrap();

    assert_eq!(decrypted, plaintext);
}

/// Test: Store message in database and retrieve.
#[tokio::test]
async fn store_message_in_db() {
    let temp = TempDir::new().unwrap();
    let db_path = temp.path().join("test.db");

    let db = Database::open(&db_path).unwrap();

    // Create and store message
    let from = PeerId::random();
    let to = PeerId::random();
    let msg = Message::new_text(from, Recipient::Direct(to), "Test message".to_string());

    db.insert_message(&msg).unwrap();

    // Retrieve
    let messages = db.get_messages_with_peer(&to, 100).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].id, msg.id);
}

/// Test: Queue message for offline peer.
#[tokio::test]
async fn queue_message_for_offline_peer() {
    let from = PeerId::random();
    let to = PeerId::random();

    let mut queue = MessageQueue::new();

    // Queue message
    let msg = Message::new_text(from, Recipient::Direct(to), "Offline message".to_string());
    queue.enqueue(msg.clone());

    // Verify it's queued
    let pending = queue.peek_all(&to);
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, msg.id);
}

/// Test: Multiple contacts with different trust levels.
#[tokio::test]
async fn multiple_contacts_trust_levels() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path();

    cli::handle_init(data_dir, "test").await.unwrap();

    let peer1 = PeerId::random();
    let peer2 = PeerId::random();
    let peer3 = PeerId::random();

    cli::handle_add_contact("alice", &peer1.to_string(), data_dir)
        .await
        .unwrap();
    cli::handle_add_contact("bob", &peer2.to_string(), data_dir)
        .await
        .unwrap();
    cli::handle_add_contact("eve", &peer3.to_string(), data_dir)
        .await
        .unwrap();

    // Set different trust levels
    cli::handle_trust("alice", data_dir).await.unwrap();
    cli::handle_block("eve", data_dir).await.unwrap();

    // Verify
    let db = Database::open(&data_dir.join("whisper.db")).unwrap();

    let alice = db.get_contact_by_alias("alice").unwrap().unwrap();
    let bob = db.get_contact_by_alias("bob").unwrap().unwrap();
    let eve = db.get_contact_by_alias("eve").unwrap().unwrap();

    assert!(matches!(alice.trust_level, TrustLevel::Trusted));
    assert!(matches!(bob.trust_level, TrustLevel::Unknown));
    assert!(matches!(eve.trust_level, TrustLevel::Blocked));
}

/// Test: Group encryption with symmetric key.
#[tokio::test]
async fn group_encryption_flow() {
    // Generate group key
    let group_key = generate_group_key();

    // Encrypt message
    let plaintext = b"Hello group!";
    let ciphertext = encrypt_for_group(plaintext, &group_key).unwrap();

    // Any member with the key can decrypt
    let decrypted = decrypt_from_group(&ciphertext, &group_key).unwrap();
    assert_eq!(decrypted, plaintext);
}

/// Test: Message queue multiple peers.
#[tokio::test]
async fn message_queue_multiple_peers() {
    let from = PeerId::random();
    let peer1 = PeerId::random();
    let peer2 = PeerId::random();

    let mut queue = MessageQueue::new();

    // Queue messages for different peers
    queue.enqueue(Message::new_text(
        from,
        Recipient::Direct(peer1),
        "Message 1".to_string(),
    ));
    queue.enqueue(Message::new_text(
        from,
        Recipient::Direct(peer2),
        "Message 2".to_string(),
    ));
    queue.enqueue(Message::new_text(
        from,
        Recipient::Direct(peer1),
        "Message 3".to_string(),
    ));

    // Check peer-specific queues
    assert_eq!(queue.peek_all(&peer1).len(), 2);
    assert_eq!(queue.peek_all(&peer2).len(), 1);
}

/// Test: Full identity workflow.
#[tokio::test]
async fn full_identity_workflow() {
    use whisper::identity::{export_public_key, load_keypair, save_keypair};

    let temp = TempDir::new().unwrap();
    let key_path = temp.path().join("identity.key");

    // Generate and save
    let keypair = generate_keypair();
    let peer_id = keypair_to_peer_id(&keypair);
    let public_key = export_public_key(&keypair);

    save_keypair(&keypair, &key_path, "secret").unwrap();

    // Load and verify
    let loaded = load_keypair(&key_path, "secret").unwrap();
    let loaded_id = keypair_to_peer_id(&loaded);

    assert_eq!(peer_id, loaded_id);
    assert_eq!(export_public_key(&loaded), public_key);
}

/// Test: Status command with existing identity.
#[tokio::test]
async fn status_with_identity() {
    let temp = TempDir::new().unwrap();
    let data_dir = temp.path();

    cli::handle_init(data_dir, "test").await.unwrap();

    // Add some contacts
    cli::handle_add_contact("alice", &PeerId::random().to_string(), data_dir)
        .await
        .unwrap();
    cli::handle_add_contact("bob", &PeerId::random().to_string(), data_dir)
        .await
        .unwrap();

    // Status should work without error
    cli::handle_status(data_dir, "test").await.unwrap();
}
