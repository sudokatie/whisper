//! Network integration tests for Whisper.
//!
//! Basic tests for network functionality.
//! Full multi-node tests are complex due to async event loop requirements.

use std::time::Duration;

use libp2p::Multiaddr;
use tokio::time::timeout;

use whisper::identity::generate_keypair;
use whisper::network::{NodeEvent, WhisperNode};

/// Test: Node can be created with a keypair.
#[tokio::test]
async fn node_creation_works() {
    let keypair = generate_keypair();
    let node = WhisperNode::new(keypair).await;
    assert!(node.is_ok(), "Node should be created successfully");
}

/// Test: Node reports its peer ID.
#[tokio::test]
async fn node_has_peer_id() {
    let keypair = generate_keypair();
    let node = WhisperNode::new(keypair.clone()).await.unwrap();

    // Peer ID should match the keypair
    let expected_peer_id = libp2p::PeerId::from(keypair.public());
    assert_eq!(node.peer_id(), expected_peer_id);
}

/// Test: Node can listen on an address.
#[tokio::test]
async fn node_can_listen() {
    let keypair = generate_keypair();
    let mut node = WhisperNode::new(keypair).await.unwrap();

    let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    let result = node.listen_on(listen_addr);
    assert!(result.is_ok(), "Node should be able to listen");
}

/// Test: Node reports listening address.
#[tokio::test]
async fn node_reports_listening_address() {
    let keypair = generate_keypair();
    let mut node = WhisperNode::new(keypair).await.unwrap();

    let listen_addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
    node.listen_on(listen_addr).unwrap();

    let result = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = node.poll_event().await {
                if let NodeEvent::Listening(addr) = event {
                    return addr;
                }
            }
        }
    })
    .await;

    assert!(result.is_ok(), "Should receive listening address");
    let addr = result.unwrap();
    assert!(
        addr.to_string().contains("127.0.0.1"),
        "Address should be localhost"
    );
}

/// Test: Node initially has no connected peers.
#[tokio::test]
async fn node_starts_with_no_peers() {
    let keypair = generate_keypair();
    let node = WhisperNode::new(keypair).await.unwrap();

    assert!(
        node.connected_peers().is_empty(),
        "New node should have no connected peers"
    );
}

/// Test: Node can queue messages for offline peers.
#[tokio::test]
async fn node_can_queue_messages() {
    let keypair = generate_keypair();
    let mut node = WhisperNode::new(keypair).await.unwrap();

    // Generate a fake peer ID to send to
    let other_keypair = generate_keypair();
    let other_peer = libp2p::PeerId::from(other_keypair.public());

    // Queue a message (peer not connected)
    assert_eq!(node.pending_count(), 0);
    node.send_message(other_peer, b"Hello".to_vec());

    // Message should be pending since peer isn't connected
    assert_eq!(
        node.pending_count(),
        1,
        "Message should be queued for offline peer"
    );
}

/// Test: Node tracks connection state correctly.
#[tokio::test]
async fn node_tracks_connection_state() {
    let keypair = generate_keypair();
    let mut node = WhisperNode::new(keypair).await.unwrap();

    let fake_peer = libp2p::PeerId::random();

    // Initially not connected
    assert!(!node.is_connected(&fake_peer));

    // Manually add as connected (simulating connection event)
    node.add_connected_peer(fake_peer);
    assert!(node.is_connected(&fake_peer));
    assert_eq!(node.connected_peers().len(), 1);

    // Remove connection
    node.remove_connected_peer(&fake_peer);
    assert!(!node.is_connected(&fake_peer));
    assert!(node.connected_peers().is_empty());
}

/// Test: Pending messages are cleared when peer connects.
#[tokio::test]
async fn pending_messages_clear_on_connect() {
    let keypair = generate_keypair();
    let mut node = WhisperNode::new(keypair).await.unwrap();

    let other_peer = libp2p::PeerId::random();

    // Queue messages
    node.send_message(other_peer, b"Message 1".to_vec());
    node.send_message(other_peer, b"Message 2".to_vec());
    assert_eq!(node.pending_count(), 2);

    // Simulate peer connecting (this triggers flush_pending internally)
    node.add_connected_peer(other_peer);

    // Pending messages should be cleared (sent)
    assert_eq!(
        node.pending_count(),
        0,
        "Pending messages should be flushed on connect"
    );
}
