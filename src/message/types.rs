//! Message data types.

use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A group chat.
#[derive(Debug, Clone)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub members: Vec<PeerId>,
    pub symmetric_key: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

impl Group {
    /// Create a new group.
    pub fn new(name: String, symmetric_key: Vec<u8>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            members: Vec::new(),
            symmetric_key,
            created_at: Utc::now(),
        }
    }

    /// Add a member to the group.
    pub fn add_member(&mut self, peer_id: PeerId) {
        if !self.members.contains(&peer_id) {
            self.members.push(peer_id);
        }
    }

    /// Remove a member from the group.
    pub fn remove_member(&mut self, peer_id: &PeerId) -> bool {
        if let Some(pos) = self.members.iter().position(|p| p == peer_id) {
            self.members.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if a peer is a member.
    pub fn is_member(&self, peer_id: &PeerId) -> bool {
        self.members.contains(peer_id)
    }
}

/// Message recipient.
#[derive(Debug, Clone)]
pub enum Recipient {
    Direct(PeerId),
    Group(Uuid),
}

/// Message content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageContent {
    Text(String),
    Receipt(Uuid, ReceiptType),
}

/// Receipt type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ReceiptType {
    Delivered,
    Read,
}

/// Message status.
#[derive(Debug, Clone)]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
    Read,
    Failed(String),
}

/// A message.
#[derive(Debug, Clone)]
pub struct Message {
    pub id: Uuid,
    pub from: PeerId,
    pub to: Recipient,
    pub content: MessageContent,
    pub timestamp: DateTime<Utc>,
    pub status: MessageStatus,
}

impl Message {
    /// Create a new text message.
    pub fn new_text(from: PeerId, to: Recipient, text: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            from,
            to,
            content: MessageContent::Text(text),
            timestamp: Utc::now(),
            status: MessageStatus::Pending,
        }
    }

    /// Create a receipt message.
    pub fn new_receipt(from: PeerId, to: Recipient, message_id: Uuid, receipt_type: ReceiptType) -> Self {
        Self {
            id: Uuid::new_v4(),
            from,
            to,
            content: MessageContent::Receipt(message_id, receipt_type),
            timestamp: Utc::now(),
            status: MessageStatus::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn make_peer_id() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    #[test]
    fn create_text_message() {
        let from = make_peer_id();
        let to = make_peer_id();
        let msg = Message::new_text(from, Recipient::Direct(to), "hello".to_string());

        assert!(matches!(msg.content, MessageContent::Text(_)));
        assert!(matches!(msg.status, MessageStatus::Pending));
    }

    #[test]
    fn create_receipt() {
        let from = make_peer_id();
        let to = make_peer_id();
        let msg_id = Uuid::new_v4();
        let receipt = Message::new_receipt(from, Recipient::Direct(to), msg_id, ReceiptType::Delivered);

        assert!(matches!(receipt.content, MessageContent::Receipt(_, ReceiptType::Delivered)));
    }

    #[test]
    fn message_has_unique_id() {
        let from = make_peer_id();
        let to = make_peer_id();
        let msg1 = Message::new_text(from, Recipient::Direct(to), "a".to_string());
        let msg2 = Message::new_text(from, Recipient::Direct(to), "b".to_string());

        assert_ne!(msg1.id, msg2.id);
    }

    #[test]
    fn group_recipient() {
        let from = make_peer_id();
        let group_id = Uuid::new_v4();
        let msg = Message::new_text(from, Recipient::Group(group_id), "hello group".to_string());

        assert!(matches!(msg.to, Recipient::Group(_)));
    }

    #[test]
    fn create_group() {
        let group = Group::new("Test Group".to_string(), vec![1, 2, 3]);
        assert_eq!(group.name, "Test Group");
        assert_eq!(group.symmetric_key, vec![1, 2, 3]);
        assert!(group.members.is_empty());
    }

    #[test]
    fn group_add_member() {
        let mut group = Group::new("Test".to_string(), vec![]);
        let peer = make_peer_id();
        group.add_member(peer);
        assert_eq!(group.members.len(), 1);
        assert!(group.is_member(&peer));
    }

    #[test]
    fn group_add_member_idempotent() {
        let mut group = Group::new("Test".to_string(), vec![]);
        let peer = make_peer_id();
        group.add_member(peer);
        group.add_member(peer);
        assert_eq!(group.members.len(), 1);
    }

    #[test]
    fn group_remove_member() {
        let mut group = Group::new("Test".to_string(), vec![]);
        let peer = make_peer_id();
        group.add_member(peer);
        assert!(group.remove_member(&peer));
        assert!(!group.is_member(&peer));
    }

    #[test]
    fn group_remove_nonexistent() {
        let mut group = Group::new("Test".to_string(), vec![]);
        let peer = make_peer_id();
        assert!(!group.remove_member(&peer));
    }
}
