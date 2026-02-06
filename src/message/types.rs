//! Message data types.

use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
}
