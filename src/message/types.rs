//! Message data types.

use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Message recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    Sent,
    Delivered,
    Read,
    Failed(String),
}

/// A message.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
