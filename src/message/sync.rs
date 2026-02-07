//! Message synchronization between peers.

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

use super::types::{Message, MessageStatus};

/// Request for message history.
#[derive(Debug, Clone)]
pub struct HistoryRequest {
    /// Request messages since this timestamp.
    pub since: DateTime<Utc>,
    /// Maximum number of messages to return.
    pub limit: Option<usize>,
}

impl HistoryRequest {
    /// Create a new history request.
    pub fn new(since: DateTime<Utc>) -> Self {
        Self { since, limit: None }
    }

    /// Create a request with limit.
    pub fn with_limit(since: DateTime<Utc>, limit: usize) -> Self {
        Self {
            since,
            limit: Some(limit),
        }
    }
}

/// Filter messages by timestamp for history response.
pub fn filter_history(messages: &[Message], since: DateTime<Utc>, limit: Option<usize>) -> Vec<&Message> {
    let mut filtered: Vec<_> = messages
        .iter()
        .filter(|m| m.timestamp > since)
        .collect();
    
    // Sort by timestamp
    filtered.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    
    if let Some(limit) = limit {
        filtered.truncate(limit);
    }
    
    filtered
}

/// Merge local and remote messages, deduplicating by ID.
/// 
/// When the same message ID exists in both, the newer status wins.
pub fn merge_messages(local: Vec<Message>, remote: Vec<Message>) -> Vec<Message> {
    let mut by_id: HashMap<Uuid, Message> = HashMap::new();
    
    // Add local messages first
    for msg in local {
        by_id.insert(msg.id, msg);
    }
    
    // Merge remote messages
    for remote_msg in remote {
        match by_id.get(&remote_msg.id) {
            Some(existing) => {
                // Keep the one with "better" status
                if status_priority(&remote_msg.status) > status_priority(&existing.status) {
                    by_id.insert(remote_msg.id, remote_msg);
                }
            }
            None => {
                by_id.insert(remote_msg.id, remote_msg);
            }
        }
    }
    
    // Sort by timestamp
    let mut result: Vec<_> = by_id.into_values().collect();
    result.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    result
}

/// Get priority of message status (higher = more final).
fn status_priority(status: &MessageStatus) -> u8 {
    match status {
        MessageStatus::Pending => 0,
        MessageStatus::Sent => 1,
        MessageStatus::Delivered => 2,
        MessageStatus::Read => 3,
        MessageStatus::Failed(_) => 4, // Failed is also final
    }
}

/// Check if a message needs to be synced.
pub fn needs_sync(message: &Message) -> bool {
    matches!(
        message.status,
        MessageStatus::Pending | MessageStatus::Sent
    )
}

/// Calculate messages that need to be sent to peer.
pub fn diff_messages<'a>(local: &'a [Message], remote_ids: &[Uuid]) -> Vec<&'a Message> {
    local
        .iter()
        .filter(|m| !remote_ids.contains(&m.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::types::Recipient;
    use chrono::Duration;
    use libp2p::identity::Keypair;
    use libp2p::PeerId;

    fn make_peer_id() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    fn make_message_at(from: PeerId, to: PeerId, text: &str, ts: DateTime<Utc>) -> Message {
        let mut msg = Message::new_text(from, Recipient::Direct(to), text.to_string());
        msg.timestamp = ts;
        msg
    }

    #[test]
    fn filter_history_respects_since() {
        let from = make_peer_id();
        let to = make_peer_id();
        let now = Utc::now();
        
        let old = make_message_at(from, to, "old", now - Duration::hours(2));
        let new = make_message_at(from, to, "new", now - Duration::minutes(30));
        let messages = vec![old, new];
        
        let since = now - Duration::hours(1);
        let filtered = filter_history(&messages, since, None);
        
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn filter_history_respects_limit() {
        let from = make_peer_id();
        let to = make_peer_id();
        let now = Utc::now();
        
        let messages: Vec<_> = (0..10)
            .map(|i| make_message_at(from, to, &format!("msg{}", i), now - Duration::minutes(i as i64)))
            .collect();
        
        let since = now - Duration::hours(1);
        let filtered = filter_history(&messages, since, Some(3));
        
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn merge_deduplicates_by_id() {
        let from = make_peer_id();
        let to = make_peer_id();
        
        let msg1 = Message::new_text(from, Recipient::Direct(to), "hello".to_string());
        let msg2 = msg1.clone(); // Same ID
        
        let local = vec![msg1];
        let remote = vec![msg2];
        
        let merged = merge_messages(local, remote);
        assert_eq!(merged.len(), 1);
    }

    #[test]
    fn merge_newer_status_wins() {
        let from = make_peer_id();
        let to = make_peer_id();
        
        let mut local_msg = Message::new_text(from, Recipient::Direct(to), "hello".to_string());
        local_msg.status = MessageStatus::Sent;
        
        let mut remote_msg = local_msg.clone();
        remote_msg.status = MessageStatus::Read;
        
        let merged = merge_messages(vec![local_msg], vec![remote_msg]);
        
        assert!(matches!(merged[0].status, MessageStatus::Read));
    }

    #[test]
    fn merge_preserves_ordering() {
        let from = make_peer_id();
        let to = make_peer_id();
        let now = Utc::now();
        
        let msg1 = make_message_at(from, to, "first", now - Duration::hours(2));
        let msg2 = make_message_at(from, to, "second", now - Duration::hours(1));
        let msg3 = make_message_at(from, to, "third", now);
        
        let local = vec![msg2.clone()];
        let remote = vec![msg1.clone(), msg3.clone()];
        
        let merged = merge_messages(local, remote);
        
        assert_eq!(merged.len(), 3);
        // Should be sorted by timestamp
        assert!(merged[0].timestamp < merged[1].timestamp);
        assert!(merged[1].timestamp < merged[2].timestamp);
    }

    #[test]
    fn needs_sync_pending_and_sent() {
        let from = make_peer_id();
        let to = make_peer_id();
        
        let mut pending = Message::new_text(from, Recipient::Direct(to), "pending".to_string());
        pending.status = MessageStatus::Pending;
        
        let mut sent = Message::new_text(from, Recipient::Direct(to), "sent".to_string());
        sent.status = MessageStatus::Sent;
        
        let mut delivered = Message::new_text(from, Recipient::Direct(to), "delivered".to_string());
        delivered.status = MessageStatus::Delivered;
        
        assert!(needs_sync(&pending));
        assert!(needs_sync(&sent));
        assert!(!needs_sync(&delivered));
    }

    #[test]
    fn diff_finds_missing_messages() {
        let from = make_peer_id();
        let to = make_peer_id();
        
        let msg1 = Message::new_text(from, Recipient::Direct(to), "msg1".to_string());
        let msg2 = Message::new_text(from, Recipient::Direct(to), "msg2".to_string());
        let msg3 = Message::new_text(from, Recipient::Direct(to), "msg3".to_string());
        
        let local = vec![msg1.clone(), msg2.clone(), msg3.clone()];
        let remote_ids = vec![msg1.id, msg3.id]; // Missing msg2
        
        let diff = diff_messages(&local, &remote_ids);
        
        assert_eq!(diff.len(), 1);
        assert_eq!(diff[0].id, msg2.id);
    }

    #[test]
    fn empty_merge() {
        let merged = merge_messages(vec![], vec![]);
        assert!(merged.is_empty());
    }
}
