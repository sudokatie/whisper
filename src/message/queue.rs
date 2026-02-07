//! Offline message queue.

use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use uuid::Uuid;

use super::types::{Message, MessageStatus};
use crate::storage::Database;

/// Message queue for pending messages.
/// 
/// Maintains per-peer queues and persists to database for offline handling.
pub struct MessageQueue {
    /// Pending messages by peer.
    pending: HashMap<PeerId, VecDeque<Message>>,
    /// Database for persistence.
    db: Option<Database>,
}

impl MessageQueue {
    /// Create a new message queue.
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            db: None,
        }
    }

    /// Create a queue with database persistence.
    pub fn with_database(db: Database) -> Self {
        Self {
            pending: HashMap::new(),
            db: Some(db),
        }
    }

    /// Add a message to the queue.
    pub fn enqueue(&mut self, message: Message) {
        let peer_id = match &message.to {
            super::types::Recipient::Direct(peer) => *peer,
            super::types::Recipient::Group(_) => {
                // For groups, we'd need to enqueue for each member
                // For now, store under sender
                message.from
            }
        };

        self.pending
            .entry(peer_id)
            .or_default()
            .push_back(message);
    }

    /// Remove and return the oldest message for a peer.
    pub fn dequeue(&mut self, peer_id: &PeerId) -> Option<Message> {
        self.pending
            .get_mut(peer_id)
            .and_then(|queue| queue.pop_front())
    }

    /// View all pending messages for a peer without removing.
    pub fn peek_all(&self, peer_id: &PeerId) -> Vec<&Message> {
        self.pending
            .get(peer_id)
            .map(|q| q.iter().collect())
            .unwrap_or_default()
    }

    /// Get count of pending messages for a peer.
    pub fn pending_count(&self, peer_id: &PeerId) -> usize {
        self.pending.get(peer_id).map(|q| q.len()).unwrap_or(0)
    }

    /// Get total pending message count.
    pub fn total_pending(&self) -> usize {
        self.pending.values().map(|q| q.len()).sum()
    }

    /// Mark a message as sent and remove from pending.
    pub fn mark_sent(&mut self, message_id: Uuid) -> bool {
        for queue in self.pending.values_mut() {
            if let Some(pos) = queue.iter().position(|m| m.id == message_id) {
                queue.remove(pos);
                return true;
            }
        }
        false
    }

    /// Mark a message as failed with reason.
    pub fn mark_failed(&mut self, message_id: Uuid, reason: String) -> bool {
        for queue in self.pending.values_mut() {
            if let Some(msg) = queue.iter_mut().find(|m| m.id == message_id) {
                msg.status = MessageStatus::Failed(reason);
                return true;
            }
        }
        false
    }

    /// Get all peers with pending messages.
    pub fn peers_with_pending(&self) -> Vec<PeerId> {
        self.pending
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(peer, _)| *peer)
            .collect()
    }

    /// Retry all failed messages (move back to pending status).
    pub fn retry_failed(&mut self) -> usize {
        let mut count = 0;
        for queue in self.pending.values_mut() {
            for msg in queue.iter_mut() {
                if matches!(msg.status, MessageStatus::Failed(_)) {
                    msg.status = MessageStatus::Pending;
                    count += 1;
                }
            }
        }
        count
    }

    /// Clear all pending messages for a peer.
    pub fn clear_peer(&mut self, peer_id: &PeerId) {
        self.pending.remove(peer_id);
    }

    /// Clear all pending messages.
    pub fn clear_all(&mut self) {
        self.pending.clear();
    }
}

impl Default for MessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::types::Recipient;
    use libp2p::identity::Keypair;

    fn make_peer_id() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    fn make_message(from: PeerId, to: PeerId, text: &str) -> Message {
        Message::new_text(from, Recipient::Direct(to), text.to_string())
    }

    #[test]
    fn enqueue_adds_to_queue() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to = make_peer_id();
        let msg = make_message(from, to, "hello");

        queue.enqueue(msg);

        assert_eq!(queue.pending_count(&to), 1);
    }

    #[test]
    fn dequeue_returns_oldest_first() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to = make_peer_id();

        let msg1 = make_message(from, to, "first");
        let msg2 = make_message(from, to, "second");
        let id1 = msg1.id;

        queue.enqueue(msg1);
        queue.enqueue(msg2);

        let dequeued = queue.dequeue(&to).unwrap();
        assert_eq!(dequeued.id, id1);
    }

    #[test]
    fn peer_specific_queues() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to1 = make_peer_id();
        let to2 = make_peer_id();

        queue.enqueue(make_message(from, to1, "for peer 1"));
        queue.enqueue(make_message(from, to2, "for peer 2"));

        assert_eq!(queue.pending_count(&to1), 1);
        assert_eq!(queue.pending_count(&to2), 1);
        assert_eq!(queue.total_pending(), 2);
    }

    #[test]
    fn peek_all_returns_without_removing() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to = make_peer_id();

        queue.enqueue(make_message(from, to, "msg1"));
        queue.enqueue(make_message(from, to, "msg2"));

        let peeked = queue.peek_all(&to);
        assert_eq!(peeked.len(), 2);
        assert_eq!(queue.pending_count(&to), 2); // Still there
    }

    #[test]
    fn mark_sent_removes_from_pending() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to = make_peer_id();
        let msg = make_message(from, to, "hello");
        let msg_id = msg.id;

        queue.enqueue(msg);
        assert_eq!(queue.pending_count(&to), 1);

        let removed = queue.mark_sent(msg_id);
        assert!(removed);
        assert_eq!(queue.pending_count(&to), 0);
    }

    #[test]
    fn mark_failed_updates_status() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to = make_peer_id();
        let msg = make_message(from, to, "hello");
        let msg_id = msg.id;

        queue.enqueue(msg);
        queue.mark_failed(msg_id, "network error".to_string());

        let messages = queue.peek_all(&to);
        assert!(matches!(messages[0].status, MessageStatus::Failed(_)));
    }

    #[test]
    fn retry_failed_resets_status() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to = make_peer_id();
        let msg = make_message(from, to, "hello");
        let msg_id = msg.id;

        queue.enqueue(msg);
        queue.mark_failed(msg_id, "error".to_string());

        let count = queue.retry_failed();
        assert_eq!(count, 1);

        let messages = queue.peek_all(&to);
        assert!(matches!(messages[0].status, MessageStatus::Pending));
    }

    #[test]
    fn peers_with_pending_lists_active_peers() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to1 = make_peer_id();
        let to2 = make_peer_id();

        queue.enqueue(make_message(from, to1, "msg"));
        queue.enqueue(make_message(from, to2, "msg"));

        let peers = queue.peers_with_pending();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&to1));
        assert!(peers.contains(&to2));
    }

    #[test]
    fn clear_peer_removes_only_that_peer() {
        let mut queue = MessageQueue::new();
        let from = make_peer_id();
        let to1 = make_peer_id();
        let to2 = make_peer_id();

        queue.enqueue(make_message(from, to1, "msg"));
        queue.enqueue(make_message(from, to2, "msg"));

        queue.clear_peer(&to1);

        assert_eq!(queue.pending_count(&to1), 0);
        assert_eq!(queue.pending_count(&to2), 1);
    }

    #[test]
    fn dequeue_empty_returns_none() {
        let mut queue = MessageQueue::new();
        let peer = make_peer_id();

        assert!(queue.dequeue(&peer).is_none());
    }
}
