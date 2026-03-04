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
    FileChunk(FileChunk),
    FileComplete(FileTransferComplete),
}

/// File transfer status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum FileTransferStatus {
    Pending,
    InProgress,
    Complete,
    Failed,
    Cancelled,
}

/// A chunk of a file being transferred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChunk {
    pub transfer_id: Uuid,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub checksum: [u8; 32],
}

impl FileChunk {
    /// Default chunk size (64KB for relay compatibility).
    pub const CHUNK_SIZE: usize = 64 * 1024;

    /// Create a new file chunk.
    pub fn new(transfer_id: Uuid, chunk_index: u32, total_chunks: u32, data: Vec<u8>) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let checksum: [u8; 32] = hasher.finalize().into();
        
        Self {
            transfer_id,
            chunk_index,
            total_chunks,
            data,
            checksum,
        }
    }

    /// Verify the chunk checksum.
    pub fn verify(&self) -> bool {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.data);
        let computed: [u8; 32] = hasher.finalize().into();
        computed == self.checksum
    }
}

/// File transfer completion notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTransferComplete {
    pub transfer_id: Uuid,
    pub filename: String,
    pub total_size: u64,
    pub file_checksum: [u8; 32],
}

/// Metadata for a file transfer.
#[derive(Debug, Clone)]
pub struct FileTransfer {
    pub id: Uuid,
    pub from: PeerId,
    pub to: Recipient,
    pub filename: String,
    pub total_size: u64,
    pub total_chunks: u32,
    pub chunks_received: u32,
    pub status: FileTransferStatus,
    pub created_at: DateTime<Utc>,
    pub file_checksum: [u8; 32],
}

impl FileTransfer {
    /// Create a new outgoing file transfer.
    pub fn new_outgoing(from: PeerId, to: Recipient, filename: String, data: &[u8]) -> Self {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let file_checksum: [u8; 32] = hasher.finalize().into();
        
        let total_size = data.len() as u64;
        let total_chunks = (total_size as usize).div_ceil(FileChunk::CHUNK_SIZE) as u32;

        Self {
            id: Uuid::new_v4(),
            from,
            to,
            filename,
            total_size,
            total_chunks,
            chunks_received: 0,
            status: FileTransferStatus::Pending,
            created_at: Utc::now(),
            file_checksum,
        }
    }

    /// Create a new incoming file transfer from metadata.
    pub fn new_incoming(
        id: Uuid,
        from: PeerId,
        to: Recipient,
        filename: String,
        total_size: u64,
        total_chunks: u32,
        file_checksum: [u8; 32],
    ) -> Self {
        Self {
            id,
            from,
            to,
            filename,
            total_size,
            total_chunks,
            chunks_received: 0,
            status: FileTransferStatus::InProgress,
            created_at: Utc::now(),
            file_checksum,
        }
    }

    /// Check if transfer is complete.
    pub fn is_complete(&self) -> bool {
        self.chunks_received >= self.total_chunks
    }

    /// Get progress as a percentage.
    pub fn progress(&self) -> f32 {
        if self.total_chunks == 0 {
            return 100.0;
        }
        (self.chunks_received as f32 / self.total_chunks as f32) * 100.0
    }

    /// Split file data into chunks.
    pub fn create_chunks(transfer_id: Uuid, data: &[u8]) -> Vec<FileChunk> {
        let total_chunks = data.len().div_ceil(FileChunk::CHUNK_SIZE) as u32;
        let mut chunks = Vec::new();

        for (i, chunk_data) in data.chunks(FileChunk::CHUNK_SIZE).enumerate() {
            chunks.push(FileChunk::new(
                transfer_id,
                i as u32,
                total_chunks,
                chunk_data.to_vec(),
            ));
        }

        chunks
    }

    /// Reassemble a file from its chunks.
    /// Chunks must be sorted by chunk_index.
    pub fn reassemble_file(chunks: &[FileChunk]) -> anyhow::Result<Vec<u8>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        // Sort chunks by index
        let mut sorted: Vec<_> = chunks.to_vec();
        sorted.sort_by_key(|c| c.chunk_index);

        // Verify we have all chunks
        let expected = sorted[0].total_chunks;
        if sorted.len() != expected as usize {
            anyhow::bail!("Missing chunks: have {}, expected {}", sorted.len(), expected);
        }

        // Verify all checksums and reassemble
        let mut data = Vec::new();
        for (i, chunk) in sorted.iter().enumerate() {
            if chunk.chunk_index != i as u32 {
                anyhow::bail!("Missing chunk {}", i);
            }
            if !chunk.verify() {
                anyhow::bail!("Chunk {} failed checksum verification", i);
            }
            data.extend_from_slice(&chunk.data);
        }

        Ok(data)
    }
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

    // File transfer tests

    #[test]
    fn file_chunk_new() {
        let transfer_id = Uuid::new_v4();
        let data = vec![1, 2, 3, 4, 5];
        let chunk = FileChunk::new(transfer_id, 0, 1, data.clone());

        assert_eq!(chunk.transfer_id, transfer_id);
        assert_eq!(chunk.chunk_index, 0);
        assert_eq!(chunk.total_chunks, 1);
        assert_eq!(chunk.data, data);
    }

    #[test]
    fn file_chunk_verify_valid() {
        let transfer_id = Uuid::new_v4();
        let data = vec![1, 2, 3, 4, 5];
        let chunk = FileChunk::new(transfer_id, 0, 1, data);

        assert!(chunk.verify());
    }

    #[test]
    fn file_chunk_verify_invalid() {
        let transfer_id = Uuid::new_v4();
        let data = vec![1, 2, 3, 4, 5];
        let mut chunk = FileChunk::new(transfer_id, 0, 1, data);
        
        // Corrupt the data
        chunk.data[0] = 99;
        assert!(!chunk.verify());
    }

    #[test]
    fn file_transfer_new_outgoing() {
        let from = make_peer_id();
        let to = make_peer_id();
        let data = vec![0u8; 100];
        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "test.txt".to_string(),
            &data,
        );

        assert_eq!(transfer.filename, "test.txt");
        assert_eq!(transfer.total_size, 100);
        assert_eq!(transfer.total_chunks, 1); // 100 bytes fits in one 64KB chunk
        assert_eq!(transfer.chunks_received, 0);
        assert_eq!(transfer.status, FileTransferStatus::Pending);
    }

    #[test]
    fn file_transfer_large_file_chunks() {
        let from = make_peer_id();
        let to = make_peer_id();
        // 200KB file = 4 chunks (64KB each, last one smaller)
        let data = vec![0u8; 200 * 1024];
        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "large.bin".to_string(),
            &data,
        );

        assert_eq!(transfer.total_chunks, 4);
    }

    #[test]
    fn file_transfer_progress() {
        let from = make_peer_id();
        let to = make_peer_id();
        let mut transfer = FileTransfer::new_incoming(
            Uuid::new_v4(),
            from,
            Recipient::Direct(to),
            "test.txt".to_string(),
            100,
            4,
            [0; 32],
        );

        assert_eq!(transfer.progress(), 0.0);
        
        transfer.chunks_received = 2;
        assert_eq!(transfer.progress(), 50.0);
        
        transfer.chunks_received = 4;
        assert_eq!(transfer.progress(), 100.0);
    }

    #[test]
    fn file_transfer_is_complete() {
        let from = make_peer_id();
        let to = make_peer_id();
        let mut transfer = FileTransfer::new_incoming(
            Uuid::new_v4(),
            from,
            Recipient::Direct(to),
            "test.txt".to_string(),
            100,
            4,
            [0; 32],
        );

        assert!(!transfer.is_complete());
        
        transfer.chunks_received = 4;
        assert!(transfer.is_complete());
    }

    #[test]
    fn file_transfer_create_chunks() {
        let transfer_id = Uuid::new_v4();
        let data = vec![0u8; 150 * 1024]; // 150KB = 3 chunks
        let chunks = FileTransfer::create_chunks(transfer_id, &data);

        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[1].chunk_index, 1);
        assert_eq!(chunks[2].chunk_index, 2);
        assert_eq!(chunks[0].total_chunks, 3);
        
        // First two chunks should be full size
        assert_eq!(chunks[0].data.len(), FileChunk::CHUNK_SIZE);
        assert_eq!(chunks[1].data.len(), FileChunk::CHUNK_SIZE);
        // Last chunk should be smaller
        assert_eq!(chunks[2].data.len(), 150 * 1024 - 2 * FileChunk::CHUNK_SIZE);
    }

    #[test]
    fn file_transfer_reassemble() {
        let transfer_id = Uuid::new_v4();
        let original_data: Vec<u8> = (0..200_000).map(|i| (i % 256) as u8).collect();
        
        // Create chunks
        let chunks = FileTransfer::create_chunks(transfer_id, &original_data);
        assert_eq!(chunks.len(), 4); // 200KB / 64KB = ~3.1 = 4 chunks
        
        // Reassemble
        let reassembled = FileTransfer::reassemble_file(&chunks).unwrap();
        
        assert_eq!(reassembled.len(), original_data.len());
        assert_eq!(reassembled, original_data);
    }

    #[test]
    fn file_transfer_reassemble_out_of_order() {
        let transfer_id = Uuid::new_v4();
        let original_data: Vec<u8> = (0..150_000).map(|i| (i % 256) as u8).collect();
        
        // Create chunks and shuffle
        let mut chunks = FileTransfer::create_chunks(transfer_id, &original_data);
        chunks.reverse(); // Put them in reverse order
        
        // Should still reassemble correctly
        let reassembled = FileTransfer::reassemble_file(&chunks).unwrap();
        
        assert_eq!(reassembled, original_data);
    }

    #[test]
    fn file_transfer_reassemble_missing_chunk() {
        let transfer_id = Uuid::new_v4();
        let data = vec![0u8; 150 * 1024];
        
        let mut chunks = FileTransfer::create_chunks(transfer_id, &data);
        chunks.remove(1); // Remove middle chunk
        
        let result = FileTransfer::reassemble_file(&chunks);
        assert!(result.is_err());
    }

    #[test]
    fn file_transfer_small_file_single_chunk() {
        let transfer_id = Uuid::new_v4();
        let data = vec![1, 2, 3, 4, 5];
        let chunks = FileTransfer::create_chunks(transfer_id, &data);

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].data, data);
    }
}
