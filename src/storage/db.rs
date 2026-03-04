//! Database operations.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use libp2p::PeerId;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::identity::{Contact, TrustLevel};
use crate::message::{
    FileChunk, FileTransfer, FileTransferStatus,
    Group, Message, MessageContent, MessageStatus, Recipient,
};

/// SQLite database wrapper with SQLCipher encryption.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create encrypted database at path.
    /// 
    /// The encryption_key should be derived using Argon2 from the user's passphrase.
    /// Use `storage::derive_database_key()` to derive the key.
    /// If the database already exists, it will be opened with the key.
    /// If the key is wrong, an error is returned.
    pub fn open(path: &Path, encryption_key: &str) -> Result<Self> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        
        // Set the encryption key using SQLCipher PRAGMA
        // This must be done before any other database operations
        // The key should be in format x'hexstring' from derive_database_key()
        if !encryption_key.is_empty() {
            conn.pragma_update(None, "key", encryption_key)
                .context("Failed to set encryption key - wrong passphrase?")?;
        }
        
        // Verify the key is correct by trying to access the database
        // SQLCipher returns an error on first query if key is wrong
        // We use query_row instead of execute since SELECT returns results
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
            .context("Database authentication failed - incorrect passphrase")?;
        
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }
    
    /// Open or create encrypted database using a passphrase.
    /// 
    /// This derives the encryption key using Argon2 and then opens the database.
    /// The data_dir is used to store/load the salt file.
    pub fn open_with_passphrase(path: &Path, passphrase: &str, data_dir: &Path) -> Result<Self> {
        let key = super::encryption::derive_database_key(passphrase, data_dir)?;
        Self::open(path, &key)
    }

    /// Open an in-memory database (for testing).
    /// In-memory databases don't need encryption.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }
    
    /// Open an encrypted in-memory database (for testing encryption).
    #[cfg(test)]
    pub fn open_in_memory_encrypted(passphrase: &str) -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        if !passphrase.is_empty() {
            conn.pragma_update(None, "key", passphrase)
                .context("Failed to set encryption key")?;
        }
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Run migrations.
    fn migrate(&self) -> Result<()> {
        self.conn
            .execute_batch(include_str!("schema.sql"))
            .context("Failed to run migrations")?;
        Ok(())
    }

    // === Message Operations ===

    /// Insert a message.
    pub fn insert_message(&self, msg: &Message) -> Result<()> {
        let to_peer = match &msg.to {
            Recipient::Direct(peer) => peer.to_string(),
            Recipient::Group(id) => id.to_string(),
        };
        let content = serde_json::to_vec(&msg.content)?;
        let status = format!("{:?}", msg.status);

        self.conn.execute(
            "INSERT INTO messages (id, from_peer, to_peer, content, timestamp, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                msg.id.to_string(),
                msg.from.to_string(),
                to_peer,
                content,
                msg.timestamp.timestamp(),
                status,
            ],
        )?;
        Ok(())
    }

    /// Get messages with a peer.
    pub fn get_messages_with_peer(&self, peer_id: &PeerId, limit: usize) -> Result<Vec<Message>> {
        let peer_str = peer_id.to_string();
        let mut stmt = self.conn.prepare(
            "SELECT id, from_peer, to_peer, content, timestamp, status
             FROM messages
             WHERE from_peer = ?1 OR to_peer = ?1
             ORDER BY timestamp DESC
             LIMIT ?2",
        )?;

        let rows = stmt.query_map(params![peer_str, limit as i64], |row| {
            Ok(MessageRow {
                id: row.get(0)?,
                from_peer: row.get(1)?,
                to_peer: row.get(2)?,
                content: row.get(3)?,
                timestamp: row.get(4)?,
                status: row.get(5)?,
            })
        })?;

        let mut messages = Vec::new();
        for row in rows {
            let row = row?;
            if let Ok(msg) = self.row_to_message(row) {
                messages.push(msg);
            }
        }
        Ok(messages)
    }

    /// Update message status.
    pub fn update_message_status(&self, id: &Uuid, status: &MessageStatus) -> Result<bool> {
        let status_str = format!("{:?}", status);
        let rows = self.conn.execute(
            "UPDATE messages SET status = ?1 WHERE id = ?2",
            params![status_str, id.to_string()],
        )?;
        Ok(rows > 0)
    }

    fn row_to_message(&self, row: MessageRow) -> Result<Message> {
        let id = Uuid::parse_str(&row.id)?;
        let from: PeerId = row.from_peer.parse()?;
        let to = if let Ok(peer) = row.to_peer.parse::<PeerId>() {
            Recipient::Direct(peer)
        } else {
            Recipient::Group(Uuid::parse_str(&row.to_peer)?)
        };
        let content: MessageContent = serde_json::from_slice(&row.content)?;
        let timestamp = Utc.timestamp_opt(row.timestamp, 0).single().unwrap_or_else(Utc::now);
        let status = match row.status.as_str() {
            "Pending" => MessageStatus::Pending,
            "Sent" => MessageStatus::Sent,
            "Delivered" => MessageStatus::Delivered,
            "Read" => MessageStatus::Read,
            s if s.starts_with("Failed") => MessageStatus::Failed(s.to_string()),
            _ => MessageStatus::Pending,
        };

        Ok(Message {
            id,
            from,
            to,
            content,
            timestamp,
            status,
        })
    }

    // === Contact Operations ===

    /// Insert or update a contact.
    pub fn upsert_contact(&self, contact: &Contact) -> Result<()> {
        let trust = format!("{:?}", contact.trust_level);
        let last_seen = contact.last_seen.map(|dt| dt.timestamp());

        self.conn.execute(
            "INSERT OR REPLACE INTO contacts (peer_id, alias, public_key, trust_level, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                contact.peer_id.to_string(),
                contact.alias,
                contact.public_key,
                trust,
                last_seen,
            ],
        )?;
        Ok(())
    }

    /// Get a contact by peer ID.
    pub fn get_contact(&self, peer_id: &PeerId) -> Result<Option<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id, alias, public_key, trust_level, last_seen FROM contacts WHERE peer_id = ?1",
        )?;

        stmt.query_row(params![peer_id.to_string()], |row| {
            self.row_to_contact(row)
        })
        .optional()
        .map_err(Into::into)
    }

    /// Get a contact by alias.
    pub fn get_contact_by_alias(&self, alias: &str) -> Result<Option<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id, alias, public_key, trust_level, last_seen FROM contacts WHERE alias = ?1",
        )?;

        stmt.query_row(params![alias], |row| self.row_to_contact(row))
            .optional()
            .map_err(Into::into)
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Result<Vec<Contact>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id, alias, public_key, trust_level, last_seen FROM contacts ORDER BY alias",
        )?;

        let rows = stmt.query_map([], |row| self.row_to_contact(row))?;

        let mut contacts = Vec::new();
        for row in rows {
            contacts.push(row?);
        }
        Ok(contacts)
    }

    /// Delete a contact.
    pub fn delete_contact(&self, peer_id: &PeerId) -> Result<bool> {
        let rows = self
            .conn
            .execute("DELETE FROM contacts WHERE peer_id = ?1", params![peer_id.to_string()])?;
        Ok(rows > 0)
    }

    fn row_to_contact(&self, row: &rusqlite::Row) -> rusqlite::Result<Contact> {
        let peer_id_str: String = row.get(0)?;
        let alias: String = row.get(1)?;
        let public_key: Vec<u8> = row.get(2)?;
        let trust_str: String = row.get(3)?;
        let last_seen_ts: Option<i64> = row.get(4)?;

        let peer_id = peer_id_str
            .parse()
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;

        let trust_level = match trust_str.as_str() {
            "Verified" => TrustLevel::Verified,
            "Trusted" => TrustLevel::Trusted,
            "Blocked" => TrustLevel::Blocked,
            _ => TrustLevel::Unknown,
        };

        let last_seen = last_seen_ts.and_then(|ts| Utc.timestamp_opt(ts, 0).single());

        Ok(Contact {
            peer_id,
            alias,
            public_key,
            trust_level,
            last_seen,
        })
    }

    // === Group Operations ===

    /// Create a new group.
    pub fn create_group(&self, group: &Group) -> Result<()> {
        self.conn.execute(
            "INSERT INTO groups (id, name, symmetric_key, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                group.id.to_string(),
                group.name,
                group.symmetric_key,
                group.created_at.timestamp(),
            ],
        )?;

        // Add members
        for member in &group.members {
            self.add_group_member(&group.id, member)?;
        }

        Ok(())
    }

    /// Get a group by ID.
    pub fn get_group(&self, id: &Uuid) -> Result<Option<Group>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, symmetric_key, created_at FROM groups WHERE id = ?1",
        )?;

        let group_opt = stmt
            .query_row(params![id.to_string()], |row| {
                let id_str: String = row.get(0)?;
                let name: String = row.get(1)?;
                let symmetric_key: Vec<u8> = row.get(2)?;
                let created_at_ts: i64 = row.get(3)?;

                Ok((id_str, name, symmetric_key, created_at_ts))
            })
            .optional()?;

        match group_opt {
            Some((id_str, name, symmetric_key, created_at_ts)) => {
                let id = Uuid::parse_str(&id_str)?;
                let created_at = Utc.timestamp_opt(created_at_ts, 0).single().unwrap_or_else(Utc::now);
                let members = self.get_group_members(&id)?;

                Ok(Some(Group {
                    id,
                    name,
                    members,
                    symmetric_key,
                    created_at,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get a group by name.
    pub fn get_group_by_name(&self, name: &str) -> Result<Option<Group>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM groups WHERE name = ?1",
        )?;

        let id_opt: Option<String> = stmt
            .query_row(params![name], |row| row.get(0))
            .optional()?;

        match id_opt {
            Some(id_str) => {
                let id = Uuid::parse_str(&id_str)?;
                self.get_group(&id)
            }
            None => Ok(None),
        }
    }

    /// List all groups.
    pub fn list_groups(&self) -> Result<Vec<Group>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, symmetric_key, created_at FROM groups ORDER BY name",
        )?;

        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let name: String = row.get(1)?;
            let symmetric_key: Vec<u8> = row.get(2)?;
            let created_at_ts: i64 = row.get(3)?;
            Ok((id_str, name, symmetric_key, created_at_ts))
        })?;

        let mut groups = Vec::new();
        for row in rows {
            let (id_str, name, symmetric_key, created_at_ts) = row?;
            let id = Uuid::parse_str(&id_str)?;
            let created_at = Utc.timestamp_opt(created_at_ts, 0).single().unwrap_or_else(Utc::now);
            let members = self.get_group_members(&id)?;

            groups.push(Group {
                id,
                name,
                members,
                symmetric_key,
                created_at,
            });
        }

        Ok(groups)
    }

    /// Delete a group.
    pub fn delete_group(&self, id: &Uuid) -> Result<bool> {
        // Delete members first
        self.conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1",
            params![id.to_string()],
        )?;

        let rows = self
            .conn
            .execute("DELETE FROM groups WHERE id = ?1", params![id.to_string()])?;
        Ok(rows > 0)
    }

    /// Add a member to a group.
    pub fn add_group_member(&self, group_id: &Uuid, peer_id: &PeerId) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO group_members (group_id, peer_id) VALUES (?1, ?2)",
            params![group_id.to_string(), peer_id.to_string()],
        )?;
        Ok(())
    }

    /// Remove a member from a group.
    pub fn remove_group_member(&self, group_id: &Uuid, peer_id: &PeerId) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND peer_id = ?2",
            params![group_id.to_string(), peer_id.to_string()],
        )?;
        Ok(rows > 0)
    }

    /// Get members of a group.
    fn get_group_members(&self, group_id: &Uuid) -> Result<Vec<PeerId>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_id FROM group_members WHERE group_id = ?1",
        )?;

        let rows = stmt.query_map(params![group_id.to_string()], |row| {
            let peer_str: String = row.get(0)?;
            Ok(peer_str)
        })?;

        let mut members = Vec::new();
        for row in rows {
            let peer_str = row?;
            if let Ok(peer_id) = peer_str.parse() {
                members.push(peer_id);
            }
        }

        Ok(members)
    }

    // === Pending Message Queue (Persistent Offline Queue) ===

    /// Queue an encrypted message for later delivery.
    pub fn queue_pending_message(&self, id: &Uuid, to_peer: &PeerId, encrypted_data: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO pending_messages (id, to_peer, encrypted_data, created_at, attempts)
             VALUES (?1, ?2, ?3, ?4, 0)",
            params![
                id.to_string(),
                to_peer.to_string(),
                encrypted_data,
                Utc::now().timestamp(),
            ],
        )?;
        Ok(())
    }

    /// Get all pending messages for a peer.
    pub fn get_pending_for_peer(&self, peer_id: &PeerId) -> Result<Vec<(Uuid, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, encrypted_data FROM pending_messages WHERE to_peer = ?1 ORDER BY created_at",
        )?;

        let rows = stmt.query_map(params![peer_id.to_string()], |row| {
            let id_str: String = row.get(0)?;
            let data: Vec<u8> = row.get(1)?;
            Ok((id_str, data))
        })?;

        let mut pending = Vec::new();
        for row in rows {
            let (id_str, data) = row?;
            if let Ok(id) = Uuid::parse_str(&id_str) {
                pending.push((id, data));
            }
        }

        Ok(pending)
    }

    /// Remove a pending message after successful delivery.
    pub fn remove_pending_message(&self, id: &Uuid) -> Result<bool> {
        let rows = self.conn.execute(
            "DELETE FROM pending_messages WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(rows > 0)
    }

    /// Get all pending messages (for loading queue on startup).
    pub fn get_all_pending(&self) -> Result<Vec<(Uuid, PeerId, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, to_peer, encrypted_data FROM pending_messages ORDER BY created_at",
        )?;

        let rows = stmt.query_map([], |row| {
            let id_str: String = row.get(0)?;
            let peer_str: String = row.get(1)?;
            let data: Vec<u8> = row.get(2)?;
            Ok((id_str, peer_str, data))
        })?;

        let mut pending = Vec::new();
        for row in rows {
            let (id_str, peer_str, data) = row?;
            if let (Ok(id), Ok(peer_id)) = (Uuid::parse_str(&id_str), peer_str.parse()) {
                pending.push((id, peer_id, data));
            }
        }

        Ok(pending)
    }

    /// Increment attempt count for a pending message.
    pub fn increment_pending_attempts(&self, id: &Uuid) -> Result<()> {
        self.conn.execute(
            "UPDATE pending_messages SET attempts = attempts + 1 WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(())
    }

    // === File Transfer Operations ===

    /// Insert a new file transfer.
    pub fn insert_file_transfer(&self, transfer: &FileTransfer) -> Result<()> {
        let to_peer = match &transfer.to {
            Recipient::Direct(peer) => peer.to_string(),
            Recipient::Group(id) => id.to_string(),
        };
        let status = format!("{:?}", transfer.status);

        self.conn.execute(
            "INSERT INTO file_transfers (id, from_peer, to_peer, filename, total_size, total_chunks, chunks_received, status, created_at, file_checksum)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                transfer.id.to_string(),
                transfer.from.to_string(),
                to_peer,
                transfer.filename,
                transfer.total_size as i64,
                transfer.total_chunks as i64,
                transfer.chunks_received as i64,
                status,
                transfer.created_at.timestamp(),
                transfer.file_checksum.as_slice(),
            ],
        )?;
        Ok(())
    }

    /// Get a file transfer by ID.
    pub fn get_file_transfer(&self, id: &Uuid) -> Result<Option<FileTransfer>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, from_peer, to_peer, filename, total_size, total_chunks, chunks_received, status, created_at, file_checksum
             FROM file_transfers WHERE id = ?1",
        )?;

        let result = stmt.query_row(params![id.to_string()], |row| {
            Ok(FileTransferRow {
                id: row.get(0)?,
                from_peer: row.get(1)?,
                to_peer: row.get(2)?,
                filename: row.get(3)?,
                total_size: row.get(4)?,
                total_chunks: row.get(5)?,
                chunks_received: row.get(6)?,
                status: row.get(7)?,
                created_at: row.get(8)?,
                file_checksum: row.get(9)?,
            })
        }).optional()?;

        match result {
            Some(row) => Ok(Some(self.row_to_file_transfer(row)?)),
            None => Ok(None),
        }
    }

    /// Update file transfer status and chunk count.
    pub fn update_file_transfer(&self, id: &Uuid, chunks_received: u32, status: &FileTransferStatus) -> Result<bool> {
        let status_str = format!("{:?}", status);
        let rows = self.conn.execute(
            "UPDATE file_transfers SET chunks_received = ?1, status = ?2 WHERE id = ?3",
            params![chunks_received as i64, status_str, id.to_string()],
        )?;
        Ok(rows > 0)
    }

    /// List file transfers with optional status filter.
    pub fn list_file_transfers(&self, status: Option<&FileTransferStatus>) -> Result<Vec<FileTransfer>> {
        let mut transfers = Vec::new();
        
        if let Some(s) = status {
            let status_str = format!("{:?}", s);
            let mut stmt = self.conn.prepare(
                "SELECT id, from_peer, to_peer, filename, total_size, total_chunks, chunks_received, status, created_at, file_checksum
                 FROM file_transfers WHERE status = ?1 ORDER BY created_at DESC",
            )?;
            
            let rows = stmt.query_map(params![status_str], |row| {
                Ok(FileTransferRow {
                    id: row.get(0)?,
                    from_peer: row.get(1)?,
                    to_peer: row.get(2)?,
                    filename: row.get(3)?,
                    total_size: row.get(4)?,
                    total_chunks: row.get(5)?,
                    chunks_received: row.get(6)?,
                    status: row.get(7)?,
                    created_at: row.get(8)?,
                    file_checksum: row.get(9)?,
                })
            })?;
            
            for row in rows {
                if let Ok(transfer) = self.row_to_file_transfer(row?) {
                    transfers.push(transfer);
                }
            }
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id, from_peer, to_peer, filename, total_size, total_chunks, chunks_received, status, created_at, file_checksum
                 FROM file_transfers ORDER BY created_at DESC",
            )?;
            
            let rows = stmt.query_map([], |row| {
                Ok(FileTransferRow {
                    id: row.get(0)?,
                    from_peer: row.get(1)?,
                    to_peer: row.get(2)?,
                    filename: row.get(3)?,
                    total_size: row.get(4)?,
                    total_chunks: row.get(5)?,
                    chunks_received: row.get(6)?,
                    status: row.get(7)?,
                    created_at: row.get(8)?,
                    file_checksum: row.get(9)?,
                })
            })?;
            
            for row in rows {
                if let Ok(transfer) = self.row_to_file_transfer(row?) {
                    transfers.push(transfer);
                }
            }
        }
        
        Ok(transfers)
    }

    /// Insert a file chunk.
    pub fn insert_file_chunk(&self, chunk: &FileChunk) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO file_chunks (transfer_id, chunk_index, data, checksum, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                chunk.transfer_id.to_string(),
                chunk.chunk_index as i64,
                chunk.data.as_slice(),
                chunk.checksum.as_slice(),
                Utc::now().timestamp(),
            ],
        )?;
        Ok(())
    }

    /// Get a file chunk.
    pub fn get_file_chunk(&self, transfer_id: &Uuid, chunk_index: u32) -> Result<Option<FileChunk>> {
        let mut stmt = self.conn.prepare(
            "SELECT transfer_id, chunk_index, data, checksum
             FROM file_chunks WHERE transfer_id = ?1 AND chunk_index = ?2",
        )?;

        let result = stmt.query_row(
            params![transfer_id.to_string(), chunk_index as i64],
            |row| {
                let data: Vec<u8> = row.get(2)?;
                let checksum_vec: Vec<u8> = row.get(3)?;
                let total_chunks: u32 = row.get::<_, i64>(1)? as u32;
                Ok((data, checksum_vec, total_chunks))
            },
        ).optional()?;

        match result {
            Some((data, checksum_vec, _)) => {
                let mut checksum = [0u8; 32];
                if checksum_vec.len() == 32 {
                    checksum.copy_from_slice(&checksum_vec);
                }
                Ok(Some(FileChunk {
                    transfer_id: *transfer_id,
                    chunk_index,
                    total_chunks: 0, // Will be set from transfer metadata
                    data,
                    checksum,
                }))
            }
            None => Ok(None),
        }
    }

    /// Get all chunks for a transfer.
    pub fn get_file_chunks(&self, transfer_id: &Uuid) -> Result<Vec<FileChunk>> {
        let mut stmt = self.conn.prepare(
            "SELECT chunk_index, data, checksum FROM file_chunks
             WHERE transfer_id = ?1 ORDER BY chunk_index",
        )?;

        let rows = stmt.query_map(params![transfer_id.to_string()], |row| {
            let chunk_index: i64 = row.get(0)?;
            let data: Vec<u8> = row.get(1)?;
            let checksum_vec: Vec<u8> = row.get(2)?;
            Ok((chunk_index as u32, data, checksum_vec))
        })?;

        let mut chunks = Vec::new();
        for row in rows {
            let (chunk_index, data, checksum_vec) = row?;
            let mut checksum = [0u8; 32];
            if checksum_vec.len() == 32 {
                checksum.copy_from_slice(&checksum_vec);
            }
            chunks.push(FileChunk {
                transfer_id: *transfer_id,
                chunk_index,
                total_chunks: chunks.len() as u32 + 1, // Placeholder
                data,
                checksum,
            });
        }
        Ok(chunks)
    }

    /// Delete a file transfer and its chunks.
    pub fn delete_file_transfer(&self, id: &Uuid) -> Result<bool> {
        // Foreign key cascade will delete chunks
        let rows = self.conn.execute(
            "DELETE FROM file_transfers WHERE id = ?1",
            params![id.to_string()],
        )?;
        Ok(rows > 0)
    }

    /// Reassemble file from chunks.
    pub fn reassemble_file(&self, transfer_id: &Uuid) -> Result<Vec<u8>> {
        let chunks = self.get_file_chunks(transfer_id)?;
        let mut data = Vec::new();
        for chunk in chunks {
            data.extend(chunk.data);
        }
        Ok(data)
    }

    fn row_to_file_transfer(&self, row: FileTransferRow) -> Result<FileTransfer> {
        use crate::message::{FileTransfer, FileTransferStatus};
        
        let id = Uuid::parse_str(&row.id)?;
        let from: PeerId = row.from_peer.parse()?;
        let to = if let Ok(peer) = row.to_peer.parse::<PeerId>() {
            Recipient::Direct(peer)
        } else {
            Recipient::Group(Uuid::parse_str(&row.to_peer)?)
        };
        let created_at = Utc.timestamp_opt(row.created_at, 0).single().unwrap_or_else(Utc::now);
        let status = match row.status.as_str() {
            "Pending" => FileTransferStatus::Pending,
            "InProgress" => FileTransferStatus::InProgress,
            "Complete" => FileTransferStatus::Complete,
            "Failed" => FileTransferStatus::Failed,
            "Cancelled" => FileTransferStatus::Cancelled,
            _ => FileTransferStatus::Pending,
        };

        let mut file_checksum = [0u8; 32];
        if row.file_checksum.len() == 32 {
            file_checksum.copy_from_slice(&row.file_checksum);
        }

        Ok(FileTransfer {
            id,
            from,
            to,
            filename: row.filename,
            total_size: row.total_size as u64,
            total_chunks: row.total_chunks as u32,
            chunks_received: row.chunks_received as u32,
            status,
            created_at,
            file_checksum,
        })
    }
}

struct MessageRow {
    id: String,
    from_peer: String,
    to_peer: String,
    content: Vec<u8>,
    timestamp: i64,
    status: String,
}

struct FileTransferRow {
    id: String,
    from_peer: String,
    to_peer: String,
    filename: String,
    total_size: i64,
    total_chunks: i64,
    chunks_received: i64,
    status: String,
    created_at: i64,
    file_checksum: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Contact;
    use libp2p::identity::Keypair;

    fn make_peer_id() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    #[test]
    fn open_creates_tables() {
        let db = Database::open_in_memory().unwrap();
        // Should not panic - tables exist
        db.list_contacts().unwrap();
    }

    #[test]
    fn insert_and_get_contact() {
        let db = Database::open_in_memory().unwrap();
        let peer_id = make_peer_id();
        let contact = Contact::new(peer_id, "alice".to_string(), vec![1, 2, 3]);

        db.upsert_contact(&contact).unwrap();
        let loaded = db.get_contact(&peer_id).unwrap().unwrap();

        assert_eq!(loaded.alias, "alice");
        assert_eq!(loaded.public_key, vec![1, 2, 3]);
    }

    #[test]
    fn get_contact_by_alias() {
        let db = Database::open_in_memory().unwrap();
        let contact = Contact::new(make_peer_id(), "bob".to_string(), vec![]);

        db.upsert_contact(&contact).unwrap();
        let loaded = db.get_contact_by_alias("bob").unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn list_contacts_returns_all() {
        let db = Database::open_in_memory().unwrap();

        db.upsert_contact(&Contact::new(make_peer_id(), "alice".to_string(), vec![])).unwrap();
        db.upsert_contact(&Contact::new(make_peer_id(), "bob".to_string(), vec![])).unwrap();

        let contacts = db.list_contacts().unwrap();
        assert_eq!(contacts.len(), 2);
    }

    #[test]
    fn delete_contact_works() {
        let db = Database::open_in_memory().unwrap();
        let peer_id = make_peer_id();
        let contact = Contact::new(peer_id, "alice".to_string(), vec![]);

        db.upsert_contact(&contact).unwrap();
        assert!(db.delete_contact(&peer_id).unwrap());
        assert!(db.get_contact(&peer_id).unwrap().is_none());
    }

    #[test]
    fn insert_message() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();
        let msg = Message::new_text(from, Recipient::Direct(to), "hello".to_string());

        db.insert_message(&msg).unwrap();
    }

    #[test]
    fn get_messages_with_peer() {
        let db = Database::open_in_memory().unwrap();
        let me = make_peer_id();
        let them = make_peer_id();

        let msg1 = Message::new_text(me, Recipient::Direct(them), "hi".to_string());
        let msg2 = Message::new_text(them, Recipient::Direct(me), "hello".to_string());

        db.insert_message(&msg1).unwrap();
        db.insert_message(&msg2).unwrap();

        let messages = db.get_messages_with_peer(&them, 10).unwrap();
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn update_message_status() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();
        let msg = Message::new_text(from, Recipient::Direct(to), "test".to_string());

        db.insert_message(&msg).unwrap();
        assert!(db.update_message_status(&msg.id, &MessageStatus::Sent).unwrap());
    }

    #[test]
    fn upsert_updates_existing() {
        let db = Database::open_in_memory().unwrap();
        let peer_id = make_peer_id();

        let mut contact = Contact::new(peer_id, "alice".to_string(), vec![1]);
        db.upsert_contact(&contact).unwrap();

        contact.public_key = vec![2, 3];
        db.upsert_contact(&contact).unwrap();

        let loaded = db.get_contact(&peer_id).unwrap().unwrap();
        assert_eq!(loaded.public_key, vec![2, 3]);

        // Should still be only one contact
        assert_eq!(db.list_contacts().unwrap().len(), 1);
    }

    #[test]
    fn contact_trust_level_persists() {
        let db = Database::open_in_memory().unwrap();
        let peer_id = make_peer_id();
        let mut contact = Contact::new(peer_id, "alice".to_string(), vec![]);
        contact.trust_level = TrustLevel::Trusted;

        db.upsert_contact(&contact).unwrap();
        let loaded = db.get_contact(&peer_id).unwrap().unwrap();
        assert_eq!(loaded.trust_level, TrustLevel::Trusted);
    }

    #[test]
    fn contact_last_seen_persists() {
        let db = Database::open_in_memory().unwrap();
        let peer_id = make_peer_id();
        let mut contact = Contact::new(peer_id, "alice".to_string(), vec![]);
        contact.last_seen = Some(Utc::now());

        db.upsert_contact(&contact).unwrap();
        let loaded = db.get_contact(&peer_id).unwrap().unwrap();
        assert!(loaded.last_seen.is_some());
    }

    // === Group Tests ===

    #[test]
    fn create_and_get_group() {
        let db = Database::open_in_memory().unwrap();
        let group = Group::new("Test Group".to_string(), vec![1, 2, 3]);

        db.create_group(&group).unwrap();
        let loaded = db.get_group(&group.id).unwrap().unwrap();

        assert_eq!(loaded.name, "Test Group");
        assert_eq!(loaded.symmetric_key, vec![1, 2, 3]);
    }

    #[test]
    fn get_group_by_name() {
        let db = Database::open_in_memory().unwrap();
        let group = Group::new("My Group".to_string(), vec![]);

        db.create_group(&group).unwrap();
        let loaded = db.get_group_by_name("My Group").unwrap();

        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().id, group.id);
    }

    #[test]
    fn list_groups() {
        let db = Database::open_in_memory().unwrap();

        db.create_group(&Group::new("Alpha".to_string(), vec![])).unwrap();
        db.create_group(&Group::new("Beta".to_string(), vec![])).unwrap();

        let groups = db.list_groups().unwrap();
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn delete_group() {
        let db = Database::open_in_memory().unwrap();
        let group = Group::new("ToDelete".to_string(), vec![]);

        db.create_group(&group).unwrap();
        assert!(db.delete_group(&group.id).unwrap());
        assert!(db.get_group(&group.id).unwrap().is_none());
    }

    #[test]
    fn add_group_member() {
        let db = Database::open_in_memory().unwrap();
        let group = Group::new("Team".to_string(), vec![]);
        let peer = make_peer_id();

        db.create_group(&group).unwrap();
        db.add_group_member(&group.id, &peer).unwrap();

        let loaded = db.get_group(&group.id).unwrap().unwrap();
        assert_eq!(loaded.members.len(), 1);
        assert_eq!(loaded.members[0], peer);
    }

    #[test]
    fn remove_group_member() {
        let db = Database::open_in_memory().unwrap();
        let mut group = Group::new("Team".to_string(), vec![]);
        let peer = make_peer_id();
        group.add_member(peer);

        db.create_group(&group).unwrap();
        assert!(db.remove_group_member(&group.id, &peer).unwrap());

        let loaded = db.get_group(&group.id).unwrap().unwrap();
        assert!(loaded.members.is_empty());
    }

    #[test]
    fn group_members_persist() {
        let db = Database::open_in_memory().unwrap();
        let mut group = Group::new("Team".to_string(), vec![]);
        let peer1 = make_peer_id();
        let peer2 = make_peer_id();
        group.add_member(peer1);
        group.add_member(peer2);

        db.create_group(&group).unwrap();

        let loaded = db.get_group(&group.id).unwrap().unwrap();
        assert_eq!(loaded.members.len(), 2);
    }

    // === Pending Queue Tests ===

    #[test]
    fn queue_pending_message() {
        let db = Database::open_in_memory().unwrap();
        let peer = make_peer_id();
        let id = Uuid::new_v4();

        db.queue_pending_message(&id, &peer, b"encrypted data").unwrap();

        let pending = db.get_pending_for_peer(&peer).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, id);
        assert_eq!(pending[0].1, b"encrypted data");
    }

    #[test]
    fn get_all_pending() {
        let db = Database::open_in_memory().unwrap();
        let peer1 = make_peer_id();
        let peer2 = make_peer_id();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        db.queue_pending_message(&id1, &peer1, b"msg1").unwrap();
        db.queue_pending_message(&id2, &peer2, b"msg2").unwrap();

        let all = db.get_all_pending().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn remove_pending_message() {
        let db = Database::open_in_memory().unwrap();
        let peer = make_peer_id();
        let id = Uuid::new_v4();

        db.queue_pending_message(&id, &peer, b"data").unwrap();
        assert!(db.remove_pending_message(&id).unwrap());
        
        let pending = db.get_pending_for_peer(&peer).unwrap();
        assert!(pending.is_empty());
    }

    #[test]
    fn pending_survives_reopen() {
        use tempfile::tempdir;
        
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.db");
        let peer = make_peer_id();
        let id = Uuid::new_v4();

        // Queue and close
        {
            let db = Database::open(&path, "").unwrap();
            db.queue_pending_message(&id, &peer, b"persist me").unwrap();
        }

        // Reopen and verify
        {
            let db = Database::open(&path, "").unwrap();
            let pending = db.get_all_pending().unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].2, b"persist me");
        }
    }

    // File transfer tests

    #[test]
    fn insert_and_get_file_transfer() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        let data = vec![0u8; 1000];
        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "test.txt".to_string(),
            &data,
        );

        db.insert_file_transfer(&transfer).unwrap();

        let loaded = db.get_file_transfer(&transfer.id).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.filename, "test.txt");
        assert_eq!(loaded.total_size, 1000);
    }

    #[test]
    fn update_file_transfer_status() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        let data = vec![0u8; 500];
        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "update.txt".to_string(),
            &data,
        );

        db.insert_file_transfer(&transfer).unwrap();
        
        // Update status
        db.update_file_transfer(&transfer.id, 1, &FileTransferStatus::Complete).unwrap();

        let loaded = db.get_file_transfer(&transfer.id).unwrap().unwrap();
        assert_eq!(loaded.status, FileTransferStatus::Complete);
        assert_eq!(loaded.chunks_received, 1);
    }

    #[test]
    fn list_file_transfers() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        // Create multiple transfers
        for i in 0..3 {
            let transfer = FileTransfer::new_outgoing(
                from,
                Recipient::Direct(to),
                format!("file{}.txt", i),
                &vec![0u8; 100],
            );
            db.insert_file_transfer(&transfer).unwrap();
        }

        let all = db.list_file_transfers(None).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn list_file_transfers_by_status() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        // Create pending transfer
        let pending = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "pending.txt".to_string(),
            &vec![0u8; 100],
        );
        db.insert_file_transfer(&pending).unwrap();

        // Create and complete another transfer
        let complete = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "complete.txt".to_string(),
            &vec![0u8; 100],
        );
        db.insert_file_transfer(&complete).unwrap();
        db.update_file_transfer(&complete.id, 1, &FileTransferStatus::Complete).unwrap();

        // Filter by pending
        let pending_only = db.list_file_transfers(Some(&FileTransferStatus::Pending)).unwrap();
        assert_eq!(pending_only.len(), 1);
        assert_eq!(pending_only[0].filename, "pending.txt");

        // Filter by complete
        let complete_only = db.list_file_transfers(Some(&FileTransferStatus::Complete)).unwrap();
        assert_eq!(complete_only.len(), 1);
        assert_eq!(complete_only[0].filename, "complete.txt");
    }

    #[test]
    fn insert_and_get_file_chunk() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        // Create parent transfer first
        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "chunk_test.txt".to_string(),
            &vec![1, 2, 3, 4, 5],
        );
        db.insert_file_transfer(&transfer).unwrap();

        let chunk = FileChunk::new(transfer.id, 0, 1, vec![1, 2, 3, 4, 5]);
        db.insert_file_chunk(&chunk).unwrap();

        let loaded = db.get_file_chunk(&transfer.id, 0).unwrap();
        assert!(loaded.is_some());
        let loaded = loaded.unwrap();
        assert_eq!(loaded.data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn get_all_file_chunks() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        // Create parent transfer
        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "multi_chunk.txt".to_string(),
            &vec![0u8; 30],
        );
        db.insert_file_transfer(&transfer).unwrap();

        // Insert 3 chunks
        for i in 0..3 {
            let chunk = FileChunk::new(transfer.id, i, 3, vec![i as u8; 10]);
            db.insert_file_chunk(&chunk).unwrap();
        }

        let chunks = db.get_file_chunks(&transfer.id).unwrap();
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[1].chunk_index, 1);
        assert_eq!(chunks[2].chunk_index, 2);
    }

    #[test]
    fn reassemble_file_from_chunks() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        // Original data
        let original = b"Hello, World! This is a test file.";
        
        // Create parent transfer
        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "reassemble.txt".to_string(),
            original,
        );
        db.insert_file_transfer(&transfer).unwrap();

        // Split into chunks
        let chunk1 = FileChunk::new(transfer.id, 0, 2, original[..17].to_vec());
        let chunk2 = FileChunk::new(transfer.id, 1, 2, original[17..].to_vec());

        db.insert_file_chunk(&chunk1).unwrap();
        db.insert_file_chunk(&chunk2).unwrap();

        let reassembled = db.reassemble_file(&transfer.id).unwrap();
        assert_eq!(reassembled, original);
    }

    #[test]
    fn delete_file_transfer() {
        let db = Database::open_in_memory().unwrap();
        let from = make_peer_id();
        let to = make_peer_id();

        let transfer = FileTransfer::new_outgoing(
            from,
            Recipient::Direct(to),
            "delete_me.txt".to_string(),
            &vec![0u8; 100],
        );
        db.insert_file_transfer(&transfer).unwrap();

        // Add some chunks
        let chunk = FileChunk::new(transfer.id, 0, 1, vec![1, 2, 3]);
        db.insert_file_chunk(&chunk).unwrap();

        // Delete
        assert!(db.delete_file_transfer(&transfer.id).unwrap());

        // Verify gone
        assert!(db.get_file_transfer(&transfer.id).unwrap().is_none());
    }
}
