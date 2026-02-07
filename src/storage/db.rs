//! Database operations.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{TimeZone, Utc};
use libp2p::PeerId;
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::identity::{Contact, TrustLevel};
use crate::message::{Group, Message, MessageContent, MessageStatus, Recipient};

/// SQLite database wrapper.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create database at path.
    pub fn open(path: &Path) -> Result<Self> {
        // Create parent directories if needed
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Open an in-memory database (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
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
}

struct MessageRow {
    id: String,
    from_peer: String,
    to_peer: String,
    content: Vec<u8>,
    timestamp: i64,
    status: String,
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
        let mut group = Group::new("Team".to_string(), vec![]);
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
}
