//! Contact management.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

/// Trust level for a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    Unknown,
    Verified,
    Trusted,
    Blocked,
}

/// A contact in the address book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub peer_id: PeerId,
    pub alias: String,
    pub public_key: Vec<u8>,
    pub trust_level: TrustLevel,
    pub last_seen: Option<DateTime<Utc>>,
}

/// Contact storage.
#[derive(Debug, Default)]
pub struct ContactStore {
    contacts: HashMap<PeerId, Contact>,
    aliases: HashMap<String, PeerId>,
}

impl ContactStore {
    /// Create a new empty contact store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a contact.
    pub fn add_contact(&mut self, contact: Contact) -> Result<(), &'static str> {
        if self.aliases.contains_key(&contact.alias) {
            return Err("Alias already exists");
        }
        self.aliases.insert(contact.alias.clone(), contact.peer_id);
        self.contacts.insert(contact.peer_id, contact);
        Ok(())
    }

    /// Remove a contact by peer ID.
    pub fn remove_contact(&mut self, peer_id: &PeerId) -> Option<Contact> {
        if let Some(contact) = self.contacts.remove(peer_id) {
            self.aliases.remove(&contact.alias);
            Some(contact)
        } else {
            None
        }
    }

    /// Get a contact by peer ID.
    pub fn get_by_peer_id(&self, peer_id: &PeerId) -> Option<&Contact> {
        self.contacts.get(peer_id)
    }

    /// Get a contact by alias.
    pub fn get_by_alias(&self, alias: &str) -> Option<&Contact> {
        self.aliases.get(alias).and_then(|id| self.contacts.get(id))
    }

    /// List all contacts.
    pub fn list_contacts(&self) -> Vec<&Contact> {
        self.contacts.values().collect()
    }

    /// Set trust level for a contact.
    pub fn set_trust_level(&mut self, peer_id: &PeerId, level: TrustLevel) -> bool {
        if let Some(contact) = self.contacts.get_mut(peer_id) {
            contact.trust_level = level;
            true
        } else {
            false
        }
    }
}
