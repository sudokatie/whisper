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
#[derive(Debug, Clone)]
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

    /// Update last seen timestamp for a contact.
    pub fn update_last_seen(&mut self, peer_id: &PeerId) -> bool {
        if let Some(contact) = self.contacts.get_mut(peer_id) {
            contact.last_seen = Some(Utc::now());
            true
        } else {
            false
        }
    }

    /// Check if a contact is blocked.
    pub fn is_blocked(&self, peer_id: &PeerId) -> bool {
        self.contacts
            .get(peer_id)
            .map_or(false, |c| c.trust_level == TrustLevel::Blocked)
    }

    /// Get count of contacts.
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Check if store is empty.
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }
}

impl Contact {
    /// Create a new contact.
    pub fn new(peer_id: PeerId, alias: String, public_key: Vec<u8>) -> Self {
        Self {
            peer_id,
            alias,
            public_key,
            trust_level: TrustLevel::Unknown,
            last_seen: None,
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

    fn make_contact(alias: &str) -> Contact {
        Contact::new(make_peer_id(), alias.to_string(), vec![1, 2, 3])
    }

    #[test]
    fn add_contact_works() {
        let mut store = ContactStore::new();
        let contact = make_contact("alice");
        assert!(store.add_contact(contact).is_ok());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn add_duplicate_alias_fails() {
        let mut store = ContactStore::new();
        let peer1 = make_peer_id();
        let peer2 = make_peer_id();

        let c1 = Contact::new(peer1, "alice".to_string(), vec![]);
        let c2 = Contact::new(peer2, "alice".to_string(), vec![]);

        assert!(store.add_contact(c1).is_ok());
        assert!(store.add_contact(c2).is_err());
    }

    #[test]
    fn remove_contact_works() {
        let mut store = ContactStore::new();
        let contact = make_contact("alice");
        let peer_id = contact.peer_id;

        store.add_contact(contact).unwrap();
        let removed = store.remove_contact(&peer_id);
        assert!(removed.is_some());
        assert!(store.is_empty());
    }

    #[test]
    fn get_by_peer_id_works() {
        let mut store = ContactStore::new();
        let contact = make_contact("alice");
        let peer_id = contact.peer_id;

        store.add_contact(contact).unwrap();
        assert!(store.get_by_peer_id(&peer_id).is_some());
    }

    #[test]
    fn get_by_alias_works() {
        let mut store = ContactStore::new();
        store.add_contact(make_contact("alice")).unwrap();
        assert!(store.get_by_alias("alice").is_some());
        assert!(store.get_by_alias("bob").is_none());
    }

    #[test]
    fn list_contacts_returns_all() {
        let mut store = ContactStore::new();
        store.add_contact(make_contact("alice")).unwrap();
        store.add_contact(make_contact("bob")).unwrap();
        assert_eq!(store.list_contacts().len(), 2);
    }

    #[test]
    fn set_trust_level_works() {
        let mut store = ContactStore::new();
        let contact = make_contact("alice");
        let peer_id = contact.peer_id;

        store.add_contact(contact).unwrap();
        assert!(store.set_trust_level(&peer_id, TrustLevel::Trusted));

        let c = store.get_by_peer_id(&peer_id).unwrap();
        assert_eq!(c.trust_level, TrustLevel::Trusted);
    }

    #[test]
    fn is_blocked_works() {
        let mut store = ContactStore::new();
        let contact = make_contact("alice");
        let peer_id = contact.peer_id;

        store.add_contact(contact).unwrap();
        assert!(!store.is_blocked(&peer_id));

        store.set_trust_level(&peer_id, TrustLevel::Blocked);
        assert!(store.is_blocked(&peer_id));
    }

    #[test]
    fn update_last_seen_works() {
        let mut store = ContactStore::new();
        let contact = make_contact("alice");
        let peer_id = contact.peer_id;

        store.add_contact(contact).unwrap();
        assert!(store.get_by_peer_id(&peer_id).unwrap().last_seen.is_none());

        store.update_last_seen(&peer_id);
        assert!(store.get_by_peer_id(&peer_id).unwrap().last_seen.is_some());
    }

    #[test]
    fn remove_clears_alias() {
        let mut store = ContactStore::new();
        let contact = make_contact("alice");
        let peer_id = contact.peer_id;

        store.add_contact(contact).unwrap();
        store.remove_contact(&peer_id);

        // Should be able to add new contact with same alias
        store.add_contact(make_contact("alice")).unwrap();
    }
}
