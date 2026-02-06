//! Identity management - keypairs and contacts.

mod contacts;
mod keypair;

pub use contacts::{Contact, ContactStore, TrustLevel};
pub use keypair::{
    export_public_key, generate_keypair, import_public_key, keypair_to_peer_id, load_keypair,
    save_keypair,
};
