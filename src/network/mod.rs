//! P2P networking with libp2p.

mod behaviour;
mod discovery;
mod node;
mod relay;

pub use behaviour::{
    MessageCodec, MessageRequest, MessageResponse, WhisperBehaviour, WhisperEvent,
    WHISPER_PROTOCOL,
};
pub use discovery::{
    add_peer_address, bootstrap_kademlia, bootstrap_nodes, configure_kademlia, configure_mdns,
    extract_peer_id, ipfs_bootstrap_nodes, is_local_address, start_peer_discovery,
    KAD_QUERY_TIMEOUT_SECS, KAD_REPLICATION_FACTOR, MDNS_QUERY_INTERVAL_SECS,
};
pub use node::{NodeEvent, WhisperNode};
pub use relay::{
    connect_to_relay, is_behind_nat, is_relay_address, make_relay_address, public_relays,
    RELAY_CONNECT_TIMEOUT_SECS,
};
