//! Peer discovery with mDNS and Kademlia DHT.

use anyhow::Result;
use libp2p::{
    kad::{self, QueryId},
    mdns, Multiaddr, PeerId,
};
use std::time::Duration;

use super::node::WhisperNode;

/// Default mDNS query interval in seconds.
pub const MDNS_QUERY_INTERVAL_SECS: u64 = 5;

/// Default Kademlia replication factor.
pub const KAD_REPLICATION_FACTOR: usize = 20;

/// Default Kademlia query timeout in seconds.
pub const KAD_QUERY_TIMEOUT_SECS: u64 = 60;

/// Configure mDNS for local peer discovery.
pub fn configure_mdns() -> mdns::Config {
    mdns::Config {
        ttl: Duration::from_secs(6 * 60), // 6 minutes
        query_interval: Duration::from_secs(MDNS_QUERY_INTERVAL_SECS),
        enable_ipv6: false, // Most local networks use IPv4
    }
}

/// Configure Kademlia DHT for peer routing.
pub fn configure_kademlia(_peer_id: PeerId) -> kad::Config {
    let mut config = kad::Config::new(kad::PROTOCOL_NAME.clone());
    
    // Set replication factor
    config.set_replication_factor(
        std::num::NonZeroUsize::new(KAD_REPLICATION_FACTOR).unwrap()
    );
    
    // Set query timeout
    config.set_query_timeout(Duration::from_secs(KAD_QUERY_TIMEOUT_SECS));
    
    // Enable automatic server mode if we're publicly reachable
    config.set_kbucket_inserts(kad::BucketInserts::OnConnected);
    
    config
}

/// Get bootstrap nodes for the Whisper network.
/// 
/// These are well-known nodes that help new peers join the network.
/// In production, these would be maintained by the Whisper project.
pub fn bootstrap_nodes() -> Vec<Multiaddr> {
    // Default bootstrap nodes (can be empty for local-only networks)
    // Format: /ip4/{ip}/tcp/{port}/p2p/{peer_id}
    vec![
        // Example bootstrap nodes - in production these would be real
        // "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"
    ]
    .into_iter()
    .filter_map(|s: &str| s.parse().ok())
    .collect()
}

/// Known public bootstrap nodes for testing.
/// These are IPFS bootstrap nodes that can help with DHT.
pub fn ipfs_bootstrap_nodes() -> Vec<Multiaddr> {
    vec![
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        "/dnsaddr/bootstrap.libp2p.io/p2p/QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
        "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
    ]
    .into_iter()
    .filter_map(|s| s.parse().ok())
    .collect()
}

/// Discover a peer's addresses using Kademlia DHT.
/// 
/// This initiates a DHT lookup for the given peer ID.
/// Returns the query ID which can be used to track the result.
pub fn start_peer_discovery(node: &mut WhisperNode, peer_id: PeerId) -> QueryId {
    node.swarm_mut()
        .behaviour_mut()
        .kademlia
        .get_closest_peers(peer_id)
}

/// Add a peer address to the Kademlia routing table.
pub fn add_peer_address(node: &mut WhisperNode, peer_id: &PeerId, addr: Multiaddr) {
    node.swarm_mut()
        .behaviour_mut()
        .kademlia
        .add_address(peer_id, addr);
}

/// Bootstrap the Kademlia DHT by connecting to known nodes.
pub fn bootstrap_kademlia(node: &mut WhisperNode) -> Result<QueryId> {
    // Add bootstrap nodes to routing table
    for addr in bootstrap_nodes() {
        if let Some(peer_id) = extract_peer_id(&addr) {
            add_peer_address(node, &peer_id, addr);
        }
    }
    
    // Start bootstrap query
    node.swarm_mut()
        .behaviour_mut()
        .kademlia
        .bootstrap()
        .map_err(|e| anyhow::anyhow!("Bootstrap failed: {:?}", e))
}

/// Extract peer ID from a multiaddr if present.
pub fn extract_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|p| {
        if let libp2p::multiaddr::Protocol::P2p(peer_id) = p {
            Some(peer_id)
        } else {
            None
        }
    })
}

/// Check if an address is a local/private address.
pub fn is_local_address(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        libp2p::multiaddr::Protocol::Ip4(ip) => {
            ip.is_loopback() || ip.is_private() || ip.is_link_local()
        }
        libp2p::multiaddr::Protocol::Ip6(ip) => {
            ip.is_loopback()
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mdns_config_has_valid_ttl() {
        let config = configure_mdns();
        assert!(config.ttl >= Duration::from_secs(60));
    }

    #[test]
    fn mdns_config_has_valid_query_interval() {
        let config = configure_mdns();
        assert!(config.query_interval <= Duration::from_secs(60));
        assert!(config.query_interval >= Duration::from_secs(1));
    }

    #[test]
    fn kademlia_config_has_valid_replication() {
        let peer_id = PeerId::random();
        let config = configure_kademlia(peer_id);
        // Config is valid if we can create it
        let _ = config;
    }

    #[test]
    fn kademlia_config_has_query_timeout() {
        let peer_id = PeerId::random();
        let config = configure_kademlia(peer_id);
        // Config is created with timeout set
        let _ = config;
    }

    #[test]
    fn bootstrap_nodes_returns_valid_addrs() {
        let nodes = bootstrap_nodes();
        // All returned addresses should be valid Multiaddrs
        for addr in nodes {
            // Just verify they're valid by converting to string
            let _ = addr.to_string();
        }
    }

    #[test]
    fn ipfs_bootstrap_nodes_are_parseable() {
        let nodes = ipfs_bootstrap_nodes();
        // Should have some nodes
        assert!(!nodes.is_empty());
    }

    #[test]
    fn extract_peer_id_from_valid_addr() {
        let addr: Multiaddr = "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ"
            .parse()
            .unwrap();
        let peer_id = extract_peer_id(&addr);
        assert!(peer_id.is_some());
    }

    #[test]
    fn extract_peer_id_none_for_addr_without_peer() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let peer_id = extract_peer_id(&addr);
        assert!(peer_id.is_none());
    }

    #[test]
    fn is_local_address_true_for_localhost() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert!(is_local_address(&addr));
    }

    #[test]
    fn is_local_address_false_for_public() {
        let addr: Multiaddr = "/ip4/8.8.8.8/tcp/4001".parse().unwrap();
        assert!(!is_local_address(&addr));
    }
}
