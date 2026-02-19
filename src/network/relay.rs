//! NAT traversal with relay nodes.

use anyhow::Result;
use libp2p::{Multiaddr, PeerId};
use std::net::UdpSocket;

use super::discovery::extract_peer_id;
use super::node::WhisperNode;

/// Default relay connection timeout in seconds.
pub const RELAY_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Connect to a relay server for NAT traversal.
/// 
/// The relay address should include the peer ID of the relay.
/// Example: /ip4/1.2.3.4/tcp/4001/p2p/12D3KooW...
pub fn connect_to_relay(node: &mut WhisperNode, relay_addr: Multiaddr) -> Result<()> {
    // Extract peer ID from the relay address
    let relay_peer_id = extract_peer_id(&relay_addr)
        .ok_or_else(|| anyhow::anyhow!("Relay address must include peer ID"))?;
    
    // Add the relay to Kademlia for routing
    node.swarm_mut()
        .behaviour_mut()
        .kademlia
        .add_address(&relay_peer_id, relay_addr.clone());
    
    // Dial the relay
    node.dial(relay_addr)?;
    
    Ok(())
}

/// Check if we're likely behind NAT.
/// 
/// This performs a simple check by attempting to bind to a public-facing socket.
/// Not 100% reliable but provides a good heuristic.
pub fn is_behind_nat() -> bool {
    // Try to determine our external IP by connecting to a known server
    // If our local IP differs from what external services see, we're behind NAT
    
    // Simple heuristic: if we only have private IPs, assume NAT
    match get_local_ip() {
        Some(ip) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local()
        }
        None => true, // Assume NAT if we can't determine
    }
}

/// Get the local IP address by creating a UDP socket.
fn get_local_ip() -> Option<std::net::Ipv4Addr> {
    // Create a UDP socket and connect to a public DNS server
    // This doesn't actually send any data, just determines the route
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
        std::net::SocketAddr::V6(_) => None,
    }
}

/// Known public relay nodes for the Whisper network.
pub fn public_relays() -> Vec<Multiaddr> {
    // In production, these would be maintained relay nodes
    vec![]
}

/// Create a relay listening address.
/// 
/// This creates an address that tells other peers to reach us through a relay.
/// Format: /p2p/{relay_peer_id}/p2p-circuit/p2p/{our_peer_id}
pub fn make_relay_address(relay_peer_id: PeerId, our_peer_id: PeerId) -> Multiaddr {
    format!("/p2p/{}/p2p-circuit/p2p/{}", relay_peer_id, our_peer_id)
        .parse()
        .expect("Valid relay address format")
}

/// Check if an address is a relay circuit address.
pub fn is_relay_address(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, libp2p::multiaddr::Protocol::P2pCircuit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_behind_nat_returns_bool() {
        // Just verify the function runs without panicking
        let _result = is_behind_nat();
        // Function compiles and returns a bool, that's the test
    }

    #[test]
    fn public_relays_returns_vec() {
        let relays = public_relays();
        // Should return a valid (possibly empty) vector
        for addr in relays {
            let _ = addr.to_string();
        }
    }

    #[test]
    fn make_relay_address_creates_valid_addr() {
        let relay_peer = PeerId::random();
        let our_peer = PeerId::random();
        
        let addr = make_relay_address(relay_peer, our_peer);
        
        // Should contain both peer IDs
        let addr_str = addr.to_string();
        assert!(addr_str.contains(&relay_peer.to_string()));
        assert!(addr_str.contains(&our_peer.to_string()));
        assert!(addr_str.contains("p2p-circuit"));
    }

    #[test]
    fn is_relay_address_true_for_circuit() {
        let relay_peer = PeerId::random();
        let our_peer = PeerId::random();
        let addr = make_relay_address(relay_peer, our_peer);
        
        assert!(is_relay_address(&addr));
    }

    #[test]
    fn is_relay_address_false_for_direct() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        assert!(!is_relay_address(&addr));
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn relay_timeout_is_reasonable() {
        // These assertions document the expected bounds on the constant
        assert!(RELAY_CONNECT_TIMEOUT_SECS >= 10);
        assert!(RELAY_CONNECT_TIMEOUT_SECS <= 120);
    }
}
