//! Main P2P node.

use anyhow::Result;
use libp2p::{
    identity::Keypair,
    mdns, noise, request_response,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::collections::HashSet;
use tokio::sync::mpsc;

use super::behaviour::{MessageRequest, MessageResponse, WhisperBehaviour, WhisperBehaviourEvent};

/// Events emitted by the network node.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A peer connected.
    PeerConnected(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// A message was received from a peer.
    MessageReceived { from: PeerId, data: Vec<u8> },
    /// A message was sent successfully.
    MessageSent { to: PeerId },
    /// Listening on an address.
    Listening(Multiaddr),
}

/// The main Whisper network node.
pub struct WhisperNode {
    /// libp2p swarm.
    swarm: Swarm<WhisperBehaviour>,
    /// Our peer ID.
    peer_id: PeerId,
    /// Connected peers.
    connected_peers: HashSet<PeerId>,
    /// Pending message sends.
    pending_sends: Vec<(PeerId, Vec<u8>)>,
}

impl WhisperNode {
    /// Create a new WhisperNode with the given keypair.
    pub async fn new(keypair: Keypair) -> Result<Self> {
        let peer_id = PeerId::from(keypair.public());

        // Build the swarm
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|keypair, relay_client| {
                WhisperBehaviour::new(PeerId::from(keypair.public()), relay_client)
            })?
            .build();

        Ok(Self {
            swarm,
            peer_id,
            connected_peers: HashSet::new(),
            pending_sends: Vec::new(),
        })
    }

    /// Get this node's peer ID.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Get list of connected peers.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.connected_peers.iter().cloned().collect()
    }

    /// Check if connected to a specific peer.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.connected_peers.contains(peer_id)
    }

    /// Listen on an address.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.listen_on(addr)?;
        Ok(())
    }

    /// Dial a peer at a specific address.
    pub fn dial(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm.dial(addr)?;
        Ok(())
    }

    /// Queue a message to send to a peer.
    pub fn send_message(&mut self, peer_id: PeerId, data: Vec<u8>) {
        if self.connected_peers.contains(&peer_id) {
            // Send immediately using request-response
            self.swarm
                .behaviour_mut()
                .request_response
                .send_request(&peer_id, MessageRequest(data));
        } else {
            // Queue for later
            self.pending_sends.push((peer_id, data));
        }
    }

    /// Flush pending messages for a newly connected peer.
    /// Called when peer connects (in event loop, not yet implemented).
    #[allow(dead_code)]
    fn flush_pending(&mut self, peer_id: &PeerId) {
        let to_send: Vec<_> = self
            .pending_sends
            .iter()
            .filter(|(p, _)| p == peer_id)
            .cloned()
            .collect();

        for (_, data) in to_send {
            self.swarm
                .behaviour_mut()
                .request_response
                .send_request(peer_id, MessageRequest(data));
        }

        self.pending_sends.retain(|(p, _)| p != peer_id);
    }

    /// Get number of pending messages.
    pub fn pending_count(&self) -> usize {
        self.pending_sends.len()
    }

    /// Add a peer to the Kademlia DHT.
    pub fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(peer_id, addr);
    }

    /// Get the swarm for advanced operations.
    pub fn swarm(&self) -> &Swarm<WhisperBehaviour> {
        &self.swarm
    }

    /// Get mutable swarm for advanced operations.
    pub fn swarm_mut(&mut self) -> &mut Swarm<WhisperBehaviour> {
        &mut self.swarm
    }

    /// Mark a peer as connected.
    pub fn add_connected_peer(&mut self, peer_id: PeerId) {
        self.connected_peers.insert(peer_id);
        self.flush_pending(&peer_id);
    }

    /// Mark a peer as disconnected.
    pub fn remove_connected_peer(&mut self, peer_id: &PeerId) {
        self.connected_peers.remove(peer_id);
    }

    /// Poll the swarm for events and return any node events.
    /// This should be called in a loop from the main event handler.
    pub async fn poll_event(&mut self) -> Option<NodeEvent> {
        use futures::StreamExt;

        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    return Some(NodeEvent::Listening(address));
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    self.add_connected_peer(peer_id);
                    return Some(NodeEvent::PeerConnected(peer_id));
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    self.remove_connected_peer(&peer_id);
                    return Some(NodeEvent::PeerDisconnected(peer_id));
                }
                SwarmEvent::Behaviour(event) => {
                    if let Some(node_event) = self.handle_behaviour_event(event) {
                        return Some(node_event);
                    }
                }
                _ => {}
            }
        }
    }

    /// Handle a behaviour event and return any resulting node event.
    fn handle_behaviour_event(&mut self, event: WhisperBehaviourEvent) -> Option<NodeEvent> {
        match event {
            WhisperBehaviourEvent::Mdns(mdns::Event::Discovered(peers)) => {
                for (peer_id, addr) in peers {
                    // Add discovered peer to Kademlia
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    // Try to dial them
                    let _ = self.swarm.dial(addr);
                }
                None
            }
            WhisperBehaviourEvent::Mdns(mdns::Event::Expired(peers)) => {
                for (peer_id, _) in peers {
                    self.remove_connected_peer(&peer_id);
                }
                None
            }
            WhisperBehaviourEvent::RequestResponse(request_response::Event::Message {
                peer,
                message,
            }) => {
                match message {
                    request_response::Message::Request { request, channel, .. } => {
                        // Received a message - send acknowledgment
                        let _ = self.swarm
                            .behaviour_mut()
                            .request_response
                            .send_response(channel, MessageResponse(true));
                        Some(NodeEvent::MessageReceived {
                            from: peer,
                            data: request.0,
                        })
                    }
                    request_response::Message::Response { .. } => {
                        Some(NodeEvent::MessageSent { to: peer })
                    }
                }
            }
            _ => None,
        }
    }

    /// Start listening on the default address and return the channel for events.
    #[allow(dead_code)]
    pub async fn start(&mut self) -> Result<mpsc::Receiver<NodeEvent>> {
        // Listen on all interfaces
        let addr: Multiaddr = "/ip4/0.0.0.0/tcp/0".parse()?;
        self.listen_on(addr)?;

        // Create event channel (tx would be used in a spawned event loop)
        let (_tx, rx) = mpsc::channel(100);

        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_keypair() -> Keypair {
        Keypair::generate_ed25519()
    }

    #[tokio::test]
    async fn node_creation_succeeds() {
        let keypair = generate_keypair();
        let node = WhisperNode::new(keypair).await;
        assert!(node.is_ok());
    }

    #[tokio::test]
    async fn peer_id_matches_keypair() {
        let keypair = generate_keypair();
        let expected_peer_id = PeerId::from(keypair.public());
        let node = WhisperNode::new(keypair).await.unwrap();
        assert_eq!(node.peer_id(), expected_peer_id);
    }

    #[tokio::test]
    async fn initially_no_connected_peers() {
        let keypair = generate_keypair();
        let node = WhisperNode::new(keypair).await.unwrap();
        assert!(node.connected_peers().is_empty());
    }

    #[tokio::test]
    async fn is_connected_false_for_unknown_peer() {
        let keypair = generate_keypair();
        let node = WhisperNode::new(keypair).await.unwrap();
        let random_peer = PeerId::random();
        assert!(!node.is_connected(&random_peer));
    }

    #[tokio::test]
    async fn send_message_queues_when_not_connected() {
        let keypair = generate_keypair();
        let mut node = WhisperNode::new(keypair).await.unwrap();
        let peer = PeerId::random();
        
        node.send_message(peer, vec![1, 2, 3]);
        
        assert_eq!(node.pending_count(), 1);
    }

    #[tokio::test]
    async fn pending_count_initially_zero() {
        let keypair = generate_keypair();
        let node = WhisperNode::new(keypair).await.unwrap();
        assert_eq!(node.pending_count(), 0);
    }

    #[tokio::test]
    async fn multiple_sends_queue() {
        let keypair = generate_keypair();
        let mut node = WhisperNode::new(keypair).await.unwrap();
        let peer = PeerId::random();
        
        node.send_message(peer, vec![1]);
        node.send_message(peer, vec![2]);
        node.send_message(peer, vec![3]);
        
        assert_eq!(node.pending_count(), 3);
    }

    #[tokio::test]
    async fn different_peers_queue_separately() {
        let keypair = generate_keypair();
        let mut node = WhisperNode::new(keypair).await.unwrap();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        
        node.send_message(peer1, vec![1]);
        node.send_message(peer2, vec![2]);
        
        assert_eq!(node.pending_count(), 2);
    }

    #[tokio::test]
    async fn listen_on_valid_address() {
        let keypair = generate_keypair();
        let mut node = WhisperNode::new(keypair).await.unwrap();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        
        let result = node.listen_on(addr);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn swarm_accessible() {
        let keypair = generate_keypair();
        let node = WhisperNode::new(keypair).await.unwrap();
        let _ = node.swarm();
    }

    #[tokio::test]
    async fn swarm_mut_accessible() {
        let keypair = generate_keypair();
        let mut node = WhisperNode::new(keypair).await.unwrap();
        let _ = node.swarm_mut();
    }
}
