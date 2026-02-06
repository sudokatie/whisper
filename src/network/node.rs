//! Main P2P node.

use libp2p::PeerId;

/// The main whisper network node.
pub struct WhisperNode {
    peer_id: PeerId,
}

impl WhisperNode {
    /// Get this node's peer ID.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }
}
