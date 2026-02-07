//! Combined libp2p network behaviour.

use libp2p::{
    kad::{self, store::MemoryStore},
    mdns,
    relay,
    request_response::{self, ProtocolSupport},
    swarm::NetworkBehaviour,
    PeerId, StreamProtocol,
};
use std::iter;

/// Protocol name for Whisper messages.
pub const WHISPER_PROTOCOL: &str = "/whisper/1.0.0";

/// Message codec for request-response.
#[derive(Debug, Clone, Default)]
pub struct MessageCodec;

/// Request type - encrypted message bytes.
#[derive(Debug, Clone)]
pub struct MessageRequest(pub Vec<u8>);

/// Response type - delivery receipt.
#[derive(Debug, Clone)]
pub struct MessageResponse(pub bool);

impl request_response::Codec for MessageCodec {
    type Protocol = StreamProtocol;
    type Request = MessageRequest;
    type Response = MessageResponse;

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Self::Request>> + Send + 'async_trait>>
    where
        T: futures::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut buf = Vec::new();
            futures::AsyncReadExt::read_to_end(io, &mut buf).await?;
            Ok(MessageRequest(buf))
        })
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<Self::Response>> + Send + 'async_trait>>
    where
        T: futures::AsyncRead + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let mut buf = [0u8; 1];
            futures::AsyncReadExt::read_exact(io, &mut buf).await?;
            Ok(MessageResponse(buf[0] == 1))
        })
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        req: Self::Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'async_trait>>
    where
        T: futures::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            futures::AsyncWriteExt::write_all(io, &req.0).await?;
            futures::AsyncWriteExt::close(io).await?;
            Ok(())
        })
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        res: Self::Response,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'async_trait>>
    where
        T: futures::AsyncWrite + Unpin + Send + 'async_trait,
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            futures::AsyncWriteExt::write_all(io, &[if res.0 { 1 } else { 0 }]).await?;
            futures::AsyncWriteExt::close(io).await?;
            Ok(())
        })
    }
}

/// Combined network behaviour for Whisper.
#[derive(NetworkBehaviour)]
pub struct WhisperBehaviour {
    /// mDNS for local peer discovery.
    pub mdns: mdns::tokio::Behaviour,
    /// Kademlia DHT for peer routing.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// Request-response for message exchange.
    pub request_response: request_response::Behaviour<MessageCodec>,
    /// Relay client for NAT traversal.
    pub relay_client: relay::client::Behaviour,
}

impl WhisperBehaviour {
    /// Create a new WhisperBehaviour.
    pub fn new(
        local_peer_id: PeerId,
        relay_client: relay::client::Behaviour,
    ) -> Self {
        // mDNS config
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        ).expect("mDNS should initialize");

        // Kademlia config
        let store = MemoryStore::new(local_peer_id);
        let kademlia = kad::Behaviour::new(local_peer_id, store);

        // Request-response config
        let protocol = StreamProtocol::new(WHISPER_PROTOCOL);
        let request_response = request_response::Behaviour::new(
            iter::once((protocol, ProtocolSupport::Full)),
            request_response::Config::default(),
        );

        Self {
            mdns,
            kademlia,
            request_response,
            relay_client,
        }
    }
}

/// Events emitted by WhisperBehaviour.
#[derive(Debug)]
pub enum WhisperEvent {
    /// A peer was discovered via mDNS.
    PeerDiscovered(PeerId),
    /// A peer expired from mDNS.
    PeerExpired(PeerId),
    /// A message was received.
    MessageReceived {
        peer: PeerId,
        data: Vec<u8>,
    },
    /// A message was sent successfully.
    MessageSent {
        peer: PeerId,
    },
    /// A message send failed.
    MessageFailed {
        peer: PeerId,
        error: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_request_holds_data() {
        let data = vec![1, 2, 3, 4, 5];
        let req = MessageRequest(data.clone());
        assert_eq!(req.0, data);
    }

    #[test]
    fn message_request_empty() {
        let req = MessageRequest(vec![]);
        assert!(req.0.is_empty());
    }

    #[test]
    fn message_response_holds_bool() {
        let res_ok = MessageResponse(true);
        let res_fail = MessageResponse(false);
        assert!(res_ok.0);
        assert!(!res_fail.0);
    }

    #[test]
    fn whisper_event_peer_discovered() {
        let peer = PeerId::random();
        let discovered = WhisperEvent::PeerDiscovered(peer);
        assert!(matches!(discovered, WhisperEvent::PeerDiscovered(p) if p == peer));
    }

    #[test]
    fn whisper_event_peer_expired() {
        let peer = PeerId::random();
        let expired = WhisperEvent::PeerExpired(peer);
        assert!(matches!(expired, WhisperEvent::PeerExpired(p) if p == peer));
    }

    #[test]
    fn whisper_event_message_received() {
        let peer = PeerId::random();
        let data = vec![1, 2, 3];
        let received = WhisperEvent::MessageReceived {
            peer,
            data: data.clone(),
        };
        match received {
            WhisperEvent::MessageReceived { peer: p, data: d } => {
                assert_eq!(p, peer);
                assert_eq!(d, data);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn whisper_event_message_failed() {
        let peer = PeerId::random();
        let failed = WhisperEvent::MessageFailed {
            peer,
            error: "timeout".to_string(),
        };
        match failed {
            WhisperEvent::MessageFailed { peer: p, error: e } => {
                assert_eq!(p, peer);
                assert_eq!(e, "timeout");
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn codec_is_default() {
        let codec = MessageCodec::default();
        // Just verify it compiles and creates
        let _ = codec;
    }

    #[test]
    fn protocol_name_is_valid() {
        assert!(WHISPER_PROTOCOL.starts_with('/'));
        assert!(WHISPER_PROTOCOL.contains("whisper"));
        assert!(WHISPER_PROTOCOL.contains("1.0.0"));
    }

    // Note: Full behaviour tests require async runtime and are in integration tests
}
