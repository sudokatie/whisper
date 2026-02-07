//! Message handling - types, queue, and sync.

mod queue;
mod sync;
mod types;

pub use queue::MessageQueue;
pub use types::{Message, MessageContent, MessageStatus, Recipient, ReceiptType};
