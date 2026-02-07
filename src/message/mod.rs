//! Message handling - types, queue, and sync.

mod queue;
mod sync;
mod types;

pub use queue::MessageQueue;
pub use sync::{diff_messages, filter_history, merge_messages, needs_sync, HistoryRequest};
pub use types::{Message, MessageContent, MessageStatus, Recipient, ReceiptType};
