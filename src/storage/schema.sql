-- Whisper database schema

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_peer TEXT NOT NULL,
    to_peer TEXT NOT NULL,
    content BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    status TEXT NOT NULL,
    expires_at INTEGER
);

-- Index for efficient expired message cleanup
CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages(expires_at) WHERE expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS contacts (
    peer_id TEXT PRIMARY KEY,
    alias TEXT UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    trust_level TEXT NOT NULL,
    last_seen INTEGER,
    send_read_receipts INTEGER NOT NULL DEFAULT 1,
    disappear_after_seconds INTEGER
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    owner_peer_id TEXT,
    symmetric_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (group_id, peer_id)
);

CREATE TABLE IF NOT EXISTS pending_messages (
    id TEXT PRIMARY KEY,
    to_peer TEXT NOT NULL,
    encrypted_data BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    attempts INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_peer);
CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_peer);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_pending_to ON pending_messages(to_peer);

-- File transfer tables

CREATE TABLE IF NOT EXISTS file_transfers (
    id TEXT PRIMARY KEY,
    from_peer TEXT NOT NULL,
    to_peer TEXT NOT NULL,
    filename TEXT NOT NULL,
    total_size INTEGER NOT NULL,
    total_chunks INTEGER NOT NULL,
    chunks_received INTEGER DEFAULT 0,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    file_checksum BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS file_chunks (
    transfer_id TEXT NOT NULL,
    chunk_index INTEGER NOT NULL,
    data BLOB NOT NULL,
    checksum BLOB NOT NULL,
    received_at INTEGER NOT NULL,
    PRIMARY KEY (transfer_id, chunk_index),
    FOREIGN KEY (transfer_id) REFERENCES file_transfers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_transfers_status ON file_transfers(status);
CREATE INDEX IF NOT EXISTS idx_file_transfers_from ON file_transfers(from_peer);
CREATE INDEX IF NOT EXISTS idx_file_transfers_to ON file_transfers(to_peer);

-- Reactions table

CREATE TABLE IF NOT EXISTS reactions (
    id TEXT PRIMARY KEY,
    message_id TEXT NOT NULL,
    from_peer TEXT NOT NULL,
    emoji TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    UNIQUE(message_id, from_peer, emoji)
);

CREATE INDEX IF NOT EXISTS idx_reactions_message ON reactions(message_id);
CREATE INDEX IF NOT EXISTS idx_reactions_from ON reactions(from_peer);
