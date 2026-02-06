-- Whisper database schema

CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_peer TEXT NOT NULL,
    to_peer TEXT NOT NULL,
    content BLOB NOT NULL,
    timestamp INTEGER NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    peer_id TEXT PRIMARY KEY,
    alias TEXT UNIQUE NOT NULL,
    public_key BLOB NOT NULL,
    trust_level TEXT NOT NULL,
    last_seen INTEGER
);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    symmetric_key BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    peer_id TEXT NOT NULL,
    PRIMARY KEY (group_id, peer_id)
);

CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_peer);
CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_peer);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
