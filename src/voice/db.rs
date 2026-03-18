//! Database operations for voice messages.

use rusqlite::{params, Connection, Result as SqlResult};
use uuid::Uuid;

use super::{AudioCodec, VoiceMessage};

/// Create voice messages table.
pub fn create_voice_table(conn: &Connection) -> SqlResult<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS voice_messages (
            id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL,
            duration_ms INTEGER NOT NULL,
            codec TEXT NOT NULL,
            sample_rate INTEGER NOT NULL,
            size_bytes INTEGER NOT NULL,
            waveform BLOB,
            audio_data BLOB NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )",
        [],
    )?;
    
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_voice_message_id ON voice_messages(message_id)",
        [],
    )?;
    
    Ok(())
}

/// Store a voice message.
pub fn store_voice_message(
    conn: &Connection,
    message_id: &str,
    voice: &VoiceMessage,
    audio_data: &[u8],
) -> SqlResult<()> {
    let codec_str = match voice.codec {
        AudioCodec::Opus => "opus",
        AudioCodec::Pcm16 => "pcm16",
    };
    
    conn.execute(
        "INSERT INTO voice_messages (id, message_id, duration_ms, codec, sample_rate, size_bytes, waveform, audio_data)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            voice.id.to_string(),
            message_id,
            voice.duration_ms as i64,
            codec_str,
            voice.sample_rate as i64,
            voice.size_bytes as i64,
            &voice.waveform,
            audio_data,
        ],
    )?;
    
    Ok(())
}

/// Get voice message by message ID.
pub fn get_voice_message(conn: &Connection, message_id: &str) -> SqlResult<Option<(VoiceMessage, Vec<u8>)>> {
    let mut stmt = conn.prepare(
        "SELECT id, duration_ms, codec, sample_rate, size_bytes, waveform, audio_data
         FROM voice_messages WHERE message_id = ?1"
    )?;
    
    let result = stmt.query_row(params![message_id], |row| {
        let id_str: String = row.get(0)?;
        let duration_ms: i64 = row.get(1)?;
        let codec_str: String = row.get(2)?;
        let sample_rate: i64 = row.get(3)?;
        let size_bytes: i64 = row.get(4)?;
        let waveform: Vec<u8> = row.get(5)?;
        let audio_data: Vec<u8> = row.get(6)?;
        
        let codec = match codec_str.as_str() {
            "opus" => AudioCodec::Opus,
            "pcm16" => AudioCodec::Pcm16,
            _ => AudioCodec::Opus,
        };
        
        let voice = VoiceMessage {
            id: Uuid::parse_str(&id_str).unwrap_or_else(|_| Uuid::new_v4()),
            duration_ms: duration_ms as u64,
            codec,
            sample_rate: sample_rate as u32,
            size_bytes: size_bytes as u64,
            waveform,
        };
        
        Ok((voice, audio_data))
    });
    
    match result {
        Ok(data) => Ok(Some(data)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Delete voice message.
pub fn delete_voice_message(conn: &Connection, message_id: &str) -> SqlResult<bool> {
    let rows = conn.execute(
        "DELETE FROM voice_messages WHERE message_id = ?1",
        params![message_id],
    )?;
    
    Ok(rows > 0)
}

/// Get total voice message storage in bytes.
pub fn get_voice_storage_bytes(conn: &Connection) -> SqlResult<u64> {
    let size: i64 = conn.query_row(
        "SELECT COALESCE(SUM(size_bytes), 0) FROM voice_messages",
        [],
        |row| row.get(0),
    )?;
    
    Ok(size as u64)
}

#[cfg(test)]
mod db_tests {
    use super::*;
    use rusqlite::Connection;
    
    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        create_voice_table(&conn).unwrap();
        conn
    }
    
    #[test]
    fn test_create_voice_table() {
        let conn = setup_test_db();
        
        // Table should exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='voice_messages'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        
        assert_eq!(count, 1);
    }
    
    #[test]
    fn test_store_and_get_voice_message() {
        let conn = setup_test_db();
        
        let voice = VoiceMessage::new(5000, AudioCodec::Opus, 16000, 1024);
        let audio_data = vec![1, 2, 3, 4, 5];
        let message_id = "msg-123";
        
        store_voice_message(&conn, message_id, &voice, &audio_data).unwrap();
        
        let result = get_voice_message(&conn, message_id).unwrap();
        assert!(result.is_some());
        
        let (retrieved, retrieved_audio) = result.unwrap();
        assert_eq!(retrieved.duration_ms, 5000);
        assert_eq!(retrieved.codec, AudioCodec::Opus);
        assert_eq!(retrieved_audio, audio_data);
    }
    
    #[test]
    fn test_get_nonexistent_voice_message() {
        let conn = setup_test_db();
        
        let result = get_voice_message(&conn, "nonexistent").unwrap();
        assert!(result.is_none());
    }
    
    #[test]
    fn test_delete_voice_message() {
        let conn = setup_test_db();
        
        let voice = VoiceMessage::new(5000, AudioCodec::Opus, 16000, 1024);
        let audio_data = vec![1, 2, 3];
        let message_id = "msg-456";
        
        store_voice_message(&conn, message_id, &voice, &audio_data).unwrap();
        
        let deleted = delete_voice_message(&conn, message_id).unwrap();
        assert!(deleted);
        
        let result = get_voice_message(&conn, message_id).unwrap();
        assert!(result.is_none());
    }
    
    #[test]
    fn test_get_voice_storage_bytes() {
        let conn = setup_test_db();
        
        // Initially zero
        let size = get_voice_storage_bytes(&conn).unwrap();
        assert_eq!(size, 0);
        
        // Add a voice message
        let voice = VoiceMessage::new(5000, AudioCodec::Opus, 16000, 2048);
        store_voice_message(&conn, "msg-1", &voice, &vec![0; 100]).unwrap();
        
        let size = get_voice_storage_bytes(&conn).unwrap();
        assert_eq!(size, 2048);
    }
}
