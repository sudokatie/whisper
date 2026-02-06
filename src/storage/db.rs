//! Database operations.

use std::path::Path;

use anyhow::Result;
use rusqlite::Connection;

/// SQLite database wrapper.
pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open or create database at path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.migrate()?;
        Ok(db)
    }

    /// Run migrations.
    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(include_str!("schema.sql"))?;
        Ok(())
    }

    /// Get the connection.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}
