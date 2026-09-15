//! SQLite storage: single connection behind a mutex, WAL mode, hand-written
//! SQL (no ORM — the control plane volume does not need pooling).

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("存储错误：{0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("IO 错误：{0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct Db {
    conn: std::sync::Arc<Mutex<Connection>>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS networks(
    id BLOB PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    cidr TEXT NOT NULL,
    created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS devices(
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    pubkey_sign TEXT NOT NULL,
    pubkey_dh TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    relay_key TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS enroll_tokens(
    token TEXT PRIMARY KEY,
    network_id BLOB NOT NULL,
    uses_left INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    requested_ip TEXT,
    created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS memberships(
    network_id BLOB NOT NULL,
    device_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    PRIMARY KEY(network_id, device_id),
    UNIQUE(network_id, ip));
CREATE TABLE IF NOT EXISTS device_settings(
    device_id INTEGER PRIMARY KEY,
    revision INTEGER NOT NULL DEFAULT 0,
    json TEXT NOT NULL,
    updated_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash);
CREATE INDEX IF NOT EXISTS idx_memberships_device ON memberships(device_id);
";

impl Db {
    pub fn open(path: &Path) -> Result<Db, DbError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        Ok(Db {
            conn: std::sync::Arc::new(Mutex::new(conn)),
        })
    }

    /// Run a closure with exclusive access to the connection. Do not nest
    /// DB calls while holding the lock.
    pub fn with<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, rusqlite::Error>,
    ) -> Result<T, DbError> {
        let guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        f(&guard).map_err(DbError::Sqlite)
    }

    /// Run a closure inside a single transaction (rollback on error).
    pub fn with_tx<T, E>(
        &self,
        f: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, E>,
    ) -> Result<T, E>
    where
        E: From<rusqlite::Error>,
    {
        let mut guard = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        let tx = guard.transaction().map_err(E::from)?;
        let out = f(&tx)?;
        tx.commit().map_err(E::from)?;
        Ok(out)
    }
}
