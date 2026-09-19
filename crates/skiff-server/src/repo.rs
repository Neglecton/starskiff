//! Repositories over the SQLite schema. Row mapping is hand-written; column
//! names must match the SQL exactly.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

use rusqlite::{OptionalExtension, params};
use skiff_core::crypto::tokens::{make_device_token, make_enroll_token, sha256_hex, split_token};
use skiff_core::ipam::{Cidr, IpPool};
use skiff_core::logging::unix_ms;
use skiff_core::models::{DeviceSettings, NetId};

use crate::db::Db;

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NetworkRow {
    pub id: NetId,
    pub name: String,
    pub cidr: String,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: u64,
    pub name: String,
    pub pubkey_sign: String,
    pub pubkey_dh: String,
    pub token_hash: String,
    pub relay_key: String,
    pub created_at: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone)]
pub struct TokenRow {
    pub token: String,
    pub network_id: NetId,
    pub uses_left: i64,
    pub expires_at: i64,
    pub requested_ip: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MembershipRow {
    pub network_id: NetId,
    pub device_id: u64,
    pub ip: String,
}

fn map_network(row: &rusqlite::Row<'_>) -> rusqlite::Result<NetworkRow> {
    let id_blob: Vec<u8> = row.get("id")?;
    Ok(NetworkRow {
        id: NetId(id_blob.try_into().expect("network id is 16 bytes")),
        name: row.get("name")?,
        cidr: row.get("cidr")?,
        created_at: row.get("created_at")?,
    })
}

fn map_device(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRow> {
    Ok(DeviceRow {
        id: row.get::<_, i64>("id")? as u64,
        name: row.get("name")?,
        pubkey_sign: row.get("pubkey_sign")?,
        pubkey_dh: row.get("pubkey_dh")?,
        token_hash: row.get("token_hash")?,
        relay_key: row.get("relay_key")?,
        created_at: row.get("created_at")?,
        last_seen: row.get("last_seen")?,
    })
}

fn map_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<TokenRow> {
    let network_id: Vec<u8> = row.get("network_id")?;
    Ok(TokenRow {
        token: row.get("token")?,
        network_id: NetId(network_id.try_into().expect("network id is 16 bytes")),
        uses_left: row.get("uses_left")?,
        expires_at: row.get("expires_at")?,
        requested_ip: row.get("requested_ip")?,
    })
}

fn map_membership(row: &rusqlite::Row<'_>) -> rusqlite::Result<MembershipRow> {
    let network_id: Vec<u8> = row.get("network_id")?;
    Ok(MembershipRow {
        network_id: NetId(network_id.try_into().expect("network id is 16 bytes")),
        device_id: row.get::<_, i64>("device_id")? as u64,
        ip: row.get("ip")?,
    })
}

/// Random non-zero device id.
pub fn new_device_id() -> u64 {
    use rand_core::{OsRng, RngCore};
    loop {
        let id = OsRng.next_u64();
        if id != 0 {
            return id;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error(transparent)]
    Db(#[from] crate::db::DbError),
    #[error("{0}")]
    Conflict(String),
}

// ---------------------------------------------------------------------------
// Repo
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Repo {
    db: Db,
}

#[derive(Debug)]
pub struct EnrollResult {
    pub device_id: u64,
    pub device_token: String,
    pub network: NetworkRow,
    pub ip: String,
}

#[derive(Debug)]
pub struct JoinResult {
    pub network: NetworkRow,
    pub ip: String,
    pub already_member: bool,
}

impl Repo {
    pub fn open(path: &Path) -> Result<Repo, crate::db::DbError> {
        Ok(Repo {
            db: Db::open(path)?,
        })
    }

    pub fn from_db(db: Db) -> Repo {
        Repo { db }
    }

    // settings ---------------------------------------------------------------

    pub fn get_setting(&self, key: &str) -> Result<Option<String>, crate::db::DbError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |r| r.get(0),
            )
            .optional()
        })
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), crate::db::DbError> {
        self.db.with(|c| {
            c.execute(
                "INSERT INTO settings(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )?;
            Ok(())
        })
    }

    // device_settings ---------------------------------------------------------

    /// 读设备的托管配置；无记录时返回 revision=0 的空配置（全部未托管）。
    /// 附带下发状态（last_good/last_error，供管理页展示）。
    pub fn get_device_settings_full(
        &self,
        device_id: u64,
    ) -> Result<(DeviceSettings, Option<String>, Option<i64>), RepoError> {
        let row = self.db.with(|c| {
            c.query_row(
                "SELECT revision, json, last_error, failed_revision FROM device_settings WHERE device_id = ?1",
                params![device_id as i64],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()
        })?;
        match row {
            Some((revision, json, err, failed_rev)) => {
                let mut settings: DeviceSettings =
                    serde_json::from_str(&json).map_err(|e| RepoError::Conflict(format!("device_settings JSON 无效: {e}")))?;
                settings.revision = revision; // 列是 revision 的权威来源
                Ok((settings, err, failed_rev))
            }
            None => Ok((DeviceSettings::default(), None, None)),
        }
    }

    pub fn get_device_settings(&self, device_id: u64) -> Result<DeviceSettings, RepoError> {
        Ok(self.get_device_settings_full(device_id)?.0)
    }

    /// 节点应答成功（心跳 appliedRevision 追平当前 revision）：把**节点
    /// 已验证的那一版**内容固化为 last_good（回滚锚点），清除错误记录。
    /// 单条条件 UPDATE（revision <= applied）：若调用方读判与写入之间
    /// 管理员又下发了新版本，守卫 0 行命中、新内容不会被固化——把
    /// 正确性交给数据库原子性而非调用方时序（AGENTS.md #22）。
    pub fn mark_settings_applied(&self, device_id: u64, applied: i64) -> Result<(), RepoError> {
        self.db.with(|c| {
            c.execute(
                "UPDATE device_settings SET last_good_json = json, last_error = NULL, failed_revision = NULL
                 WHERE device_id = ?1 AND revision > 0 AND revision <= ?2",
                params![device_id as i64, applied],
            )?;
            Ok(())
        })?;
        Ok(())
    }

    /// worker 启动失败上报：仅当上报的 revision 仍是当前 revision 时生效
    ///（过期/重复上报天然幂等）。回滚 = 恢复 last_good（无则清空托管），
    /// revision 递增，记录错误。返回回滚后的配置（供日志/推送）。
    /// 读-判-写同事务且 UPDATE 带 revision 守卫：过期上报不会覆盖期间
    /// 管理员新下发的配置（AGENTS.md #22/#23）。
    pub fn report_settings_fail(
        &self,
        device_id: u64,
        failed_revision: i64,
        error: &str,
    ) -> Result<Option<DeviceSettings>, RepoError> {
        let err: String = error.chars().take(500).collect();
        let rolled: Option<(String, i64)> = self.db.with_tx(|tx| -> Result<Option<(String, i64)>, RepoError> {
            let row = tx
                .query_row(
                    "SELECT revision, last_good_json FROM device_settings WHERE device_id = ?1",
                    params![device_id as i64],
                    |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)),
                )
                .optional()?;
            let Some((current, last_good)) = row else {
                return Ok(None); // 无托管记录：无需回滚
            };
            if failed_revision != current {
                return Ok(None); // 过期上报（已回滚过 / 又有新下发）
            }
            let rollback_json = match last_good {
                Some(g) => g,
                None => serde_json::to_string(&DeviceSettings::default())
                    .map_err(|e| RepoError::Conflict(format!("序列化失败: {e}")))?,
            };
            let next = current + 1;
            let hit = tx.execute(
                "UPDATE device_settings SET json = ?2, revision = ?3, last_error = ?4, failed_revision = ?5, updated_at = ?6
                 WHERE device_id = ?1 AND revision = ?7",
                params![device_id as i64, rollback_json, next, err, failed_revision, unix_ms(), current],
            )?;
            if hit == 0 {
                return Ok(None); // 守卫未命中（并发已变更）：按过期上报处理
            }
            Ok(Some((rollback_json, next)))
        })?;
        let Some((rollback_json, next)) = rolled else {
            return Ok(None);
        };
        let mut rolled = serde_json::from_str::<DeviceSettings>(&rollback_json)
            .map_err(|e| RepoError::Conflict(format!("回滚内容无效: {e}")))?;
        rolled.revision = next;
        Ok(Some(rolled))
    }

    /// 保存托管配置：事务内 revision+1 后整体覆盖，返回落库后的值。
    pub fn set_device_settings(
        &self,
        device_id: u64,
        update: &DeviceSettings,
    ) -> Result<DeviceSettings, RepoError> {
        let mut stored = update.clone();
        stored.revision = 0; // json 内不存 revision，列权威
        let json = serde_json::to_string(&stored).map_err(|e| RepoError::Conflict(format!("序列化失败: {e}")))?;
        let next = self.db.with_tx(|tx| -> Result<i64, RepoError> {
            let current: i64 = tx
                .query_row(
                    "SELECT revision FROM device_settings WHERE device_id = ?1",
                    params![device_id as i64],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            let next = current + 1;
            tx.execute(
                "INSERT INTO device_settings(device_id, revision, json, updated_at)
                 VALUES(?1, ?2, ?3, ?4)
                 ON CONFLICT(device_id) DO UPDATE SET
                    revision = excluded.revision, json = excluded.json, updated_at = excluded.updated_at",
                params![device_id as i64, next, json, unix_ms()],
            )?;
            Ok(next)
        })?;
        stored.revision = next;
        Ok(stored)
    }

    // networks ---------------------------------------------------------------

    pub fn create_network(&self, name: &str, cidr: &str) -> Result<NetworkRow, RepoError> {
        let now = unix_ms();
        let id = NetId::random();
        // 查重与插入之间的竞态由 networks.name UNIQUE 兜底：约束冲突映射为
        // Conflict（调用方返回 409）而非 500。
        let inserted = self.db.with(|c| {
            c.execute(
                "INSERT INTO networks(id, name, cidr, created_at) VALUES(?1, ?2, ?3, ?4)",
                params![id.as_bytes(), name, cidr, now],
            )?;
            Ok(())
        });
        match inserted {
            Ok(()) => {}
            Err(crate::db::DbError::Sqlite(rusqlite::Error::SqliteFailure(e, _)))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(RepoError::Conflict("同名网络已存在".into()));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(NetworkRow {
            id,
            name: name.to_string(),
            cidr: cidr.to_string(),
            created_at: now,
        })
    }

    pub fn get_network(&self, id: NetId) -> Result<Option<NetworkRow>, crate::db::DbError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT * FROM networks WHERE id = ?1",
                params![id.as_bytes()],
                map_network,
            )
            .optional()
        })
    }

    pub fn get_network_by_name(
        &self,
        name: &str,
    ) -> Result<Option<NetworkRow>, crate::db::DbError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT * FROM networks WHERE name = ?1",
                params![name],
                map_network,
            )
            .optional()
        })
    }

    pub fn list_networks(&self) -> Result<Vec<NetworkRow>, crate::db::DbError> {
        self.db.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM networks ORDER BY created_at")?;
            let rows = stmt
                .query_map([], map_network)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
    }

    pub fn delete_network(&self, id: NetId) -> Result<bool, RepoError> {
        self.db.with_tx(|c| {
            let n = c.execute(
                "DELETE FROM memberships WHERE network_id = ?1",
                params![id.as_bytes()],
            )?;
            let _ = n;
            c.execute(
                "DELETE FROM enroll_tokens WHERE network_id = ?1",
                params![id.as_bytes()],
            )?;
            let deleted =
                c.execute("DELETE FROM networks WHERE id = ?1", params![id.as_bytes()])?;
            Ok(deleted > 0)
        })
    }

    // devices ----------------------------------------------------------------

    pub fn create_device(
        &self,
        name: &str,
        sign_pub: &str,
        dh_pub: &str,
        device_token: &str,
    ) -> Result<(u64, i64), crate::db::DbError> {
        let id = new_device_id();
        let now = unix_ms();
        let hash = sha256_hex(device_token);
        self.db.with(|c| {
            c.execute(
                "INSERT INTO devices(id, name, pubkey_sign, pubkey_dh, token_hash, relay_key, created_at, last_seen)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?5, ?6, 0)",
                params![id as i64, name, sign_pub, dh_pub, hash, now],
            )?;
            Ok(())
        })?;
        Ok((id, now))
    }

    pub fn get_device(&self, id: u64) -> Result<Option<DeviceRow>, crate::db::DbError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT * FROM devices WHERE id = ?1",
                params![id as i64],
                map_device,
            )
            .optional()
        })
    }

    pub fn find_device_by_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<DeviceRow>, crate::db::DbError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT * FROM devices WHERE token_hash = ?1 ORDER BY id LIMIT 1",
                params![hash],
                map_device,
            )
            .optional()
        })
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRow>, crate::db::DbError> {
        self.db.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM devices ORDER BY created_at")?;
            stmt.query_map([], map_device)?
                .collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn delete_device(&self, id: u64) -> Result<bool, RepoError> {
        self.db.with_tx(|c| {
            c.execute(
                "DELETE FROM memberships WHERE device_id = ?1",
                params![id as i64],
            )?;
            let deleted = c.execute("DELETE FROM devices WHERE id = ?1", params![id as i64])?;
            Ok(deleted > 0)
        })
    }

    pub fn touch_device(&self, id: u64) -> Result<(), crate::db::DbError> {
        self.db.with(|c| {
            c.execute(
                "UPDATE devices SET last_seen = ?1 WHERE id = ?2",
                params![unix_ms(), id as i64],
            )?;
            Ok(())
        })
    }

    // enroll tokens ----------------------------------------------------------

    pub fn create_token(
        &self,
        network_id: NetId,
        uses: i64,
        ttl_ms: i64,
        requested_ip: Option<&str>,
    ) -> Result<TokenRow, crate::db::DbError> {
        let token = make_enroll_token();
        let now = unix_ms();
        let expires = now + ttl_ms;
        self.db.with(|c| {
            c.execute(
                "INSERT INTO enroll_tokens(token, network_id, uses_left, expires_at, requested_ip, created_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                params![token, network_id.as_bytes(), uses, expires, requested_ip, now],
            )?;
            Ok(())
        })?;
        Ok(TokenRow {
            token,
            network_id,
            uses_left: uses,
            expires_at: expires,
            requested_ip: requested_ip.map(String::from),
        })
    }

    pub fn get_token(
        &self,
        token_with_suffix: &str,
    ) -> Result<Option<TokenRow>, crate::db::DbError> {
        let (bare, _) = split_token(token_with_suffix);
        self.db.with(|c| {
            c.query_row(
                "SELECT * FROM enroll_tokens WHERE token = ?1",
                params![bare],
                map_token,
            )
            .optional()
        })
    }

    pub fn list_tokens(&self) -> Result<Vec<TokenRow>, crate::db::DbError> {
        self.db.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM enroll_tokens ORDER BY rowid")?;
            stmt.query_map([], map_token)?
                .collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn delete_token(&self, token_with_suffix: &str) -> Result<bool, crate::db::DbError> {
        let (bare, _) = split_token(token_with_suffix);
        self.db.with(|c| {
            Ok(c.execute("DELETE FROM enroll_tokens WHERE token = ?1", params![bare])? > 0)
        })
    }

    /// Atomically decrement uses; `true` when a use was consumed.
    pub fn consume_token_use(
        tx: &rusqlite::Transaction<'_>,
        bare_token: &str,
    ) -> Result<bool, crate::db::DbError> {
        let n = tx.execute(
            "UPDATE enroll_tokens SET uses_left = uses_left - 1 WHERE token = ?1 AND uses_left > 0",
            params![bare_token],
        )?;
        Ok(n > 0)
    }

    // memberships ------------------------------------------------------------

    pub fn memberships_of_network(
        &self,
        network_id: NetId,
    ) -> Result<Vec<MembershipRow>, crate::db::DbError> {
        self.db.with(|c| {
            let mut stmt =
                c.prepare("SELECT * FROM memberships WHERE network_id = ?1 ORDER BY ip")?;
            stmt.query_map(params![network_id.as_bytes()], map_membership)?
                .collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn membership_of(
        &self,
        network_id: NetId,
        device_id: u64,
    ) -> Result<Option<MembershipRow>, crate::db::DbError> {
        self.db.with(|c| {
            c.query_row(
                "SELECT * FROM memberships WHERE network_id = ?1 AND device_id = ?2",
                params![network_id.as_bytes(), device_id as i64],
                map_membership,
            )
            .optional()
        })
    }

    pub fn memberships_of_device(
        &self,
        device_id: u64,
    ) -> Result<Vec<MembershipRow>, crate::db::DbError> {
        self.db.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM memberships WHERE device_id = ?1 ORDER BY network_id")?;
            stmt.query_map(params![device_id as i64], map_membership)?
                .collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn all_memberships(&self) -> Result<Vec<MembershipRow>, crate::db::DbError> {
        self.db.with(|c| {
            let mut stmt = c.prepare("SELECT * FROM memberships")?;
            stmt.query_map([], map_membership)?
                .collect::<Result<Vec<_>, _>>()
        })
    }

    pub fn update_membership_ip(
        &self,
        network_id: NetId,
        device_id: u64,
        ip: &str,
    ) -> Result<(), crate::db::DbError> {
        self.db.with(|c| {
            c.execute(
                "UPDATE memberships SET ip = ?1 WHERE network_id = ?2 AND device_id = ?3",
                params![ip, network_id.as_bytes(), device_id as i64],
            )?;
            Ok(())
        })
    }

    // enroll (the one real transaction) ---------------------------------------

    /// Enroll a new device. IP precedence: requested-by-caller, then the
    /// token's requested_ip, then sequential pool allocation. Fails with a
    /// user-facing message.
    pub fn enroll(
        &self,
        enroll_token_with_suffix: &str,
        name: &str,
        sign_pubkey: &str,
        dh_pubkey: &str,
        requested_ip: Option<&str>,
    ) -> Result<EnrollResult, RepoError> {
        let (bare, _) = split_token(enroll_token_with_suffix);
        let now = unix_ms();

        self.db.with_tx(|tx| {
            let token: Option<TokenRow> = tx
                .query_row("SELECT * FROM enroll_tokens WHERE token = ?1", params![bare], map_token)
                .optional()?;
            let Some(token) = token else {
                return Err(RepoError::Conflict("注册令牌不存在".into()));
            };
            if token.expires_at < now {
                return Err(RepoError::Conflict("注册令牌已过期".into()));
            }
            if token.uses_left <= 0 {
                return Err(RepoError::Conflict("注册令牌已用尽".into()));
            }

            let network: Option<NetworkRow> = tx
                .query_row("SELECT * FROM networks WHERE id = ?1", params![token.network_id.as_bytes()], map_network)
                .optional()?;
            let Some(network) = network else {
                return Err(RepoError::Conflict("令牌所属网络已不存在".into()));
            };

            let cidr = Cidr::parse(&network.cidr)
                .map_err(|_| RepoError::Conflict(format!("网络 {} 的 CIDR 配置无效", network.name)))?;
            let mut used: HashSet<u32> = HashSet::new();
            {
                let mut stmt = tx.prepare("SELECT ip FROM memberships WHERE network_id = ?1")?;
                let ips = stmt.query_map(params![token.network_id.as_bytes()], |r| r.get::<_, String>(0))?;
                for ip in ips {
                    if let Ok(addr) = ip?.parse::<Ipv4Addr>() {
                        used.insert(u32::from(addr));
                    }
                }
            }

            let chosen: u32 = if let Some(req) = requested_ip.or(token.requested_ip.as_deref()) {
                IpPool::validate_manual(req, &cidr, &used, None)
                    .map_err(RepoError::Conflict)?
            } else {
                IpPool::allocate(&cidr, &used)
                    .ok_or_else(|| RepoError::Conflict(format!("网络 {}（{}）已无可分配地址", network.name, network.cidr)))?
            };
            let ip_text = Ipv4Addr::from(chosen).to_string();

            let device_token = make_device_token();
            let device_id = new_device_id();
            let hash = sha256_hex(&device_token);
            tx.execute(
                "INSERT INTO devices(id, name, pubkey_sign, pubkey_dh, token_hash, relay_key, created_at, last_seen)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?5, ?6, 0)",
                params![device_id as i64, name, sign_pubkey, dh_pubkey, hash, now],
            )?;
            tx.execute(
                "INSERT INTO memberships(network_id, device_id, ip) VALUES(?1, ?2, ?3)",
                params![token.network_id.as_bytes(), device_id as i64, ip_text],
            )?;
            if !Self::consume_token_use(tx, &bare)? {
                return Err(RepoError::Conflict("注册令牌已用尽".into()));
            }

            Ok(EnrollResult { device_id, device_token, network, ip: ip_text })
        })
    }

    /// An existing device joins another network using an enroll token.
    /// Idempotent: already-a-member returns the current membership.
    pub fn join_network(
        &self,
        device_id: u64,
        enroll_token_with_suffix: &str,
        requested_ip: Option<&str>,
    ) -> Result<JoinResult, RepoError> {
        let (bare, _) = split_token(enroll_token_with_suffix);
        let now = unix_ms();

        self.db.with_tx(|tx| {
            let token: Option<TokenRow> = tx
                .query_row("SELECT * FROM enroll_tokens WHERE token = ?1", params![bare], map_token)
                .optional()?;
            let Some(token) = token else {
                return Err(RepoError::Conflict("注册令牌不存在".into()));
            };
            if token.expires_at < now {
                return Err(RepoError::Conflict("注册令牌已过期".into()));
            }
            if token.uses_left <= 0 {
                return Err(RepoError::Conflict("注册令牌已用尽".into()));
            }
            let network: Option<NetworkRow> = tx
                .query_row("SELECT * FROM networks WHERE id = ?1", params![token.network_id.as_bytes()], map_network)
                .optional()?;
            let Some(network) = network else {
                return Err(RepoError::Conflict("令牌所属网络已不存在".into()));
            };

            // Idempotency: an existing membership is returned as-is (the
            // token is not consumed).
            if let Some(m) = tx
                .query_row(
                    "SELECT * FROM memberships WHERE network_id = ?1 AND device_id = ?2",
                    params![token.network_id.as_bytes(), device_id as i64],
                    map_membership,
                )
                .optional()?
            {
                return Ok(JoinResult { network, ip: m.ip, already_member: true });
            }

            let ip_text =
                Self::insert_membership(tx, &network, device_id, requested_ip, token.requested_ip.as_deref())?;
            if !Self::consume_token_use(tx, &bare)? {
                return Err(RepoError::Conflict("注册令牌已用尽".into()));
            }

            Ok(JoinResult { network, ip: ip_text, already_member: false })
        })
    }

    /// 事务内分配并写入一条成员关系（join_network / admin_join_network
    /// 共用）：优先级 requested_ip > fallback_ip（令牌内嵌 IP）> 顺序分配。
    fn insert_membership(
        tx: &rusqlite::Transaction<'_>,
        network: &NetworkRow,
        device_id: u64,
        requested_ip: Option<&str>,
        fallback_ip: Option<&str>,
    ) -> Result<String, RepoError> {
        let cidr = Cidr::parse(&network.cidr)
            .map_err(|_| RepoError::Conflict(format!("网络 {} 的 CIDR 配置无效", network.name)))?;
        let mut used: HashSet<u32> = HashSet::new();
        {
            let mut stmt = tx.prepare("SELECT ip FROM memberships WHERE network_id = ?1")?;
            let ips = stmt.query_map(params![network.id.as_bytes()], |r| r.get::<_, String>(0))?;
            for ip in ips {
                if let Ok(addr) = ip?.parse::<Ipv4Addr>() {
                    used.insert(u32::from(addr));
                }
            }
        }
        let chosen: u32 = if let Some(req) = requested_ip.or(fallback_ip) {
            IpPool::validate_manual(req, &cidr, &used, None).map_err(RepoError::Conflict)?
        } else {
            IpPool::allocate(&cidr, &used)
                .ok_or_else(|| RepoError::Conflict(format!("网络 {}（{}）已无可分配地址", network.name, network.cidr)))?
        };
        let ip_text = Ipv4Addr::from(chosen).to_string();
        tx.execute(
            "INSERT INTO memberships(network_id, device_id, ip) VALUES(?1, ?2, ?3)",
            params![network.id.as_bytes(), device_id as i64, ip_text],
        )?;
        Ok(ip_text)
    }

    /// 管理员强制设备加入网络（绕过注册令牌；幂等：已在网络返回现 IP）。
    pub fn admin_join_network(
        &self,
        device_id: u64,
        network_id: NetId,
        requested_ip: Option<&str>,
        // TUN 单网络守卫须在**事务内**复核成员数：handler 预检在事务外，
        // 两个并发 join 都读到 1 个成员时会让 TUN 设备进 2 个网络。
        single_network_required: bool,
    ) -> Result<JoinResult, RepoError> {
        self.db.with_tx(|tx| -> Result<JoinResult, RepoError> {
            let network: Option<NetworkRow> = tx
                .query_row(
                    "SELECT * FROM networks WHERE id = ?1",
                    params![network_id.as_bytes()],
                    map_network,
                )
                .optional()?;
            let Some(network) = network else {
                return Err(RepoError::Conflict("网络不存在".into()));
            };
            if let Some(m) = tx
                .query_row(
                    "SELECT * FROM memberships WHERE network_id = ?1 AND device_id = ?2",
                    params![network_id.as_bytes(), device_id as i64],
                    map_membership,
                )
                .optional()?
            {
                return Ok(JoinResult { network, ip: m.ip, already_member: true });
            }
            if single_network_required {
                let cnt: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM memberships WHERE device_id = ?1",
                    params![device_id as i64],
                    |r| r.get(0),
                )?;
                if cnt > 0 {
                    return Err(RepoError::Conflict(
                        "TUN 模式节点仅支持单网络（先切换 proxy 模式或移出现有网络）".into(),
                    ));
                }
            }
            let ip_text = Self::insert_membership(tx, &network, device_id, requested_ip, None)?;
            Ok(JoinResult { network, ip: ip_text, already_member: false })
        })
    }

    /// 管理端改成员 IP：读占用集合 + 校验 + UPDATE 单事务（AGENTS #22）。
    /// 并发抢注由 UNIQUE(network_id, ip) 兜底并映射为 Conflict（409）——
    /// 此前校验与写入分离，竞态窗口内会以 500 裸暴露约束冲突。
    pub fn set_membership_ip_atomic(
        &self,
        network_id: NetId,
        device_id: u64,
        ip: &str,
        cidr: &Cidr,
    ) -> Result<(), RepoError> {
        self.db.with_tx(|tx| -> Result<(), RepoError> {
            let used: std::collections::HashSet<u32> = {
                let mut stmt = tx.prepare(
                    "SELECT ip FROM memberships WHERE network_id = ?1 AND device_id != ?2",
                )?;
                let rows = stmt.query_map(params![network_id.as_bytes(), device_id as i64], |r| {
                    r.get::<_, String>(0)
                })?;
                let mut set = std::collections::HashSet::new();
                for row in rows {
                    if let Ok(text) = row
                        && let Ok(v4) = text.parse::<std::net::Ipv4Addr>()
                    {
                        set.insert(u32::from(v4));
                    }
                }
                set
            };
            // 校验通过才尝试写入（错误消息面向管理员，保持 IpPool 文案）。
            if let Err(msg) = IpPool::validate_manual(ip, cidr, &used, None) {
                return Err(RepoError::Conflict(msg));
            }
            match tx.execute(
                "UPDATE memberships SET ip = ?1 WHERE network_id = ?2 AND device_id = ?3",
                params![ip, network_id.as_bytes(), device_id as i64],
            ) {
                Ok(_) => Ok(()),
                Err(e)
                    if e.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) =>
                {
                    Err(RepoError::Conflict("IP 已被占用".into()))
                }
                Err(e) => Err(RepoError::Sqlite(e)),
            }
        })
    }

    /// 管理员强制移除设备的某网络成员关系（最后一个不可移除，同 leave）。
    pub fn admin_remove_membership(
        &self,
        device_id: u64,
        network_id: NetId,
    ) -> Result<NetworkRow, RepoError> {
        remove_membership_guarded(&self.db, device_id, network_id)?;
        self.get_network(network_id)?
            .ok_or_else(|| RepoError::Conflict("网络不存在".into()))
    }

    /// A device removes its own membership in a network (name or hex id).
    /// The last membership cannot be removed (re-enroll instead).
    pub fn leave_network(&self, device_id: u64, network_name_or_id: &str) -> Result<NetworkRow, RepoError> {
        let memberships = self.memberships_of_device(device_id)?;
        let net_id = memberships
            .iter()
            .find(|m| {
                self.get_network(m.network_id)
                    .ok()
                    .flatten()
                    .is_some_and(|n| n.name.eq_ignore_ascii_case(network_name_or_id))
                    || network_name_or_id.len() == 32
                        && network_name_or_id.bytes().all(|b| b.is_ascii_hexdigit())
                        && m.network_id.to_hex() == network_name_or_id.to_ascii_lowercase()
            })
            .map(|m| m.network_id)
            .or_else(|| {
                if network_name_or_id.len() == 32 && network_name_or_id.bytes().all(|b| b.is_ascii_hexdigit()) {
                    NetId::from_hex(network_name_or_id)
                } else {
                    None
                }
            });
        let Some(net_id) = net_id else {
            return Err(RepoError::Conflict("未找到该网络的成员关系".into()));
        };
        // 名字解析的读取在事务外无妨：最终裁决由守卫删除给出。
        remove_membership_guarded(&self.db, device_id, net_id)?;
        self.get_network(net_id)?
            .ok_or_else(|| RepoError::Conflict("网络不存在".into()))
    }

    /// Admin token bootstrap: get-or-create.
    pub fn get_or_create_admin_token(&self) -> Result<String, crate::db::DbError> {
        if let Some(existing) = self.get_setting("admin_token")? {
            return Ok(existing);
        }
        let token = skiff_core::crypto::tokens::make_admin_token();
        self.set_setting("admin_token", &token)?;
        Ok(token)
    }

    pub fn admin_token(&self) -> Option<String> {
        self.get_setting("admin_token").ok().flatten()
    }
}

/// 守卫式成员移除：单条条件 DELETE（成员数 > 1 才允许删）+ 事务内归因
/// （不属于 / 最后一个）。并发 leave 同一设备的两个网络时，单连接 Mutex
/// 串行化 + 守卫保证不会把成员关系删光（AGENTS #22）。
fn remove_membership_guarded(
    db: &crate::db::Db,
    device_id: u64,
    network_id: NetId,
) -> Result<(), RepoError> {
    db.with_tx(|tx| -> Result<(), RepoError> {
        let hit = tx.execute(
            "DELETE FROM memberships WHERE network_id = ?1 AND device_id = ?2
             AND (SELECT COUNT(*) FROM memberships WHERE device_id = ?2) > 1",
            params![network_id.as_bytes(), device_id as i64],
        )?;
        if hit > 0 {
            return Ok(());
        }
        // 0 行命中：归因（事务内重读，非竞态判定）。
        let member: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM memberships WHERE network_id = ?1 AND device_id = ?2",
                params![network_id.as_bytes(), device_id as i64],
                |r| r.get(0),
            )
            .optional()?;
        if member.is_none() {
            Err(RepoError::Conflict("设备不属于该网络".into()))
        } else {
            Err(RepoError::Conflict(
                "不能移除最后一个网络（如需重置请删除设备重新 enroll）".into(),
            ))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_repo() -> Repo {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "skiff-repo-{}-{}-{}",
            std::process::id(),
            unix_ms(),
            seq
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repo::open(&dir.join("test.sqlite")).unwrap();
        // cleanup is best-effort; temp dirs are per-run
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let _ = std::fs::remove_dir_all(dir);
        });
        repo
    }

    #[test]
    fn enroll_flow_assigns_sequential_and_manual_ips() {
        let repo = temp_repo();
        let net = repo.create_network("corp", "10.88.0.0/24").unwrap();
        let token = repo.create_token(net.id, 100, 86_400_000, None).unwrap();

        let a = repo
            .enroll(&token.token, "a", &"aa".repeat(32), &"bb".repeat(32), None)
            .unwrap();
        assert_eq!(a.ip, "10.88.0.1");
        let b = repo
            .enroll(
                &token.token,
                "b",
                &"cc".repeat(32),
                &"dd".repeat(32),
                Some("10.88.0.200"),
            )
            .unwrap();
        assert_eq!(b.ip, "10.88.0.200");
        let c = repo
            .enroll(&token.token, "c", &"ee".repeat(32), &"ff".repeat(32), None)
            .unwrap();
        assert_eq!(c.ip, "10.88.0.2");

        // Duplicate manual IP rejected; token survives for retry.
        let err = repo
            .enroll(
                &token.token,
                "d",
                &"11".repeat(32),
                &"22".repeat(32),
                Some("10.88.0.1"),
            )
            .unwrap_err();
        assert!(err.to_string().contains("占用"));

        // Token with fingerprint suffix resolves to the same bare token.
        let with_fp = format!("{}.{}", token.token, "ab".repeat(32));
        let e = repo
            .enroll(&with_fp, "e", &"33".repeat(32), &"44".repeat(32), None)
            .unwrap();
        assert_eq!(e.ip, "10.88.0.3");
    }

    #[test]
    fn expired_or_exhausted_token_rejected() {
        let repo = temp_repo();
        let net = repo.create_network("n", "10.1.0.0/24").unwrap();
        let token = repo.create_token(net.id, 1, 86_400_000, None).unwrap();
        let _ = repo
            .enroll(&token.token, "a", &"aa".repeat(32), &"bb".repeat(32), None)
            .unwrap();
        let err = repo
            .enroll(&token.token, "b", &"cc".repeat(32), &"dd".repeat(32), None)
            .unwrap_err();
        assert!(err.to_string().contains("用尽"));

        let dead = repo.create_token(net.id, 1, -1, None).unwrap();
        let err = repo
            .enroll(&dead.token, "c", &"ee".repeat(32), &"ff".repeat(32), None)
            .unwrap_err();
        assert!(err.to_string().contains("过期"));
    }

    #[test]
    fn delete_network_cascades() {
        let repo = temp_repo();
        let net = repo.create_network("gone", "10.2.0.0/24").unwrap();
        let token = repo.create_token(net.id, 5, 86_400_000, None).unwrap();
        let dev = repo
            .enroll(&token.token, "a", &"aa".repeat(32), &"bb".repeat(32), None)
            .unwrap();
        assert!(repo.delete_network(net.id).unwrap());
        assert!(repo.get_network(net.id).unwrap().is_none());
        assert!(
            repo.memberships_of_device(dev.device_id)
                .unwrap()
                .is_empty()
        );
        assert!(repo.list_tokens().unwrap().is_empty());
        assert!(!repo.delete_network(net.id).unwrap());
    }

    fn settings_with_socks(port: u16) -> DeviceSettings {
        DeviceSettings {
            socks_listen: Some(format!("127.0.0.1:{port}")),
            ..DeviceSettings::default()
        }
    }

    fn last_good_json(repo: &Repo, device_id: u64) -> Option<String> {
        repo.db
            .with(|c| {
                c.query_row(
                    "SELECT last_good_json FROM device_settings WHERE device_id = ?1",
                    params![device_id as i64],
                    |r| r.get(0),
                )
                .optional()
            })
            .unwrap()
            .flatten()
    }


    fn net_with_device(name: &str) -> (Repo, NetId, u64, NetId) {
        let repo = temp_repo();
        let a = repo.create_network(&format!("{name}-a"), "10.20.0.0/24").unwrap();
        let b = repo.create_network(&format!("{name}-b"), "10.21.0.0/24").unwrap();
        let token = repo.create_token(a.id, 10, 86_400_000, None).unwrap();
        let dev = repo
            .enroll(&token.token, name, &"ab".repeat(32), &"cd".repeat(32), None)
            .unwrap();
        (repo, a.id, dev.device_id, b.id)
    }

    /// 成员数守卫（AGENTS #22）：并发 leave 不可把成员关系删光——最后一个
    /// 不可移除；非成员移除被拒。
    #[test]
    fn membership_removal_guards_last_one() {
        let (repo, net_a, dev, net_b) = net_with_device("guard");
        // 加入第二个网络后移除其一：成功。
        let token_b = repo.create_token(net_b, 10, 86_400_000, None).unwrap();
        repo.join_network(dev, &token_b.token, None).unwrap();
        assert!(repo.admin_remove_membership(dev, net_a).is_ok());
        // 只剩最后一个：拒绝（含正确的归因文案）。
        let err = repo.admin_remove_membership(dev, net_b).unwrap_err();
        assert!(err.to_string().contains("最后"));
        // 非成员：拒绝。
        let err = repo.admin_remove_membership(dev, net_a).unwrap_err();
        assert!(err.to_string().contains("不属于"));
    }

    /// join 事务内 TUN 单网络守卫：tun 要求下单网络设备加入第二网被拒。
    #[test]
    fn join_rejects_second_network_when_single_required() {
        let (repo, _net_a, dev, net_b) = net_with_device("tung");
        let token_b = repo.create_token(net_b, 10, 86_400_000, None).unwrap();
        assert!(repo
            .admin_join_network(dev, net_b, None, true)
            .is_err_and(|e| e.to_string().contains("单网络")));
        // 非单网络要求时同一 join 成功（语义不受标志影响）。
        assert!(repo.admin_join_network(dev, net_b, None, false).is_ok());
        let _ = token_b;
    }

    /// set_membership_ip_atomic：重复 IP → Conflict（409 语义，UNIQUE 兜底
    /// 不再裸 500）；合法变更成功。
    #[test]
    fn set_ip_atomic_maps_duplicate_to_conflict() {
        let (repo, net_a, dev, net_b) = net_with_device("setip");
        let token_b = repo.create_token(net_b, 10, 86_400_000, None).unwrap();
        let other = repo
            .enroll(&token_b.token, "setip-o", &"ef".repeat(32), &"12".repeat(32), None)
            .unwrap();
        // other=10.21.0.1；再注册 other2=10.21.0.2，把 other2 改成
        // other 占用的地址应映射为 Conflict（409 语义）。
        let other2 = repo
            .enroll(&token_b.token, "setip-p", &"34".repeat(32), &"56".repeat(32), None)
            .unwrap();
        let cidr = skiff_core::ipam::Cidr::parse("10.21.0.0/24").unwrap();
        let err = repo
            .set_membership_ip_atomic(net_b, other2.device_id, "10.21.0.1", &cidr)
            .unwrap_err();
        assert!(matches!(err, RepoError::Conflict(_)), "got {err:?}");
        let _ = other;
        // 合法地址成功。
        repo.set_membership_ip_atomic(net_a, dev, "10.20.0.77", &skiff_core::ipam::Cidr::parse("10.20.0.0/24").unwrap())
            .unwrap();
    }

    /// mark_settings_applied 的 revision 守卫：节点 applied=1 期间管理员
    /// 已下发未验证的 rev2，固化不得把 rev2 内容写进 last_good（否则回滚
    /// 回到坏配置自身——AGENTS.md #22 的 TOCTOU 守护语义，确定性测试
    /// 无需复现竞态）。
    #[test]
    fn mark_applied_never_fixates_newer_unverified_revision() {
        let repo = temp_repo();
        let net = repo.create_network("n", "10.9.0.0/24").unwrap();
        let token = repo.create_token(net.id, 5, 86_400_000, None).unwrap();
        let dev = repo
            .enroll(&token.token, "a", &"aa".repeat(32), &"bb".repeat(32), None)
            .unwrap();

        let s1 = repo.set_device_settings(dev.device_id, &settings_with_socks(1111)).unwrap();
        assert_eq!(s1.revision, 1);
        repo.mark_settings_applied(dev.device_id, 1).unwrap();
        let good = last_good_json(&repo, dev.device_id).expect("applied 版本应固化为 last_good");
        assert!(good.contains("1111"));

        // 节点心跳（applied=1）与新版下发（rev2）交错：守卫 0 行命中。
        let s2 = repo.set_device_settings(dev.device_id, &settings_with_socks(2222)).unwrap();
        assert_eq!(s2.revision, 2);
        repo.mark_settings_applied(dev.device_id, 1).unwrap();
        let good2 = last_good_json(&repo, dev.device_id).unwrap();
        assert_eq!(good2, good, "未验证的 rev2 不得覆盖 last_good");

        // 节点真实验证 rev2 后（applied=2）才允许固化。
        repo.mark_settings_applied(dev.device_id, 2).unwrap();
        let good3 = last_good_json(&repo, dev.device_id).unwrap();
        assert!(good3.contains("2222"), "验证后的 rev2 才可固化");
    }

    /// report_settings_fail 的过期守卫：上报 revision 落后于当前版本时
    /// 不回滚、不覆盖新下发内容（防止过期失败上报吞掉管理员刚保存的
    /// 配置）；匹配当前版本时正常回滚到 last_good。
    #[test]
    fn report_fail_stale_revision_is_ignored() {
        let repo = temp_repo();
        let net = repo.create_network("n", "10.9.1.0/24").unwrap();
        let token = repo.create_token(net.id, 5, 86_400_000, None).unwrap();
        let dev = repo
            .enroll(&token.token, "a", &"aa".repeat(32), &"bb".repeat(32), None)
            .unwrap();

        let s1 = repo.set_device_settings(dev.device_id, &settings_with_socks(1111)).unwrap();
        repo.mark_settings_applied(dev.device_id, s1.revision).unwrap();
        let s2 = repo.set_device_settings(dev.device_id, &settings_with_socks(2222)).unwrap();
        let s3 = repo.set_device_settings(dev.device_id, &settings_with_socks(3333)).unwrap();
        assert_eq!((s2.revision, s3.revision), (2, 3));

        // 过期上报（rev2）：当前已是 rev3，忽略。
        assert!(repo.report_settings_fail(dev.device_id, 2, "stale").unwrap().is_none());
        assert_eq!(
            repo.get_device_settings(dev.device_id).unwrap().socks_listen,
            Some("127.0.0.1:3333".into()),
            "过期上报不得覆盖新下发内容"
        );

        // 匹配当前版本（rev3）：回滚到 last_good（rev1 内容）、revision 递增。
        let rolled = repo.report_settings_fail(dev.device_id, 3, "boom").unwrap().expect("当前版本应回滚");
        assert_eq!(rolled.revision, 4);
        assert_eq!(rolled.socks_listen, Some("127.0.0.1:1111".into()));
        let cur = repo.get_device_settings(dev.device_id).unwrap();
        assert_eq!(cur.revision, 4);
        assert_eq!(cur.socks_listen, Some("127.0.0.1:1111".into()));
    }
}
