use crate::security::SecurityManager;
use anyhow::{anyhow, Context, Result};
use directories::ProjectDirs;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Machine {
    pub id: Option<i64>,
    pub name: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub purpose: String,
    pub ownership: String,
    pub os_type: String,
    pub status: String,
    pub boot_delay: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub id: Option<i64>,
    pub machine_id: i64,
    pub username: String,
    pub auth_type: String, // "password", "key"
    pub credential: String,
}

pub struct ManagerDb {
    path: PathBuf,
    security: SecurityManager,
    master_key: [u8; 32],
}

impl ManagerDb {
    pub fn new() -> Result<Self> {
        let path = Self::get_db_path()?;
        if !path.exists() {
            return Err(anyhow!("mcp-ssh-manager database not found at {:?}", path));
        }
        let security = SecurityManager::new("mcp-ssh-manager");
        let master_key = security
            .get_or_create_master_key()
            .context("Failed to initialize master key from keyring")?;

        Ok(ManagerDb {
            path,
            security,
            master_key,
        })
    }

    fn get_conn(&self) -> Result<Connection> {
        Ok(Connection::open(&self.path)?)
    }

    fn get_db_path() -> Result<PathBuf> {
        let proj_dirs = ProjectDirs::from("com", "veltrea", "mcp-ssh-manager")
            .ok_or_else(|| anyhow!("Could not determine project directories"))?;
        Ok(proj_dirs.data_dir().join("manager.db"))
    }

    pub fn get_machine_by_alias(&self, alias: &str) -> Result<Option<Machine>> {
        let conn = self.get_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, ip_address, mac_address, hostname, purpose, ownership, os_type, status, boot_delay 
             FROM machines WHERE name = ?1 LIMIT 1",
        )?;

        let mut rows = stmt.query(params![alias])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Machine {
                id: Some(row.get(0)?),
                name: row.get(1)?,
                ip_address: row.get(2)?,
                mac_address: row.get(3)?,
                hostname: row.get(4)?,
                purpose: row.get(5)?,
                ownership: row.get(6)?,
                os_type: row.get(7)?,
                status: row.get(8)?,
                boot_delay: row.get(9)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn get_account_for_machine(&self, machine_id: i64) -> Result<Option<Account>> {
        let conn = self.get_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, machine_id, username, auth_type, credential FROM accounts WHERE machine_id = ?1 ORDER BY id ASC LIMIT 1",
        )?;

        let mut rows = stmt.query(params![machine_id])?;
        if let Some(row) = rows.next()? {
            let mut account = Account {
                id: Some(row.get(0)?),
                machine_id: row.get(1)?,
                username: row.get(2)?,
                auth_type: row.get(3)?,
                credential: row.get(4)?,
            };

            // Decrypt the credential
            // Fix: propagate error instead of swallowing it
            let decrypted = self
                .security
                .decrypt(&self.master_key, &account.credential)
                .context("Failed to decrypt account credential")?;
            account.credential = decrypted;

            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    pub fn get_constraints(&self, machine_id: i64) -> Result<Vec<String>> {
        let conn = self.get_conn()?;
        let mut stmt = conn.prepare("SELECT rule_text FROM constraints WHERE machine_id = ?1")?;
        let rows = stmt.query_map(params![machine_id], |row| row.get(0))?;

        let mut constraints = Vec::new();
        for rule in rows {
            constraints.push(rule?);
        }
        Ok(constraints)
    }

    pub fn log_execution(
        &self,
        machine_id: i64,
        username: &str,
        command: &str,
        stdout: &str,
        stderr: &str,
        exit_code: i32,
    ) -> Result<()> {
        let conn = self.get_conn()?;
        conn.execute(
            "INSERT INTO command_logs (machine_id, username, command, stdout, stderr, exit_code)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![machine_id, username, command, stdout, stderr, exit_code],
        )?;
        Ok(())
    }

    pub fn get_recent_failures(&self, machine_id: i64, limit: i32) -> Result<i32> {
        let conn = self.get_conn()?;
        let mut stmt = conn.prepare(
            "SELECT COUNT(*) FROM (
                SELECT exit_code FROM command_logs 
                WHERE machine_id = ?1 
                ORDER BY timestamp DESC 
                LIMIT ?2
            ) WHERE exit_code != 0",
        )?;
        let count: i32 = stmt.query_row(params![machine_id, limit], |row| row.get(0))?;
        Ok(count)
    }
}
