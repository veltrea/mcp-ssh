mod manager_db;
mod security;
mod ssh_exec;
use crate::manager_db::ManagerDb;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

#[derive(Parser)]
#[command(name = "mcp-ssh")]
#[command(about = "SSH adapter for AI agents with safety constraints", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a command on a remote host (alias required)
    Exec {
        /// Machine alias
        alias: String,
        /// Command to execute
        command: String,
    },
    /// Get host information and constraints
    Info {
        /// Machine alias
        alias: String,
    },
    /// Run as a JSON-RPC MCP server (default)
    Mcp,
}

#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: Option<Value>,
    id: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    result: Option<Value>,
    error: Option<Value>,
    id: Option<Value>,
}

const METHOD_NOT_FOUND_MESSAGE: &str = "Method not found";

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Exec { alias, command }) => {
            let args = json!({ "alias": alias, "command": command });
            let res = handle_ssh_exec(&args).await?;
            println!("{}", serde_json::to_string_pretty(&res)?);
            return Ok(());
        }
        Some(Commands::Info { alias }) => {
            let args = json!({ "alias": alias });
            let res = handle_get_host_info(&args).await?;
            println!("{}", serde_json::to_string_pretty(&res)?);
            return Ok(());
        }
        Some(Commands::Mcp) | None => {
            // Default: run MCP loop
            let stdin = io::stdin();
            let reader = stdin.lock().lines();

            for line in reader {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }

                match serde_json::from_str::<JsonRpcRequest>(&line) {
                    Ok(req) => {
                        let response = handle_request(req).await;
                        let serialized = serde_json::to_string(&response)?;
                        println!("{}", serialized);
                        io::stdout().flush()?;
                    }
                    Err(e) => {
                        let error_response = JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            result: None,
                            error: Some(
                                json!({ "code": -32700, "message": format!("Parse error: {}", e) }),
                            ),
                            id: None,
                        };
                        let serialized = serde_json::to_string(&error_response)?;
                        println!("{}", serialized);
                        io::stdout().flush()?;
                    }
                }
            }
        }
    }

    Ok(())
}

async fn handle_request(req: JsonRpcRequest) -> JsonRpcResponse {
    let id = req.id.clone();
    let result = match req.method.as_str() {
        "initialize" => Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "mcp-ssh",
                "version": "0.3.0"
            }
        })),
        "notifications/initialized" => Ok(Value::Null),
        "tools/list" => Ok(json!({
            "tools": [
                {
                    "name": "ssh_exec",
                    "description": "Execute a command on a remote host via SSH (alias required).",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "alias": { "type": "string", "description": "Machine alias registered in mcp-ssh-manager" },
                            "command": { "type": "string", "description": "The command to execute" }
                        },
                        "required": ["alias", "command"]
                    }
                },
                {
                    "name": "get_host_info",
                    "description": "Get detailed context and rules for a strict SSH host by alias. Use this BEFORE connecting to understand constraints.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "alias": { "type": "string", "description": "Machine alias" }
                        },
                        "required": ["alias"]
                    }
                }
            ]
        })),
        "tools/call" => {
            if let Some(params) = req.params {
                let name = params.get("name").and_then(|v| v.as_str());
                let arguments = params.get("arguments");

                match (name, arguments) {
                    (Some("ssh_exec"), Some(args)) => handle_ssh_exec(args).await,
                    (Some("get_host_info"), Some(args)) => handle_get_host_info(args).await,
                    _ => Err(anyhow!("Unknown tool or missing arguments")),
                }
            } else {
                Err(anyhow!("Missing params for tools/call"))
            }
        }
        _ => Err(anyhow!(METHOD_NOT_FOUND_MESSAGE)), // Will be mapped to -32601 below
    };

    match result {
        Ok(val) => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            result: Some(val),
            error: None,
            id,
        },
        Err(e) => {
            let message = e.to_string();
            let code = if message == METHOD_NOT_FOUND_MESSAGE {
                -32601
            } else {
                -32603
            };
            JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(json!({ "code": code, "message": message })),
                id,
            }
        }
    }
}

async fn handle_ssh_exec(args: &Value) -> Result<Value> {
    let command = args
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing 'command' argument"))?;

    let alias = args.get("alias").and_then(|v| v.as_str()).ok_or_else(|| {
        anyhow!("Missing 'alias' argument. Direct 'host' connection is NOT allowed.")
    })?;

    execute_direct_via_db(alias, command).await
}

async fn execute_ssh_command(
    host: &str,
    user: &str,
    port: u16,
    key_path: Option<&str>,
    password: Option<&str>,
    command: &str,
) -> Result<(String, String, i32)> {
    ssh_exec::run_command(host, port, user, key_path, password, command)
}

async fn execute_direct_via_db(alias: &str, command: &str) -> Result<Value> {
    let db = ManagerDb::new()?;
    let machine = db
        .get_machine_by_alias(alias)?
        .ok_or_else(|| anyhow!("Machine alias '{}' not found in database", alias))?;
    let machine_id = machine
        .id
        .ok_or_else(|| anyhow!("Machine '{}' has no id in database", alias))?;

    let account = db
        .get_account_for_machine(machine_id)?
        .ok_or_else(|| anyhow!("No account found for machine '{}'", alias))?;

    // Constraints Check
    let constraints = db.get_constraints(machine_id)?;
    if let Err(e) = enforce_constraints(&constraints, command) {
        db.log_execution(
            machine_id,
            &account.username,
            command,
            "",
            &format!("Constraint Violation: {}", e),
            -2,
        )?;
        return Err(e);
    }

    // Perform minimal validation (similar to vlt-ssh)
    if machine.ownership == "company" {
        eprintln!("WARNING: Connecting to a COMPANY machine.");
    }

    // Check for failures and enforce backoff
    let failure_count = db.get_recent_failures(machine_id, 5)?;
    if failure_count > 0 {
        let wait_secs = 2_u64.pow(failure_count as u32);
        eprintln!(
            "Detected {} recent failures. Waiting {} seconds...",
            failure_count, wait_secs
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(wait_secs)).await;
    }

    let key_path = if account.auth_type == "key" {
        Some(account.credential.as_str())
    } else {
        None
    };
    let password = if account.auth_type == "password" {
        Some(account.credential.as_str())
    } else {
        None
    };

    // Execute SSH
    let result = execute_ssh_command(
        &machine.ip_address,
        &account.username,
        22,
        key_path,
        password,
        command,
    )
    .await;

    // Log execution regardless of success/error
    match &result {
        Ok((stdout, stderr, exit_code)) => {
            db.log_execution(
                machine_id,
                &account.username,
                command,
                stdout,
                stderr,
                *exit_code,
            )?;
            Ok(json!({
                "content": [
                    {
                        "type": "text",
                        "text": format!("STDOUT:\n{}\nSTDERR:\n{}", stdout, stderr)
                    }
                ],
                "isError": *exit_code != 0
            }))
        }
        Err(e) => {
            // Log the transport/connection error
            db.log_execution(
                machine_id,
                &account.username,
                command,
                "",
                &format!("SSH Connection Error: {}", e),
                -1, // Custom code for connection failure
            )?;
            Err(anyhow!("SSH execution failed: {}", e))
        }
    }
}

fn enforce_constraints(constraints: &[String], command: &str) -> Result<()> {
    for rule in constraints {
        let rule = rule.trim();
        if rule.is_empty() {
            continue;
        }

        if rule == "read_only" {
            // Block likely write/admin commands when read_only is active.
            let blocked = [
                "rm", "mv", "cp", "dd", "chmod", "chown", "sudo", "nano", "vi", "vim", "tee",
                "touch", "mkdir", "rmdir", "truncate",
            ];
            for b in blocked {
                if command_invokes_word(command, b) {
                    return Err(anyhow!("Constraint Violation: Command '{}' contains blocked keyword '{}' (read_only rule active)", command, b));
                }
            }
            if command.contains('>') {
                return Err(anyhow!(
                    "Constraint Violation: Command '{}' contains shell redirection while read_only is active",
                    command
                ));
            }
        } else {
            return Err(anyhow!(
                "Constraint Violation: Unknown constraint rule '{}' (blocked by fail-close policy)",
                rule
            ));
        }
    }
    Ok(())
}

fn command_invokes_word(command: &str, needle: &str) -> bool {
    tokenize_shell_like(command).iter().any(|token| {
        token == needle
            || token
                .rsplit('/')
                .next()
                .is_some_and(|basename| basename == needle)
    })
}

fn tokenize_shell_like(command: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();

    for ch in command.chars() {
        let is_token_char =
            ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.' || ch == '/';
        if is_token_char {
            current.push(ch.to_ascii_lowercase());
        } else if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
    }

    if !current.is_empty() {
        out.push(current);
    }

    out
}

async fn handle_get_host_info(args: &Value) -> Result<Value> {
    let alias = args
        .get("alias")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Missing 'alias' argument"))?;

    // Internal Generate info from DB
    let db = ManagerDb::new()?;
    let machine = db
        .get_machine_by_alias(alias)?
        .ok_or_else(|| anyhow!("Machine '{}' not found in database", alias))?;
    let machine_id = machine
        .id
        .ok_or_else(|| anyhow!("Machine '{}' has no id in database", alias))?;
    let constraints = db.get_constraints(machine_id)?;

    let mut info = "--- SSH CONTEXT (Internal Fallback) ---\n".to_string();
    info.push_str(&format!("Target Host: {}\n", machine.name));
    info.push_str(&format!("IP Address: {}\n", machine.ip_address));
    info.push_str(&format!("OS Type: {}\n", machine.os_type));
    info.push_str(&format!("Purpose: {}\n", machine.purpose));
    info.push_str(&format!("Ownership: {}\n", machine.ownership));

    info.push_str("\nCONSTRAINTS / RULES:\n");
    if constraints.is_empty() {
        info.push_str("- No specific rules defined.\n");
    } else {
        for rule in constraints {
            info.push_str(&format!("- {}\n", rule));
        }
    }
    info.push_str("--------------------------------------\n");

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": info
            }
        ]
    }))
}

#[cfg(test)]
mod tests {
    use super::enforce_constraints;

    #[test]
    fn read_only_blocks_rm() {
        let constraints = vec!["read_only".to_string()];
        let result = enforce_constraints(&constraints, "rm -rf /tmp/x");
        assert!(result.is_err());
    }

    #[test]
    fn read_only_blocks_redirect() {
        let constraints = vec!["read_only".to_string()];
        let result = enforce_constraints(&constraints, "echo hi > /tmp/file");
        assert!(result.is_err());
    }

    #[test]
    fn read_only_allows_safe_read_command() {
        let constraints = vec!["read_only".to_string()];
        let result = enforce_constraints(&constraints, "ls -la /var/log");
        assert!(result.is_ok());
    }

    #[test]
    fn read_only_does_not_false_positive_on_substring() {
        let constraints = vec!["read_only".to_string()];
        let result = enforce_constraints(&constraints, "systemctl status service");
        assert!(result.is_ok());
    }

    #[test]
    fn unknown_rule_is_blocked() {
        let constraints = vec!["allow_network".to_string()];
        let result = enforce_constraints(&constraints, "ls");
        assert!(result.is_err());
    }
}
