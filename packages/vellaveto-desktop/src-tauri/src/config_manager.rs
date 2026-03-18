//! AI tool config detection and MCP server wrapping.
//!
//! Knows where every AI tool stores its MCP configuration,
//! detects installed tools, and wraps MCP servers with vellaveto-proxy.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// An AI tool installation detected on the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTool {
    pub name: String,
    pub installed: bool,
    pub config_path: Option<PathBuf>,
    pub mcp_servers: Vec<McpServerEntry>,
    pub protected: bool,
    pub risk_warnings: Vec<String>,
}

/// An MCP server entry from a tool's config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub protected: bool,
}

/// Protection level.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProtectionLevel {
    Shield,
    Fortress,
    Vault,
}

impl ProtectionLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shield => "shield",
            Self::Fortress => "fortress",
            Self::Vault => "vault",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Shield => "Blocks credential theft, data exfiltration, config injection, and dangerous commands. Your AI tools keep working normally.",
            Self::Fortress => "Everything in Shield plus system file protection, package config tampering, privilege escalation approval, and memory tracking.",
            Self::Vault => "Maximum security. Deny-by-default. Only safe reads are allowed. File writes and commands require explicit approval.",
        }
    }
}

/// Get config paths for known AI tools.
fn tool_config_paths() -> Vec<(&'static str, Vec<PathBuf>)> {
    let home = dirs::home_dir().unwrap_or_default();
    #[allow(unused_variables)]
    let config_dir = dirs::config_dir().unwrap_or_default();

    vec![
        (
            "Claude Desktop",
            vec![
                #[cfg(target_os = "macos")]
                home.join("Library/Application Support/Claude/claude_desktop_config.json"),
                #[cfg(target_os = "windows")]
                config_dir.join("Claude/claude_desktop_config.json"),
                #[cfg(target_os = "linux")]
                home.join(".config/Claude/claude_desktop_config.json"),
            ],
        ),
        (
            "Claude Code",
            vec![
                home.join(".claude.json"),
                home.join(".claude/settings.json"),
            ],
        ),
        (
            "Cursor",
            vec![
                home.join(".cursor/mcp.json"),
            ],
        ),
        (
            "Windsurf",
            vec![
                home.join(".codeium/windsurf/mcp_config.json"),
            ],
        ),
        (
            "VS Code (Copilot)",
            vec![
                #[cfg(target_os = "macos")]
                home.join("Library/Application Support/Code/User/settings.json"),
                #[cfg(target_os = "windows")]
                config_dir.join("Code/User/settings.json"),
                #[cfg(target_os = "linux")]
                home.join(".config/Code/User/settings.json"),
            ],
        ),
        (
            "OpenAI Codex CLI",
            vec![
                home.join(".codex/config.json"),
                home.join(".config/codex/config.json"),
            ],
        ),
        (
            "Zed",
            vec![
                #[cfg(target_os = "macos")]
                home.join("Library/Application Support/Zed/settings.json"),
                #[cfg(target_os = "linux")]
                home.join(".config/zed/settings.json"),
            ],
        ),
        (
            "Continue",
            vec![
                home.join(".continue/config.json"),
            ],
        ),
        (
            "Cline (VS Code)",
            vec![
                home.join(".cline/mcp_settings.json"),
                #[cfg(target_os = "macos")]
                home.join("Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
                #[cfg(target_os = "linux")]
                home.join(".config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"),
            ],
        ),
        (
            "Roo Code (VS Code)",
            vec![
                #[cfg(target_os = "macos")]
                home.join("Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"),
                #[cfg(target_os = "linux")]
                home.join(".config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"),
            ],
        ),
        (
            "Amazon Q Developer",
            vec![
                home.join(".aws/amazonq/mcp.json"),
            ],
        ),
        (
            "JetBrains AI",
            vec![
                home.join(".config/JetBrains/mcp.json"),
            ],
        ),
    ]
}

/// Detect all installed AI tools and their MCP configurations.
pub fn detect_tools() -> Vec<DetectedTool> {
    let mut tools = Vec::new();

    for (name, config_paths) in tool_config_paths() {
        let mut found_path = None;
        for path in &config_paths {
            if path.exists() {
                found_path = Some(path.clone());
                break;
            }
        }

        let (installed, mcp_servers, risk_warnings) = if let Some(ref path) = found_path {
            let (servers, risks) = parse_mcp_config(path);
            (true, servers, risks)
        } else {
            (false, Vec::new(), Vec::new())
        };

        let protected = mcp_servers.iter().all(|s| s.protected);

        tools.push(DetectedTool {
            name: name.to_string(),
            installed,
            config_path: found_path,
            mcp_servers,
            protected: protected && installed,
            risk_warnings,
        });
    }

    tools
}

/// Parse an MCP config file and extract server entries.
fn parse_mcp_config(path: &Path) -> (Vec<McpServerEntry>, Vec<String>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (Vec::new(), vec!["Cannot read config file".to_string()]),
    };

    let config: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return (Vec::new(), vec!["Invalid JSON in config file".to_string()]),
    };

    let mut servers = Vec::new();
    let mut risks = Vec::new();

    // Support multiple config formats:
    // - Claude Desktop / Cursor / Windsurf: { "mcpServers": { ... } }
    // - Cline / Roo Code: { "mcpServers": { ... } }
    // - VS Code Copilot: { "mcp": { "servers": { ... } } }
    // - Continue: { "mcpServers": { ... } } or { "models": [...] }
    // - Codex: { "mcpServers": { ... } }
    // - Generic: { "mcp_servers": { ... } }
    let mcp_servers = config
        .get("mcpServers")
        .or_else(|| config.get("mcp_servers"))
        .or_else(|| config.pointer("/mcp/servers"))
        .and_then(|v| v.as_object());

    if let Some(server_map) = mcp_servers {
        for (name, entry) in server_map {
            let command = entry
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let args: Vec<String> = entry
                .get("args")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let protected = command.contains("vellaveto-proxy")
                || args.iter().any(|a| a.contains("vellaveto-proxy"));

            // Risk analysis
            if name.contains("filesystem") || command.contains("filesystem") {
                let has_root = args.iter().any(|a| a == "/" || a == "~" || a.starts_with("/home"));
                if has_root {
                    risks.push(format!(
                        "⚠ '{}' has broad file system access",
                        name
                    ));
                }
            }
            if command.contains("npx") && !protected {
                risks.push(format!(
                    "⚠ '{}' uses npx without protection (supply chain risk)",
                    name
                ));
            }

            servers.push(McpServerEntry {
                name: name.clone(),
                command,
                args,
                protected,
            });
        }
    }

    (servers, risks)
}

/// Protect a tool by wrapping its MCP servers with vellaveto-proxy.
pub fn protect_tool(
    config_path: &Path,
    level: ProtectionLevel,
    proxy_binary: &str,
) -> Result<(), String> {
    // Read current config
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| format!("Cannot read config: {e}"))?;

    // Backup
    let backup_path = config_path.with_extension("json.vellaveto-backup");
    if !backup_path.exists() {
        std::fs::write(&backup_path, &content)
            .map_err(|e| format!("Cannot create backup: {e}"))?;
    }

    let mut config: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid JSON: {e}"))?;

    // Find the MCP servers key — try mcpServers first, then mcp_servers, then mcp.servers.
    let server_key = if config.get("mcpServers").is_some() {
        "mcpServers"
    } else if config.get("mcp_servers").is_some() {
        "mcp_servers"
    } else {
        return Err("No mcpServers found in config".to_string());
    };
    let mcp_servers = config
        .get_mut(server_key)
        .and_then(|v| v.as_object_mut())
        .ok_or_else(|| "No mcpServers found in config".to_string())?;

    for (_name, entry) in mcp_servers.iter_mut() {
        let obj = entry.as_object_mut().ok_or("Invalid server entry")?;

        // Skip if already protected
        let current_cmd = obj
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if current_cmd.contains("vellaveto-proxy") {
            continue;
        }

        let original_command = current_cmd.to_string();
        let original_args: Vec<String> = obj
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        // Rewrite: command → vellaveto-proxy, args → [--protect, level, --, original_command, ...original_args]
        let mut new_args = vec![
            "--protect".to_string(),
            level.as_str().to_string(),
            "--".to_string(),
            original_command,
        ];
        new_args.extend(original_args);

        obj.insert(
            "command".to_string(),
            serde_json::Value::String(proxy_binary.to_string()),
        );
        obj.insert(
            "args".to_string(),
            serde_json::to_value(&new_args).unwrap_or_default(),
        );
    }

    // Write modified config
    let output = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Cannot serialize config: {e}"))?;
    std::fs::write(config_path, output)
        .map_err(|e| format!("Cannot write config: {e}"))?;

    Ok(())
}

/// Unprotect a tool by restoring the backup config.
pub fn unprotect_tool(config_path: &Path) -> Result<(), String> {
    let backup_path = config_path.with_extension("json.vellaveto-backup");
    if !backup_path.exists() {
        return Err("No backup found — cannot unprotect".to_string());
    }

    std::fs::copy(&backup_path, config_path)
        .map_err(|e| format!("Cannot restore backup: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_claude_config() {
        let config = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
                }
            }
        }"#;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(config.as_bytes()).unwrap();

        let (servers, risks) = parse_mcp_config(f.path());
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].name, "filesystem");
        assert!(!servers[0].protected);
        assert!(!risks.is_empty()); // npx warning
    }

    #[test]
    fn test_parse_already_protected() {
        let config = r#"{
            "mcpServers": {
                "filesystem": {
                    "command": "vellaveto-proxy",
                    "args": ["--protect", "shield", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
                }
            }
        }"#;
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(config.as_bytes()).unwrap();

        let (servers, _) = parse_mcp_config(f.path());
        assert!(servers[0].protected);
    }

    #[test]
    fn test_protect_and_unprotect() {
        let config = r#"{
            "mcpServers": {
                "test": {
                    "command": "echo",
                    "args": ["hello"]
                }
            }
        }"#;
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        std::fs::write(&config_path, config).unwrap();

        // Protect
        protect_tool(&config_path, ProtectionLevel::Shield, "vellaveto-proxy").unwrap();

        let protected: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        let cmd = protected["mcpServers"]["test"]["command"]
            .as_str()
            .unwrap();
        assert_eq!(cmd, "vellaveto-proxy");

        let args: Vec<String> = protected["mcpServers"]["test"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(args.contains(&"--protect".to_string()));
        assert!(args.contains(&"shield".to_string()));
        assert!(args.contains(&"echo".to_string()));

        // Unprotect
        unprotect_tool(&config_path).unwrap();
        let restored: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(
            restored["mcpServers"]["test"]["command"].as_str().unwrap(),
            "echo"
        );
    }

    #[test]
    fn test_protection_levels() {
        assert_eq!(ProtectionLevel::Shield.as_str(), "shield");
        assert_eq!(ProtectionLevel::Fortress.as_str(), "fortress");
        assert_eq!(ProtectionLevel::Vault.as_str(), "vault");
        assert!(!ProtectionLevel::Shield.description().is_empty());
    }
}
