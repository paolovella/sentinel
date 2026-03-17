//! VellaVeto Desktop — Tauri v2 backend.
//!
//! Exposes IPC commands to the frontend for:
//! - Detecting installed AI tools
//! - Protecting/unprotecting tools
//! - Polling notifications
//! - Getting activity feed

pub mod config_manager;
pub mod notification_bridge;

use config_manager::{DetectedTool, ProtectionLevel};
use notification_bridge::ProxyNotification;
use std::sync::Mutex;
use tauri::State;

/// Shared application state.
pub struct AppState {
    notification_watcher: Mutex<Option<notification_bridge::NotificationWatcher>>,
    recent_notifications: Mutex<Vec<ProxyNotification>>,
}

impl Default for AppState {
    fn default() -> Self {
        let notif_path = notification_bridge::default_notification_path();
        // Ensure parent directory exists
        if let Some(parent) = notif_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self {
            notification_watcher: Mutex::new(Some(
                notification_bridge::NotificationWatcher::new(notif_path),
            )),
            recent_notifications: Mutex::new(Vec::new()),
        }
    }
}

/// IPC: Detect installed AI tools.
#[tauri::command]
fn detect_tools() -> Vec<DetectedTool> {
    config_manager::detect_tools()
}

/// IPC: Protect a specific tool.
#[tauri::command]
fn protect_tool(config_path: String, level: String) -> Result<(), String> {
    let level = match level.as_str() {
        "fortress" => ProtectionLevel::Fortress,
        "vault" => ProtectionLevel::Vault,
        _ => ProtectionLevel::Shield,
    };
    let proxy_binary = find_proxy_binary();
    config_manager::protect_tool(
        std::path::Path::new(&config_path),
        level,
        &proxy_binary,
    )
}

/// IPC: Unprotect a specific tool.
#[tauri::command]
fn unprotect_tool(config_path: String) -> Result<(), String> {
    config_manager::unprotect_tool(std::path::Path::new(&config_path))
}

/// IPC: Protect all detected tools.
#[tauri::command]
fn protect_all(level: String) -> Result<usize, String> {
    let tools = config_manager::detect_tools();
    let level_enum = match level.as_str() {
        "fortress" => ProtectionLevel::Fortress,
        "vault" => ProtectionLevel::Vault,
        _ => ProtectionLevel::Shield,
    };
    let proxy_binary = find_proxy_binary();
    let mut count = 0;
    for tool in &tools {
        if tool.installed && !tool.protected {
            if let Some(ref path) = tool.config_path {
                if config_manager::protect_tool(path, level_enum, &proxy_binary).is_ok() {
                    count += 1;
                }
            }
        }
    }
    Ok(count)
}

/// IPC: Poll for new notifications.
#[tauri::command]
fn poll_notifications(state: State<'_, AppState>) -> Vec<ProxyNotification> {
    let mut watcher = state.notification_watcher.lock().unwrap_or_else(|e| e.into_inner());
    let new_events = watcher
        .as_mut()
        .map(|w| w.poll())
        .unwrap_or_default();

    if !new_events.is_empty() {
        let mut recent = state.recent_notifications.lock().unwrap_or_else(|e| e.into_inner());
        recent.extend(new_events.clone());
        // Keep last 200 notifications
        if recent.len() > 200 {
            let drain_count = recent.len() - 200;
            recent.drain(..drain_count);
        }
    }

    new_events
}

/// IPC: Get recent notification history.
#[tauri::command]
fn get_activity(state: State<'_, AppState>) -> Vec<ProxyNotification> {
    state
        .recent_notifications
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// IPC: Get protection level descriptions.
#[tauri::command]
fn get_protection_levels() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "id": "shield",
            "name": "Shield",
            "description": ProtectionLevel::Shield.description(),
        }),
        serde_json::json!({
            "id": "fortress",
            "name": "Fortress",
            "description": ProtectionLevel::Fortress.description(),
        }),
        serde_json::json!({
            "id": "vault",
            "name": "Vault",
            "description": ProtectionLevel::Vault.description(),
        }),
    ]
}

/// Find the bundled vellaveto-proxy binary.
fn find_proxy_binary() -> String {
    // In Tauri bundle, the binary is in the same directory as the app
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let proxy = dir.join("vellaveto-proxy");
            if proxy.exists() {
                return proxy.to_string_lossy().to_string();
            }
            // macOS .app bundle
            let macos_proxy = dir.join("../Resources/vellaveto-proxy");
            if macos_proxy.exists() {
                return macos_proxy.to_string_lossy().to_string();
            }
        }
    }
    // Fallback to PATH
    "vellaveto-proxy".to_string()
}

/// Build the Tauri application.
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            detect_tools,
            protect_tool,
            unprotect_tool,
            protect_all,
            poll_notifications,
            get_activity,
            get_protection_levels,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VellaVeto Desktop");
}
