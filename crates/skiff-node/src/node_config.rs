//! The single node configuration file (starskiff.json): behaviour settings
//! (plain, hand-editable) + field-sealed identity + per-network entries.
//! Sensitive fields are sealed per-value by the `Secret` serde layer.

use std::path::Path;

use skiff_core::models::NodeConfig;

pub fn load(path: &Path) -> Result<NodeConfig, String> {
    NodeConfig::load(path)
}

pub fn save(path: &Path, cfg: &NodeConfig) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| format!("配置序列化失败: {e}"))?;
    std::fs::write(path, json).map_err(|e| format!("无法写入 {}: {e}", path.display()))
}
