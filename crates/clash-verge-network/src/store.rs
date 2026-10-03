use crate::{AppRoutingPolicy, ConnectionHistory, HistoryLimits, NetworkPolicy};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read as _, Write as _},
    path::Path,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkStore {
    pub schema_version: u32,
    pub policy: NetworkPolicy,
    pub recording_enabled: bool,
    pub limits: HistoryLimits,
    pub history: ConnectionHistory,
    #[serde(default)]
    pub app_routes: AppRoutingPolicy,
    #[serde(default)]
    pub active_app_routes: Option<AppRoutingPolicy>,
    #[serde(default)]
    pub active_app_route_profile: Option<String>,
    #[serde(default)]
    pub active_app_route_slots: bool,
}

impl Default for NetworkStore {
    fn default() -> Self {
        Self {
            schema_version: 1,
            policy: NetworkPolicy::default(),
            recording_enabled: false,
            limits: HistoryLimits::default(),
            history: ConnectionHistory::default(),
            app_routes: AppRoutingPolicy::default(),
            active_app_routes: None,
            active_app_route_profile: None,
            active_app_route_slots: false,
        }
    }
}

impl NetworkStore {
    pub fn load(path: &Path, now: u64) -> Result<Self, String> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let file = fs::File::open(path).map_err(|error| error.to_string())?;
        let mut data = Vec::new();
        file.take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut data)
            .map_err(|error| error.to_string())?;
        if data.len() > 64 * 1024 * 1024 {
            return Err("Network history file exceeds the supported size".to_owned());
        }
        let mut store: Self = serde_json::from_slice(&data).map_err(|error| error.to_string())?;
        if store.schema_version != 1 {
            return Err("Unsupported network store schema".to_owned());
        }
        store.policy.validate()?;
        store.app_routes.validate()?;
        if let Some(active) = &store.active_app_routes {
            active.validate()?;
        }
        store.limits.validate()?;
        store.history.interrupt(now, store.recording_enabled);
        store.history.prune(now, &store.limits);
        store.history.prune_to_bytes(32 * 1024 * 1024);
        Ok(store)
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if encoded.len() > 64 * 1024 * 1024 {
            return Err("Network workspace exceeds the supported file size; existing file preserved".to_owned());
        }
        let parent = path
            .parent()
            .ok_or_else(|| "Network history directory unavailable".to_owned())?;
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|error| error.to_string())?;
        }
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temporary = parent.join(format!(".network-{}-{nonce}.tmp", std::process::id()));
        let result = (|| {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary).map_err(|error| error.to_string())?;
            file.write_all(&encoded).map_err(|error| error.to_string())?;
            file.flush().map_err(|error| error.to_string())?;
            file.sync_all().map_err(|error| error.to_string())?;
            fs::rename(&temporary, path).map_err(|error| error.to_string())?;
            #[cfg(unix)]
            fs::File::open(parent)
                .and_then(|file| file.sync_all())
                .map_err(|error| error.to_string())?;
            Ok(())
        })();
        if temporary.exists() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn replace_policy(&mut self, mut policy: NetworkPolicy, expected_generation: u64) -> Result<(), String> {
        if self.policy.generation != expected_generation || policy.generation != expected_generation {
            return Err("Policy generation changed; reload before saving".to_owned());
        }
        policy.validate()?;
        policy.generation = expected_generation
            .checked_add(1)
            .ok_or_else(|| "Policy generation exhausted".to_owned())?;
        self.policy = policy;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_generation_is_compare_and_swap_and_roundtrips_privately() -> Result<(), String> {
        let directory = std::env::temp_dir().join(format!(
            "verge-network-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = directory.join("workspace.json");
        let mut store = NetworkStore::default();
        store.replace_policy(NetworkPolicy::default(), 0)?;
        assert_eq!(store.policy.generation, 1);
        assert!(store.replace_policy(NetworkPolicy::default(), 0).is_err());
        store.save(&path)?;
        let loaded = NetworkStore::load(&path, 1000)?;
        assert_eq!(loaded.policy.generation, 1);
        assert!(!loaded.recording_enabled);
        assert!(!loaded.active_app_route_slots);
        let mut legacy = serde_json::to_value(&store).map_err(|error| error.to_string())?;
        legacy
            .as_object_mut()
            .ok_or("Expected store object")?
            .remove("activeAppRouteSlots");
        assert!(
            !serde_json::from_value::<NetworkStore>(legacy)
                .map_err(|error| error.to_string())?
                .active_app_route_slots
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&path)
                    .map(|metadata| metadata.permissions().mode() & 0o777)
                    .unwrap_or(0),
                0o600
            );
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&directory);
        Ok(())
    }
}
