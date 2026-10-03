use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppBanPolicy {
    pub schema_version: u32,
    pub generation: u64,
    pub process_paths: Vec<String>,
}

impl AppBanPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.process_paths.len() > 512 {
            return Err("App bans require schema 1 and at most 512 executable paths".to_owned());
        }
        let mut unique = BTreeSet::new();
        for path in &self.process_paths {
            let absolute = path.starts_with('/')
                || (path.as_bytes().get(1) == Some(&b':')
                    && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
                    && path.as_bytes().get(2) == Some(&b'\\'));
            if !absolute
                || path.len() > 2048
                || path.chars().any(char::is_control)
                || path.split(['/', '\\']).any(|part| matches!(part, "." | ".."))
                || !unique.insert(path)
            {
                return Err(
                    "App bans require unique absolute executable paths without traversal or control characters"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    pub fn replace(&self, process_path: String, blocked: bool, expected_generation: u64) -> Result<Self, String> {
        self.validate()?;
        if self.generation != expected_generation {
            return Err("Native ban generation changed; refresh before applying".to_owned());
        }
        let mut next = self.clone();
        next.process_paths.retain(|path| path != &process_path);
        if blocked {
            next.process_paths.push(process_path);
        }
        next.process_paths.sort();
        next.generation = expected_generation
            .checked_add(1)
            .ok_or_else(|| "Native ban generation exhausted".to_owned())?;
        next.validate()?;
        Ok(next)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeAdapterStatus {
    pub schema_version: u32,
    pub platform: String,
    pub installed: bool,
    pub active: bool,
    pub authenticated: bool,
    pub policy_initialized: bool,
    pub monitoring: bool,
    #[serde(default)]
    pub event_sequence: u64,
    #[serde(default)]
    pub dropped_events: u64,
    pub generation: u64,
    pub process_paths: Vec<String>,
    pub instance_id: String,
    pub existing_flow_behavior: String,
    pub reason: String,
}

impl NativeAdapterStatus {
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            schema_version: 1,
            platform: std::env::consts::OS.to_owned(),
            installed: false,
            active: false,
            authenticated: false,
            policy_initialized: false,
            monitoring: false,
            event_sequence: 0,
            dropped_events: 0,
            generation: 0,
            process_paths: Vec::new(),
            instance_id: String::new(),
            existing_flow_behavior: "unavailable".to_owned(),
            reason: reason.into(),
        }
    }

    pub fn can_apply_bans(&self) -> bool {
        self.can_configure_bans() && self.policy_initialized
    }

    pub fn can_configure_bans(&self) -> bool {
        self.installed
            && self.active
            && self.authenticated
            && !self.instance_id.is_empty()
            && self.instance_id.len() <= 128
            && matches!(self.existing_flow_behavior.as_str(), "drop" | "new_flows_only")
            && (AppBanPolicy {
                schema_version: self.schema_version,
                generation: self.generation,
                process_paths: self.process_paths.clone(),
            })
            .validate()
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bans_are_separate_cas_policies_and_never_ready_from_a_saved_path() -> Result<(), String> {
        let initial = AppBanPolicy {
            schema_version: 1,
            ..Default::default()
        };
        let blocked = initial.replace("/Applications/Test.app/Contents/MacOS/Test".to_owned(), true, 0)?;
        assert_eq!(blocked.generation, 1);
        assert!(blocked.replace("/bin/test".to_owned(), true, 0).is_err());
        assert!(initial.replace("/bin/../test".to_owned(), true, 0).is_err());
        assert!(initial.replace("relative.exe".to_owned(), true, 0).is_err());
        let unblocked = blocked.replace(blocked.process_paths[0].clone(), false, 1)?;
        assert!(unblocked.process_paths.is_empty());
        let mut status = NativeAdapterStatus::unavailable("Not installed");
        status.process_paths = blocked.process_paths;
        assert!(!status.can_apply_bans());
        status.installed = true;
        status.active = true;
        status.authenticated = true;
        status.policy_initialized = true;
        status.instance_id = "native-instance".to_owned();
        status.existing_flow_behavior = "new_flows_only".to_owned();
        assert!(status.can_apply_bans());
        status.authenticated = false;
        assert!(!status.can_apply_bans());
        Ok(())
    }
}
