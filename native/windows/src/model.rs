// SPDX-License-Identifier: GPL-3.0-only
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_MESSAGE: usize = 1024 * 1024;
pub const MAX_PATHS: usize = 512;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppBanPolicy {
    pub schema_version: u32,
    pub generation: u64,
    pub process_paths: Vec<String>,
}

impl AppBanPolicy {
    pub fn validate(&self, expected: u64) -> Result<(), String> {
        if self.schema_version != 1 || self.generation != expected.saturating_add(1) || expected == u64::MAX {
            return Err("App-ban policy requires schemaVersion 1 and the next CAS generation".into());
        }
        if self.process_paths.len() > MAX_PATHS {
            return Err("App-ban policy exceeds 512 executable paths".into());
        }
        let mut unique = HashSet::new();
        for path in &self.process_paths {
            let bytes = path.as_bytes();
            let absolute = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
            if !absolute
                || path.len() > 2048
                || path.split(['/', '\\']).any(|part| matches!(part, "." | ".."))
                || path.chars().any(|c| c.is_control() || c == '*' || c == '?' || c == '"')
                || !unique.insert(path.to_lowercase())
            {
                return Err(
                    "Each ban must be a unique absolute drive-letter executable path; no wildcards or device paths"
                        .into(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyRequest {
    pub policy: AppBanPolicy,
    pub expected_generation: u64,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventsRequest {
    #[serde(default)]
    pub after_sequence: u64,
    #[serde(default = "default_limit")]
    pub limit: usize,
}
fn default_limit() -> usize {
    100
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_stale_and_non_executable_selectors() {
        let mut policy = AppBanPolicy {
            schema_version: 1,
            generation: 2,
            process_paths: vec![r"C:\Program Files\App\app.exe".into()],
        };
        assert!(policy.validate(1).is_ok());
        assert!(policy.validate(2).is_err());
        for path in [
            "app.exe",
            r"\\.\device",
            r"\\?\C:\Apps\a.exe",
            r"C:\Apps\*.exe",
            r"C:\Apps\..\a.exe",
            "C:\\Apps\\a.exe\n",
        ] {
            policy.process_paths = vec![path.into()];
            assert!(policy.validate(1).is_err());
        }
        policy.process_paths = vec![r"C:\Apps\app.exe".into(), r"c:\apps\APP.exe".into()];
        assert!(policy.validate(1).is_err());
        assert!(policy.validate(u64::MAX).is_err());
    }
}
