use crate::AppBanPolicy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppRouteRule {
    pub process_path: String,
    pub route: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppRoutingPolicy {
    pub schema_version: u32,
    pub generation: u64,
    pub enabled: bool,
    pub default_route: String,
    pub routes: Vec<AppRouteRule>,
}

impl Default for AppRoutingPolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            generation: 0,
            enabled: false,
            default_route: "DIRECT".to_owned(),
            routes: Vec::new(),
        }
    }
}

fn safe_field(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2048
        && value.trim() == value
        && !value.contains(',')
        && !value.chars().any(char::is_control)
}

impl AppRoutingPolicy {
    pub fn validate(&self) -> Result<(), String> {
        (AppBanPolicy {
            schema_version: self.schema_version,
            generation: self.generation,
            process_paths: self.routes.iter().map(|rule| rule.process_path.clone()).collect(),
        })
        .validate()?;
        if !safe_field(&self.default_route)
            || self
                .routes
                .iter()
                .any(|rule| !safe_field(&rule.process_path) || !safe_field(&rule.route))
        {
            return Err(
                "App routing paths and route names cannot contain commas, surrounding whitespace or control characters"
                    .to_owned(),
            );
        }
        Ok(())
    }

    pub fn compile(&self, available: &BTreeSet<String>) -> Result<Vec<String>, String> {
        self.validate()?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        let target = |name: &str| {
            if name == "DIRECT" || available.contains(name) {
                name.to_owned()
            } else {
                "REJECT".to_owned()
            }
        };
        let mut rules: Vec<String> = self
            .routes
            .iter()
            .map(|rule| format!("PROCESS-PATH,{},{}", rule.process_path, target(&rule.route)))
            .collect();
        rules.push(format!("MATCH,{}", target(&self.default_route)));
        Ok(rules)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_routes_have_explicit_default_and_missing_targets_reject_instead_of_falling_back() -> Result<(), String> {
        let mut policy = AppRoutingPolicy {
            enabled: true,
            default_route: "VPN-B".to_owned(),
            routes: vec![
                AppRouteRule {
                    process_path: "/usr/bin/curl".to_owned(),
                    route: "VPN-A".to_owned(),
                },
                AppRouteRule {
                    process_path: "/usr/bin/ssh".to_owned(),
                    route: "Gone".to_owned(),
                },
            ],
            ..Default::default()
        };
        assert_eq!(
            policy.compile(&BTreeSet::from(["VPN-A".to_owned(), "VPN-B".to_owned()]))?,
            vec![
                "PROCESS-PATH,/usr/bin/curl,VPN-A",
                "PROCESS-PATH,/usr/bin/ssh,REJECT",
                "MATCH,VPN-B"
            ]
        );
        policy.routes[0].process_path = "/tmp/a,REJECT".to_owned();
        assert!(policy.validate().is_err());
        policy.routes.clear();
        policy.default_route = "x,REJECT".to_owned();
        assert!(policy.validate().is_err());
        Ok(())
    }
}
