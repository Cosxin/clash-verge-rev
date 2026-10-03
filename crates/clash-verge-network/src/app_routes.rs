use crate::AppBanPolicy;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const APP_ROUTE_SLOT_PREFIX: &str = "NetworkControl-";
pub const APP_ROUTE_DEFAULT_SLOT: &str = "NetworkControl-Default";

pub fn app_route_slot(process_path: &str) -> String {
    let hash = process_path.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x100_0000_01b3)
    });
    format!("{APP_ROUTE_SLOT_PREFIX}App-{hash:016x}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppRouteSlot {
    pub name: String,
    pub selected: String,
    pub children: Vec<String>,
}

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
        let mut slots = BTreeSet::new();
        let mut paths = BTreeSet::new();
        if self.routes.iter().any(|rule| {
            !slots.insert(app_route_slot(&rule.process_path))
                || !paths.insert(rule.process_path.to_lowercase().to_uppercase().to_lowercase())
        }) {
            return Err(
                "Application paths have overlapping case-insensitive identities or selector slot collisions".to_owned(),
            );
        }
        if std::iter::once(&self.default_route)
            .chain(self.routes.iter().map(|rule| &rule.route))
            .any(|route| route.starts_with(APP_ROUTE_SLOT_PREFIX))
        {
            return Err("Managed application routing selectors cannot be assigned as route targets".to_owned());
        }
        Ok(())
    }

    pub fn same_apps(&self, other: &Self) -> bool {
        self.enabled
            && other.enabled
            && self
                .routes
                .iter()
                .map(|rule| &rule.process_path)
                .eq(other.routes.iter().map(|rule| &rule.process_path))
    }

    pub fn managed_rules(&self) -> Result<Vec<String>, String> {
        self.validate()?;
        if !self.enabled {
            return Ok(Vec::new());
        }
        let mut rules = self
            .routes
            .iter()
            .flat_map(|rule| {
                [
                    format!(
                        "PROCESS-PATH,{},{}",
                        rule.process_path,
                        app_route_slot(&rule.process_path)
                    ),
                    format!("PROCESS-PATH,{},REJECT", rule.process_path),
                ]
            })
            .collect::<Vec<_>>();
        rules.push(format!("MATCH,{APP_ROUTE_DEFAULT_SLOT}"));
        rules.push("MATCH,REJECT".to_owned());
        Ok(rules)
    }

    pub fn managed_groups(&self, available: &BTreeSet<String>) -> Result<Vec<AppRouteSlot>, String> {
        self.validate()?;
        if available.iter().any(|name| name.starts_with(APP_ROUTE_SLOT_PREFIX)) {
            return Err(
                "Profile already defines reserved NetworkControl- proxy names; refusing to adopt them".to_owned(),
            );
        }
        if !self.enabled {
            return Ok(Vec::new());
        }
        Ok(self
            .routes
            .iter()
            .map(|rule| (app_route_slot(&rule.process_path), rule.route.as_str()))
            .chain(std::iter::once((
                APP_ROUTE_DEFAULT_SLOT.to_owned(),
                self.default_route.as_str(),
            )))
            .map(|(name, desired)| {
                let selected = if desired == "DIRECT" || available.contains(desired) {
                    desired
                } else {
                    "REJECT"
                };
                let mut children = vec![selected.to_owned()];
                children.extend(available.iter().filter(|child| child.as_str() != selected).cloned());
                if !children.iter().any(|child| child == "DIRECT") {
                    children.push("DIRECT".to_owned());
                }
                if !children.iter().any(|child| child == "REJECT") {
                    children.push("REJECT".to_owned());
                }
                AppRouteSlot {
                    name,
                    selected: selected.to_owned(),
                    children,
                }
            })
            .collect())
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

    #[test]
    fn managed_prefix_is_stable_across_route_changes_and_missing_targets_start_rejected() -> Result<(), String> {
        let mut policy = AppRoutingPolicy {
            enabled: true,
            default_route: "VPN-B".to_owned(),
            routes: vec![AppRouteRule {
                process_path: "/usr/bin/curl".to_owned(),
                route: "VPN-A".to_owned(),
            }],
            ..Default::default()
        };
        let available = BTreeSet::from(["DIRECT".to_owned(), "VPN-A".to_owned()]);
        let before = policy.managed_rules()?;
        assert_eq!(
            before,
            vec![
                format!("PROCESS-PATH,/usr/bin/curl,{}", app_route_slot("/usr/bin/curl")),
                "PROCESS-PATH,/usr/bin/curl,REJECT".to_owned(),
                format!("MATCH,{APP_ROUTE_DEFAULT_SLOT}"),
                "MATCH,REJECT".to_owned()
            ]
        );
        let groups = policy.managed_groups(&available)?;
        assert_eq!(groups[0].name, app_route_slot("/usr/bin/curl"));
        assert_eq!(groups[0].selected, "VPN-A");
        assert_eq!(groups[1].selected, "REJECT");
        assert_eq!(groups[1].children.first().map(String::as_str), Some("REJECT"));
        policy.routes[0].route = "DIRECT".to_owned();
        policy.default_route = "VPN-A".to_owned();
        assert_eq!(policy.managed_rules()?, before);
        assert!(
            policy
                .managed_groups(&BTreeSet::from([groups[0].name.clone()]))
                .is_err()
        );
        policy.routes.push(AppRouteRule {
            process_path: "/USR/bin/curl".to_owned(),
            route: "DIRECT".to_owned(),
        });
        assert!(policy.validate().is_err());
        for paths in [("/usr/bin/σ", "/usr/bin/ς"), ("/usr/bin/ſ", "/usr/bin/s")] {
            policy.routes = <[&str; 2]>::from(paths)
                .into_iter()
                .map(|path| AppRouteRule {
                    process_path: path.to_owned(),
                    route: "DIRECT".to_owned(),
                })
                .collect();
            assert!(policy.validate().is_err());
            policy.routes.pop();
            assert!(policy.validate().is_ok());
        }
        Ok(())
    }
}
