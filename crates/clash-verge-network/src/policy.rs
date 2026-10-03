use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FirewallAction {
    Allow,
    Block,
    Ask,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RouteAction {
    Direct,
    ProxyGroup { group: String, required: bool },
    Vpn { required: bool },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum IdentityConfidence {
    Exact,
    Inferred,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Observe,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuleMatcher {
    #[serde(default)]
    pub process_path: Option<String>,
    #[serde(default)]
    pub unknown_process: bool,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub host_suffix: Option<String>,
    #[serde(default)]
    pub ip_cidr: Option<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub network: Option<Transport>,
    #[serde(default)]
    pub match_all: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FirewallRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub matcher: RuleMatcher,
    pub action: FirewallAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RouteRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i32,
    pub matcher: RuleMatcher,
    pub action: RouteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyDefaults {
    pub firewall: FirewallAction,
    pub route: RouteAction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPolicy {
    pub schema_version: u32,
    pub generation: u64,
    pub mode: PolicyMode,
    pub defaults: PolicyDefaults,
    pub firewall_rules: Vec<FirewallRule>,
    pub route_rules: Vec<RouteRule>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            schema_version: 1,
            generation: 0,
            mode: PolicyMode::Observe,
            defaults: PolicyDefaults {
                firewall: FirewallAction::Allow,
                route: RouteAction::Direct,
            },
            firewall_rules: Vec::new(),
            route_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreviewInput {
    #[serde(default)]
    pub process_path: Option<String>,
    #[serde(default)]
    pub identity_confidence: IdentityConfidence,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub destination_ip: Option<String>,
    #[serde(default)]
    pub destination_port: Option<u16>,
    #[serde(default)]
    pub network: Option<Transport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyPreview {
    pub generation: u64,
    pub firewall: FirewallAction,
    pub firewall_rule_id: Option<String>,
    pub route: Option<RouteAction>,
    pub route_rule_id: Option<String>,
    pub enforced: bool,
    pub identity_confidence: IdentityConfidence,
}

fn validate_label(value: &str, max: usize, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!(
            "{field} must be non-empty, contain no control characters and fit within {max} bytes"
        ));
    }
    Ok(())
}

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn validate_host(host: &str) -> Result<(), String> {
    let host = normalize_host(host);
    if host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(
            "Host conditions require an ASCII hostname without wildcards, scheme, port or credentials".to_owned(),
        );
    }
    Ok(())
}

fn parse_network(value: &str) -> Result<(IpAddr, u8), String> {
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (value, None),
    };
    let address: IpAddr = address.parse().map_err(|_| "Invalid IP/CIDR address".to_owned())?;
    let width = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.map_or(Ok(width), |value| {
        value.parse::<u8>().map_err(|_| "Invalid CIDR prefix".to_owned())
    })?;
    if prefix > width {
        return Err("CIDR prefix exceeds address width".to_owned());
    }
    Ok((address, prefix))
}

impl RuleMatcher {
    pub fn validate(&self) -> Result<(), String> {
        let has_condition = self.process_path.is_some()
            || self.unknown_process
            || self.host.is_some()
            || self.host_suffix.is_some()
            || self.ip_cidr.is_some()
            || !self.ports.is_empty()
            || self.network.is_some();
        if self.match_all == has_condition {
            return Err("A matcher must have conditions or explicit matchAll, never both".to_owned());
        }
        if self.process_path.is_some() && self.unknown_process {
            return Err("processPath and unknownProcess cannot be combined".to_owned());
        }
        if let Some(path) = &self.process_path {
            validate_label(path, 2048, "processPath")?;
            if !path.starts_with('/')
                && !(path.len() >= 3 && path.as_bytes()[1] == b':' && matches!(path.as_bytes()[2], b'\\' | b'/'))
            {
                return Err("processPath must be an absolute executable path".to_owned());
            }
        }
        if self.host.is_some() && self.host_suffix.is_some() {
            return Err("Use host or hostSuffix, not both".to_owned());
        }
        for host in [&self.host, &self.host_suffix].into_iter().flatten() {
            validate_host(host)?;
        }
        if let Some(cidr) = &self.ip_cidr {
            parse_network(cidr)?;
        }
        if self.ports.len() > 64 || self.ports.contains(&0) {
            return Err("Ports must contain at most 64 non-zero values".to_owned());
        }
        Ok(())
    }

    fn matches(&self, input: &PreviewInput) -> bool {
        if self.match_all {
            return true;
        }
        if let Some(path) = &self.process_path
            && (input.identity_confidence == IdentityConfidence::Unknown || input.process_path.as_ref() != Some(path))
        {
            return false;
        }
        if self.unknown_process
            && input.identity_confidence != IdentityConfidence::Unknown
            && input.process_path.as_ref().is_some_and(|path| !path.is_empty())
        {
            return false;
        }
        if let Some(host) = &self.host
            && input.host.as_ref().map(|value| normalize_host(value)) != Some(normalize_host(host))
        {
            return false;
        }
        if let Some(suffix) = &self.host_suffix {
            let Some(host) = input.host.as_ref().map(|value| normalize_host(value)) else {
                return false;
            };
            let suffix = normalize_host(suffix);
            if host != suffix && !host.strip_suffix(&suffix).is_some_and(|prefix| prefix.ends_with('.')) {
                return false;
            }
        }
        if let Some(cidr) = &self.ip_cidr {
            let Some(address) = input
                .destination_ip
                .as_ref()
                .and_then(|value| value.parse::<IpAddr>().ok())
            else {
                return false;
            };
            let Ok((network, prefix)) = parse_network(cidr) else {
                return false;
            };
            let in_network = match (network, address) {
                (IpAddr::V4(network), IpAddr::V4(address)) => {
                    let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
                    u32::from(network) & mask == u32::from(address) & mask
                }
                (IpAddr::V6(network), IpAddr::V6(address)) => {
                    let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
                    u128::from(network) & mask == u128::from(address) & mask
                }
                _ => false,
            };
            if !in_network {
                return false;
            }
        }
        if !self.ports.is_empty() && !input.destination_port.is_some_and(|port| self.ports.contains(&port)) {
            return false;
        }
        self.network.is_none() || self.network == input.network
    }
}

fn validate_route(route: &RouteAction) -> Result<(), String> {
    match route {
        RouteAction::ProxyGroup { group, required } => {
            validate_label(group, 256, "Proxy group")?;
            if !required {
                return Err("Proxy routes must be explicitly required; direct fallback is unsupported".to_owned());
            }
        }
        RouteAction::Vpn { required: false } => return Err("VPN routes must be explicitly required".to_owned()),
        RouteAction::Direct | RouteAction::Vpn { required: true } => {}
    }
    Ok(())
}

impl NetworkPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 {
            return Err("Unsupported network policy schema".to_owned());
        }
        if self.firewall_rules.len() + self.route_rules.len() > 1000 {
            return Err("A policy may contain at most 1000 rules".to_owned());
        }
        validate_route(&self.defaults.route)?;
        let mut ids = HashSet::new();
        for rule in &self.firewall_rules {
            validate_label(&rule.id, 128, "Rule ID")?;
            validate_label(&rule.name, 256, "Rule name")?;
            if !ids.insert(rule.id.as_str()) {
                return Err("Rule IDs must be unique across firewall and route rules".to_owned());
            }
            rule.matcher.validate()?;
        }
        for rule in &self.route_rules {
            validate_label(&rule.id, 128, "Rule ID")?;
            validate_label(&rule.name, 256, "Rule name")?;
            if !ids.insert(rule.id.as_str()) {
                return Err("Rule IDs must be unique across firewall and route rules".to_owned());
            }
            rule.matcher.validate()?;
            validate_route(&rule.action)?;
        }
        Ok(())
    }

    pub fn preview(&self, input: &PreviewInput) -> Result<PolicyPreview, String> {
        self.validate()?;
        if let Some(ip) = &input.destination_ip {
            ip.parse::<IpAddr>()
                .map_err(|_| "Invalid preview destination IP".to_owned())?;
        }
        if let Some(host) = &input.host {
            validate_host(host)?;
        }
        let firewall = self
            .firewall_rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| rule.enabled && rule.matcher.matches(input))
            .max_by_key(|(index, rule)| (rule.priority, std::cmp::Reverse(*index)))
            .map(|(_, rule)| rule);
        let action = firewall.map_or(self.defaults.firewall, |rule| rule.action);
        let route = if action == FirewallAction::Allow {
            self.route_rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.enabled && rule.matcher.matches(input))
                .max_by_key(|(index, rule)| (rule.priority, std::cmp::Reverse(*index)))
                .map(|(_, rule)| rule)
        } else {
            None
        };
        Ok(PolicyPreview {
            generation: self.generation,
            firewall: action,
            firewall_rule_id: firewall.map(|rule| rule.id.clone()),
            route: (action == FirewallAction::Allow)
                .then(|| route.map_or_else(|| self.defaults.route.clone(), |rule| rule.action.clone())),
            route_rule_id: route.map(|rule| rule.id.clone()),
            enforced: false,
            identity_confidence: input.identity_confidence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: id.to_owned(),
            name: id.to_owned(),
            enabled: true,
            priority: 10,
            matcher: RuleMatcher {
                host_suffix: Some("example.com".to_owned()),
                ..RuleMatcher::default()
            },
            action,
        }
    }

    #[test]
    fn preview_uses_priority_then_original_order_without_claiming_enforcement() -> Result<(), String> {
        let mut policy = NetworkPolicy {
            firewall_rules: vec![
                rule("first", FirewallAction::Allow),
                rule("second", FirewallAction::Block),
            ],
            ..NetworkPolicy::default()
        };
        let input = PreviewInput {
            host: Some("api.example.com".to_owned()),
            ..PreviewInput::default()
        };
        let first = policy.preview(&input)?;
        assert_eq!(first.firewall_rule_id.as_deref(), Some("first"));
        assert!(!first.enforced);
        policy.firewall_rules[1].priority = 11;
        let blocked = policy.preview(&input)?;
        assert_eq!(blocked.firewall, FirewallAction::Block);
        assert!(blocked.route.is_none());
        let unrelated = PreviewInput {
            host: Some("evilexample.com".to_owned()),
            ..PreviewInput::default()
        };
        assert!(policy.preview(&unrelated)?.firewall_rule_id.is_none());
        Ok(())
    }

    #[test]
    fn unsupported_fields_and_ambiguous_or_unrequired_rules_are_rejected() {
        assert!(serde_json::from_str::<RuleMatcher>(r#"{"matchAll":true,"signingId":"spoofed"}"#).is_err());
        assert!(RuleMatcher::default().validate().is_err());
        assert!(
            RuleMatcher {
                match_all: true,
                host: Some("example.com".to_owned()),
                ..RuleMatcher::default()
            }
            .validate()
            .is_err()
        );
        let policy = NetworkPolicy {
            defaults: PolicyDefaults {
                firewall: FirewallAction::Allow,
                route: RouteAction::Vpn { required: false },
            },
            ..NetworkPolicy::default()
        };
        assert!(policy.validate().is_err());
        let matcher = RuleMatcher {
            process_path: Some("/app/test".to_owned()),
            ..RuleMatcher::default()
        };
        assert!(!matcher.matches(&PreviewInput {
            process_path: Some("/app/test".to_owned()),
            ..PreviewInput::default()
        }));
    }
}
