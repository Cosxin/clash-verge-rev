use crate::{FirewallAction, FirewallRule, NetworkPolicy, RuleMatcher, Transport};
use ls_rules::{Action, Direction, LsRules, Ports, Priority, Remote, RemoteDomains, RemoteHosts};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const MAX_IMPORT_BYTES: usize = 2 * 1024 * 1024;
const MAX_IMPORT_RULES: usize = 512;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LsDiagnostic {
    pub source_index: Option<usize>,
    pub rule_id: Option<String>,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LsImportReport {
    pub rules: Vec<FirewallRule>,
    pub source_count: usize,
    pub accepted_count: usize,
    pub rejected_count: usize,
    pub diagnostics: Vec<LsDiagnostic>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LsExportReport {
    pub content: String,
    pub exported_count: usize,
    pub rejected_count: usize,
    pub diagnostics: Vec<LsDiagnostic>,
}

fn diagnostic(index: Option<usize>, rule_id: Option<String>, message: impl Into<String>) -> LsDiagnostic {
    LsDiagnostic {
        source_index: index,
        rule_id,
        severity: "error".to_owned(),
        message: message.into(),
    }
}

fn host_conditions_overlap(left: &RuleMatcher, right: &RuleMatcher) -> bool {
    let left = left
        .host
        .as_ref()
        .map(|value| (value, false))
        .or_else(|| left.host_suffix.as_ref().map(|value| (value, true)));
    let right = right
        .host
        .as_ref()
        .map(|value| (value, false))
        .or_else(|| right.host_suffix.as_ref().map(|value| (value, true)));
    let (Some((left, left_suffix)), Some((right, right_suffix))) = (left, right) else {
        return true;
    };
    let left = left.trim_end_matches('.').to_ascii_lowercase();
    let right = right.trim_end_matches('.').to_ascii_lowercase();
    left == right
        || right_suffix && left.ends_with(&format!(".{right}"))
        || left_suffix && right.ends_with(&format!(".{left}"))
}

fn require_compatible_precedence(rules: &[FirewallRule]) -> Result<(), String> {
    // Little Snitch resolves specificity; the draft compiler resolves equal priority by source order.
    for (index, left) in rules.iter().enumerate().filter(|(_, rule)| rule.enabled) {
        for right in rules.iter().skip(index + 1).filter(|rule| rule.enabled) {
            if left.priority != right.priority || left.action == right.action {
                continue;
            }
            let left_match = &left.matcher;
            let right_match = &right.matcher;
            if left_match.network.is_some()
                && right_match.network.is_some()
                && left_match.network != right_match.network
            {
                continue;
            }
            if !left_match.ports.is_empty()
                && !right_match.ports.is_empty()
                && !left_match.ports.iter().any(|port| right_match.ports.contains(port))
            {
                continue;
            }
            if !host_conditions_overlap(left_match, right_match) {
                continue;
            }
            return Err(format!(
                "Rules '{}' and '{}' have equal priority, opposing actions and potentially overlapping matches. Little Snitch specificity differs from draft source-order precedence; the entire transfer was rejected to avoid changing permissions.",
                left.id, right.id
            ));
        }
    }
    Ok(())
}

fn import_rule(value: &Value, index: usize) -> Result<Vec<FirewallRule>, String> {
    let object = value.as_object().ok_or("Rule must be a JSON object")?;
    const KEYS: &[&str] = &[
        "process",
        "via",
        "remote-addresses",
        "remote-hosts",
        "remote-domains",
        "remote",
        "direction",
        "action",
        "priority",
        "disabled",
        "ports",
        "protocol",
        "notes",
        "owner",
        "creationDate",
        "modificationDate",
    ];
    if let Some(key) = object.keys().find(|key| !KEYS.contains(&key.as_str())) {
        return Err(format!("Unsupported rule field '{key}'; no constraints were discarded"));
    }
    for key in [
        "process",
        "remote-addresses",
        "remote-hosts",
        "remote-domains",
        "remote",
        "direction",
        "action",
        "priority",
        "disabled",
        "ports",
        "protocol",
    ] {
        if object.get(key).is_some_and(Value::is_null) {
            return Err(format!(
                "Rule field '{key}' cannot be null; omitted and empty constraints are not interchangeable"
            ));
        }
    }
    if object.contains_key("via") {
        return Err("The originating-process 'via' constraint is not supported by the draft matcher".to_owned());
    }
    if object.get("owner").is_some_and(|owner| owner.as_str() != Some("any")) {
        return Err("User/system owner scopes cannot be translated into an unrestricted draft rule".to_owned());
    }
    let remote_fields = ["remote-addresses", "remote-hosts", "remote-domains", "remote"];
    if remote_fields
        .iter()
        .filter(|field| object.contains_key(**field))
        .count()
        > 1
    {
        return Err("Multiple remote condition types are ambiguous and were not combined".to_owned());
    }
    let mut normalized = value.clone();
    normalized["process"] = object.get("process").cloned().unwrap_or_else(|| json!("any"));
    // The upstream model calls regular priority "default"; the documented format uses "regular".
    if object.get("priority").and_then(Value::as_str) == Some("regular") {
        normalized["priority"] = json!("default");
    }
    let encoded = serde_json::to_string(&json!({"rules": [normalized]})).map_err(|error| error.to_string())?;
    let parsed: LsRules<'_> =
        serde_json::from_str(&encoded).map_err(|error| format!("Invalid .lsrules rule: {error}"))?;
    let rule = parsed
        .rules
        .as_ref()
        .and_then(|rules| rules.first())
        .ok_or("Missing rule")?;
    if !matches!(rule.direction, None | Some(Direction::Outgoing)) {
        return Err("Only outgoing rules can be represented by the current draft policy".to_owned());
    }
    let action = match rule.action.as_ref() {
        None | Some(Action::Ask) => FirewallAction::Ask,
        Some(Action::Allow) => FirewallAction::Allow,
        Some(Action::Deny) => FirewallAction::Block,
        _ => return Err("Unknown firewall action".to_owned()),
    };
    let priority = match rule.priority.as_ref() {
        None | Some(Priority::Default) => 0,
        Some(Priority::High) => 100,
        _ => return Err("Unknown priority".to_owned()),
    };
    let mut matcher = RuleMatcher::default();
    if rule.process != "any" {
        if rule.process.starts_with("identifier.") {
            return Err(
                "Signing-code identities require a native identity adapter; they were not downgraded to paths"
                    .to_owned(),
            );
        }
        matcher.process_path = Some(rule.process.to_owned());
    }
    matcher.network = match rule.protocol {
        None | Some("any") => None,
        Some("tcp" | "6") => Some(Transport::Tcp),
        Some("udp" | "17") => Some(Transport::Udp),
        _ => return Err("Only TCP, UDP or any-protocol rules are supported".to_owned()),
    };
    matcher.ports = match rule.ports.as_ref() {
        None | Some(Ports::Any) => Vec::new(),
        Some(Ports::Single(port)) => vec![*port],
        Some(Ports::Range(first, last)) if last >= first && last - first < 64 => (*first..=*last).collect(),
        _ => return Err("Ports must be any, one port or an ascending range of at most 64 ports".to_owned()),
    };
    if let Some(remote) = &rule.remote
        && !matches!(remote, Remote::Any)
    {
        return Err("Special remote classes require native context and were not widened to any destination".to_owned());
    }
    matcher.ip_cidr = rule.remote_addresses.map(str::to_owned);
    let hosts: Vec<&str> = match &rule.remote_hosts {
        None => Vec::new(),
        Some(RemoteHosts::Single(host)) => vec![host],
        Some(RemoteHosts::Multiple(hosts)) => hosts.clone(),
        _ => return Err("Unsupported host condition".to_owned()),
    };
    let domains: Vec<&str> = match &rule.remote_domains {
        None => Vec::new(),
        Some(RemoteDomains::Single(domain)) => vec![domain],
        Some(RemoteDomains::Multiple(domains)) => domains.clone(),
        _ => return Err("Unsupported domain condition".to_owned()),
    };
    if rule.remote_hosts.is_some() && hosts.is_empty() || rule.remote_domains.is_some() && domains.is_empty() {
        return Err("An empty destination list cannot become an any-destination rule".to_owned());
    }
    let targets: Vec<(Option<String>, Option<String>)> = if !hosts.is_empty() {
        hosts.into_iter().map(|host| (Some(host.to_owned()), None)).collect()
    } else if !domains.is_empty() {
        domains
            .into_iter()
            .map(|domain| (None, Some(domain.to_owned())))
            .collect()
    } else {
        vec![(None, None)]
    };
    if targets.len() > MAX_IMPORT_RULES {
        return Err("Destination expansion exceeds the import rule limit".to_owned());
    }
    targets
        .into_iter()
        .enumerate()
        .map(|(target_index, (host, host_suffix))| {
            let mut matcher = matcher.clone();
            matcher.host = host;
            matcher.host_suffix = host_suffix;
            matcher.match_all = matcher == RuleMatcher::default();
            matcher.validate()?;
            Ok(FirewallRule {
                id: format!("lsrules-{}-{}", index + 1, target_index + 1),
                name: format!("Imported rule {}.{}", index + 1, target_index + 1),
                enabled: !rule.disabled.unwrap_or(false),
                priority,
                matcher,
                action,
            })
        })
        .collect()
}

pub fn import_lsrules(content: &str) -> Result<LsImportReport, String> {
    if content.len() > MAX_IMPORT_BYTES {
        return Err("Rule file exceeds 2 MiB".to_owned());
    }
    let value: Value = serde_json::from_str(content).map_err(|error| format!("Invalid .lsrules JSON: {error}"))?;
    let object = value.as_object().ok_or("Rule file must be a JSON object")?;
    const KEYS: &[&str] = &[
        "name",
        "description",
        "rules",
        "denied-remote-domains",
        "denied-remote-hosts",
        "denied-remote-addresses",
        "denied-remote-notes",
    ];
    if let Some(key) = object.keys().find(|key| !KEYS.contains(&key.as_str())) {
        return Err(format!(
            "Unsupported group field '{key}'; group semantics were not discarded"
        ));
    }
    for key in ["name", "description", "denied-remote-notes"] {
        if object.get(key).is_some_and(|value| !value.is_string()) {
            return Err(format!("Group field '{key}' must be a string"));
        }
    }
    let mut source = match object.get("rules") {
        None => Vec::new(),
        Some(Value::Array(rules)) => rules.clone(),
        _ => return Err("The rules field must be an array".to_owned()),
    };
    for (shortcut, remote_key) in [
        ("denied-remote-domains", "remote-domains"),
        ("denied-remote-hosts", "remote-hosts"),
        ("denied-remote-addresses", "remote-addresses"),
    ] {
        if let Some(entries) = object.get(shortcut) {
            let entries = entries
                .as_array()
                .ok_or_else(|| format!("'{shortcut}' must be an array"))?;
            for entry in entries {
                if !entry.is_string() {
                    return Err(format!("'{shortcut}' entries must be strings"));
                }
                let mut rule = json!({"process": "any", "action": "deny"});
                rule[remote_key] = entry.clone();
                source.push(rule);
            }
        }
    }
    if source.len() > MAX_IMPORT_RULES {
        return Err("Rule file exceeds 512 source entries".to_owned());
    }
    let mut report = LsImportReport {
        rules: Vec::new(),
        source_count: source.len(),
        accepted_count: 0,
        rejected_count: 0,
        diagnostics: Vec::new(),
    };
    for (index, value) in source.iter().enumerate() {
        match import_rule(value, index) {
            Ok(rules) if report.rules.len() + rules.len() <= MAX_IMPORT_RULES => {
                report.rules.extend(rules);
                report.accepted_count += 1;
            }
            Ok(_) => {
                report.rejected_count += 1;
                report.diagnostics.push(diagnostic(
                    Some(index + 1),
                    None,
                    "Expanded rules exceed the 512-rule limit",
                ));
            }
            Err(error) => {
                report.rejected_count += 1;
                report.diagnostics.push(diagnostic(Some(index + 1), None, error));
            }
        }
    }
    require_compatible_precedence(&report.rules)?;
    Ok(report)
}

fn export_rule(rule: &FirewallRule) -> Result<Value, String> {
    let matcher = &rule.matcher;
    matcher.validate()?;
    if matcher.unknown_process {
        return Err("Unknown-identity rules have no equivalent .lsrules process selector".to_owned());
    }
    if !matches!(rule.priority, 0 | 100) {
        return Err(
            "Only regular (0) and high (100) priorities can be exported without changing precedence".to_owned(),
        );
    }
    let remote_count = usize::from(matcher.host.is_some())
        + usize::from(matcher.host_suffix.is_some())
        + usize::from(matcher.ip_cidr.is_some());
    if remote_count > 1 {
        return Err("Conjunctive destination predicates cannot be flattened into one .lsrules destination".to_owned());
    }
    let mut result = json!({
        "process": matcher.process_path.as_deref().unwrap_or("any"),
        "action": match rule.action { FirewallAction::Allow => "allow", FirewallAction::Block => "deny", FirewallAction::Ask => "ask" },
        "direction": "outgoing",
        "priority": if rule.priority == 100 { "high" } else { "regular" },
        "disabled": !rule.enabled,
        "notes": rule.name,
    });
    if let Some(host) = &matcher.host {
        result["remote-hosts"] = json!(host);
    }
    if let Some(domain) = &matcher.host_suffix {
        result["remote-domains"] = json!(domain);
    }
    if let Some(address) = &matcher.ip_cidr {
        result["remote-addresses"] = json!(address);
    }
    if let Some(network) = &matcher.network {
        result["protocol"] = json!(match network {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        });
    }
    if !matcher.ports.is_empty() {
        let mut ports = matcher.ports.clone();
        ports.sort_unstable();
        ports.dedup();
        let first = ports[0];
        let last = ports[ports.len() - 1];
        if usize::from(last - first) + 1 != ports.len() {
            return Err(
                "Non-contiguous port lists cannot be expressed by the documented .lsrules port field".to_owned(),
            );
        }
        result["ports"] = json!(if first == last {
            first.to_string()
        } else {
            format!("{first}-{last}")
        });
    }
    Ok(result)
}

pub fn export_lsrules(policy: &NetworkPolicy) -> Result<LsExportReport, String> {
    policy.validate()?;
    require_compatible_precedence(&policy.firewall_rules)?;
    let mut rules = Vec::new();
    let mut diagnostics = Vec::new();
    let mut rejected_count = 0;
    for rule in &policy.firewall_rules {
        match export_rule(rule) {
            Ok(value) => rules.push(value),
            Err(error) => {
                rejected_count += 1;
                diagnostics.push(diagnostic(None, Some(rule.id.clone()), error));
            }
        }
    }
    for rule in &policy.route_rules {
        rejected_count += 1;
        diagnostics.push(diagnostic(
            None,
            Some(rule.id.clone()),
            "Routing rules are not firewall permissions and cannot be exported as .lsrules",
        ));
    }
    diagnostics.push(LsDiagnostic {
        source_index: None,
        rule_id: None,
        severity: "warning".to_owned(),
        message: "Export contains explicit outgoing firewall rules only; defaults, generations and observe-mode state are not transferable".to_owned(),
    });
    let exported_count = rules.len();
    let content = serde_json::to_string_pretty(&json!({
        "name": "Network policy firewall rules",
        "description": "Explicit outgoing rules only. Review diagnostics before importing into another firewall.",
        "rules": rules,
    }))
    .map_err(|error| error.to_string())?;
    Ok(LsExportReport {
        content,
        exported_count,
        rejected_count,
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imports_documented_defaults_and_expands_domains_without_broadening() -> Result<(), String> {
        let report = import_lsrules(r#"{"rules":[{"remote-domains":["example.com","example.net"]}]}"#)?;
        assert_eq!(report.source_count, 1);
        assert_eq!(report.accepted_count, 1);
        assert_eq!(report.rules.len(), 2);
        assert_eq!(report.rules[0].action, FirewallAction::Ask);
        assert_eq!(report.rules[0].matcher.host_suffix.as_deref(), Some("example.com"));
        assert!(!report.rules[0].matcher.match_all);
        Ok(())
    }

    #[test]
    fn rejects_unrepresentable_or_empty_constraints_instead_of_dropping_them() -> Result<(), String> {
        let report = import_lsrules(
            r#"{"rules":[
            {"action":"allow","via":"/usr/bin/ssh"},
            {"action":"allow","process":"identifier.TEAM/com.example"},
            {"action":"allow","remote":"local-net"},
            {"action":"allow","remote-hosts":[]},
            {"action":"allow","unknown-condition":true},
            {"action":"allow","direction":"incoming"},
            {"action":"allow","owner":"me"},
            {"action":"allow","remote-hosts":null}
        ]}"#,
        )?;
        assert!(report.rules.is_empty());
        assert_eq!(report.rejected_count, 8);
        assert_eq!(report.diagnostics.len(), 8);
        Ok(())
    }

    #[test]
    fn imports_blocklist_shortcuts_and_keeps_high_priority() -> Result<(), String> {
        let report = import_lsrules(
            r#"{"rules":[{"action":"allow","priority":"high","process":"/usr/bin/curl","ports":"443","protocol":"6"}],"denied-remote-domains":["ads.example.com"],"denied-remote-addresses":["192.0.2.0/24"]}"#,
        )?;
        assert_eq!(report.accepted_count, 3);
        assert_eq!(report.rules[0].priority, 100);
        assert_eq!(report.rules[0].matcher.network, Some(Transport::Tcp));
        assert_eq!(report.rules[1].action, FirewallAction::Block);
        assert_eq!(report.rules[2].matcher.ip_cidr.as_deref(), Some("192.0.2.0/24"));
        Ok(())
    }

    #[test]
    fn roundtrip_preserves_representable_rule_decisions_and_rejects_port_lists() -> Result<(), String> {
        let mut policy = NetworkPolicy {
            firewall_rules: import_lsrules(r#"{"rules":[{"process":"/usr/bin/curl","action":"allow","remote-hosts":"example.com","ports":"443","protocol":"tcp","priority":"regular"}]}"#)?.rules,
            ..NetworkPolicy::default()
        };
        let exported = export_lsrules(&policy)?;
        assert_eq!(exported.exported_count, 1);
        let imported = import_lsrules(&exported.content)?;
        assert_eq!(imported.rules[0].matcher, policy.firewall_rules[0].matcher);
        assert_eq!(imported.rules[0].action, policy.firewall_rules[0].action);
        policy.firewall_rules[0].matcher.ports = vec![443, 8443];
        let exported = export_lsrules(&policy)?;
        assert_eq!(exported.exported_count, 0);
        assert_eq!(exported.rejected_count, 1);
        Ok(())
    }

    #[test]
    fn rejects_group_semantics_and_malformed_input() {
        assert!(import_lsrules(r#"{"owner":"system","rules":[{"action":"allow"}]}"#).is_err());
        assert!(import_lsrules(r#"{"rules":null}"#).is_err());
        assert!(import_lsrules(r#"{"denied-remote-domains":[7]}"#).is_err());
        assert!(import_lsrules("not json").is_err());
    }

    #[test]
    fn rejects_whole_transfer_when_specificity_could_change_opposing_decisions() -> Result<(), String> {
        let broad = import_lsrules(r#"{"rules":[{"action":"allow"}]}"#)?;
        let specific = import_lsrules(r#"{"rules":[{"action":"deny","remote-domains":"ads.example.com"}]}"#)?;
        let mut rules = broad.rules;
        let mut deny = specific.rules[0].clone();
        deny.id = "specific-deny".to_owned();
        rules.push(deny);
        let policy = NetworkPolicy {
            firewall_rules: rules,
            ..NetworkPolicy::default()
        };
        assert!(export_lsrules(&policy).is_err());
        assert!(
            import_lsrules(r#"{"rules":[{"action":"allow"},{"action":"deny","remote-domains":"ads.example.com"}]}"#)
                .is_err()
        );
        let disjoint = import_lsrules(
            r#"{"rules":[{"action":"allow","remote-hosts":"api.example.com"},{"action":"deny","remote-domains":"ads.example.com"}]}"#,
        )?;
        assert_eq!(disjoint.accepted_count, 2);
        Ok(())
    }
}
