use crate::{FirewallAction, IdentityConfidence, NetworkPolicy, PreviewInput, RouteAction, RuleMatcher, Transport};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterScope {
    pub adapter_id: String,
    pub boot_id: String,
    pub stream_epoch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdapterSession {
    pub schema_version: u32,
    pub scope: AdapterScope,
    pub can_hold_flows: bool,
    pub can_apply_verdicts: bool,
    pub can_require_proxy_route: bool,
    pub can_require_vpn_route: bool,
    pub max_pending: usize,
    pub max_timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ActivationContext {
    generation: u64,
    enforcing_scope: Option<AdapterScope>,
}

impl ActivationContext {
    pub const fn observe(generation: u64) -> Self {
        Self {
            generation,
            enforcing_scope: None,
        }
    }

    // Production activation requires the future authenticated owner's prepare/commit acknowledgement.
    #[cfg(test)]
    const fn committed_for_test(generation: u64, scope: AdapterScope) -> Self {
        Self {
            generation,
            enforcing_scope: Some(scope),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    Native,
    Inferred,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppEvidence {
    pub process_path: Option<String>,
    pub confidence: IdentityConfidence,
    pub source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteEvidence {
    pub ip: String,
    pub port: u16,
    pub hostname: Option<String>,
    pub hostname_source: EvidenceSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub sequence: u64,
    pub scope: AdapterScope,
    pub policy_generation: u64,
    pub flow_id: String,
    pub timeout_ms: u64,
    pub app: AppEvidence,
    pub remote: RemoteEvidence,
    pub network: Transport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestKey {
    pub request_id: String,
    pub sequence: u64,
    pub scope: AdapterScope,
    pub flow_id: String,
}

impl DecisionRequest {
    fn key(&self) -> RequestKey {
        RequestKey {
            request_id: self.request_id.clone(),
            sequence: self.sequence,
            scope: self.scope.clone(),
            flow_id: self.flow_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplyVerdict {
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionReply {
    pub schema_version: u32,
    pub key: RequestKey,
    pub policy_generation: u64,
    pub verdict: ReplyVerdict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NativeInstruction {
    Observe,
    Allow,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionOutcome {
    pub key: RequestKey,
    pub policy_generation: u64,
    pub instruction: NativeInstruction,
    pub preview_firewall: FirewallAction,
    pub route: Option<RouteAction>,
    pub reason: String,
    pub enforced: bool,
    pub requires_native_ack: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPrompt {
    pub key: RequestKey,
    pub policy_generation: u64,
    pub deadline_ms: u64,
    pub app: AppEvidence,
    pub remote: RemoteEvidence,
    pub network: Transport,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Submission {
    Immediate(DecisionOutcome),
    Pending(PendingPrompt),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrokerFailure {
    pub key: Box<RequestKey>,
    pub reason: String,
    pub native_block_required: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RouteAvailability {
    pub proxy_groups: Vec<String>,
    pub vpn_ready: bool,
}

struct PendingDecision {
    prompt: PendingPrompt,
    input: PreviewInput,
}

pub struct DecisionBroker {
    session: AdapterSession,
    activation: ActivationContext,
    last_sequence: u64,
    pending: BTreeMap<u64, PendingDecision>,
    disconnected: bool,
}

fn validate_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

impl DecisionBroker {
    pub fn new(session: AdapterSession, activation: ActivationContext) -> Result<Self, String> {
        if session.schema_version != 1
            || !validate_identifier(&session.scope.adapter_id)
            || !validate_identifier(&session.scope.boot_id)
            || !validate_identifier(&session.scope.stream_epoch)
            || !(1..=512).contains(&session.max_pending)
            || !(1..=30_000).contains(&session.max_timeout_ms)
        {
            return Err("Invalid or unbounded native adapter session".to_owned());
        }
        if let Some(scope) = &activation.enforcing_scope
            && (scope != &session.scope || !session.can_apply_verdicts)
        {
            return Err("Enforcement activation is not acknowledged by this adapter scope".to_owned());
        }
        Ok(Self {
            session,
            activation,
            last_sequence: 0,
            pending: BTreeMap::new(),
            disconnected: false,
        })
    }

    fn enforcing(&self) -> bool {
        !self.disconnected && self.activation.enforcing_scope.as_ref() == Some(&self.session.scope)
    }

    fn failure(&self, key: RequestKey, reason: impl Into<String>) -> BrokerFailure {
        BrokerFailure {
            key: Box::new(key),
            reason: reason.into(),
            native_block_required: self.enforcing(),
        }
    }

    fn outcome(
        &self,
        key: RequestKey,
        generation: u64,
        instruction: NativeInstruction,
        preview: FirewallAction,
        route: Option<RouteAction>,
        reason: &str,
    ) -> DecisionOutcome {
        DecisionOutcome {
            key,
            policy_generation: generation,
            instruction,
            preview_firewall: preview,
            route,
            reason: reason.to_owned(),
            enforced: false,
            requires_native_ack: instruction != NativeInstruction::Observe && self.enforcing(),
        }
    }

    fn route_available(&self, route: &RouteAction, availability: &RouteAvailability) -> bool {
        match route {
            RouteAction::Direct => true,
            RouteAction::ProxyGroup { group, required: true } => {
                self.session.can_require_proxy_route && availability.proxy_groups.contains(group)
            }
            RouteAction::Vpn { required: true } => self.session.can_require_vpn_route && availability.vpn_ready,
            _ => false,
        }
    }

    fn input(&self, request: &DecisionRequest) -> Result<PreviewInput, String> {
        if !validate_identifier(&request.request_id)
            || !validate_identifier(&request.flow_id)
            || request.timeout_ms == 0
            || request.remote.port == 0
        {
            return Err("Invalid native decision identity, port or deadline".to_owned());
        }
        request
            .remote
            .ip
            .parse::<IpAddr>()
            .map_err(|_| "Invalid native destination IP".to_owned())?;
        if let Some(path) = &request.app.process_path {
            RuleMatcher {
                process_path: Some(path.clone()),
                ..RuleMatcher::default()
            }
            .validate()?;
        }
        if let Some(host) = &request.remote.hostname {
            RuleMatcher {
                host: Some(host.clone()),
                ..RuleMatcher::default()
            }
            .validate()?;
        }
        let exact = request.app.confidence == IdentityConfidence::Exact
            && request.app.source == EvidenceSource::Native
            && request.app.process_path.is_some();
        Ok(PreviewInput {
            process_path: if self.enforcing() && !exact {
                None
            } else {
                request.app.process_path.clone()
            },
            identity_confidence: if self.enforcing() && !exact {
                IdentityConfidence::Unknown
            } else {
                request.app.confidence
            },
            host: if self.enforcing() && request.remote.hostname_source != EvidenceSource::Native {
                None
            } else {
                request.remote.hostname.clone()
            },
            destination_ip: Some(request.remote.ip.clone()),
            destination_port: Some(request.remote.port),
            network: Some(request.network),
        })
    }

    pub fn submit(
        &mut self,
        policy: &NetworkPolicy,
        request: DecisionRequest,
        now_ms: u64,
        ui_connected: bool,
        availability: &RouteAvailability,
    ) -> Result<Submission, BrokerFailure> {
        let key = request.key();
        if self.disconnected || request.schema_version != 1 || request.scope != self.session.scope {
            return Err(self.failure(key, "Native request is from an unsupported or stale adapter session"));
        }
        if request.sequence <= self.last_sequence {
            return Err(self.failure(key, "Native request sequence was replayed or reordered"));
        }
        self.last_sequence = request.sequence;
        if request.policy_generation != policy.generation || self.activation.generation != policy.generation {
            return Err(self.failure(key, "Native request policy generation is stale or not acknowledged"));
        }
        if self.pending.values().any(|pending| {
            pending.prompt.key.request_id == request.request_id || pending.prompt.key.flow_id == request.flow_id
        }) {
            return Err(self.failure(key, "A decision is already pending for this request or held flow"));
        }
        let input = self
            .input(&request)
            .map_err(|reason| self.failure(key.clone(), reason))?;
        let preview = policy
            .preview(&input)
            .map_err(|reason| self.failure(key.clone(), reason))?;
        if !self.enforcing() {
            return Ok(Submission::Immediate(self.outcome(
                key,
                policy.generation,
                NativeInstruction::Observe,
                preview.firewall,
                None,
                "Observe-only activation cannot issue native permission or routing instructions",
            )));
        }
        if input.identity_confidence == IdentityConfidence::Unknown && preview.firewall_rule_id.is_none() {
            return Ok(Submission::Immediate(self.outcome(
                key,
                policy.generation,
                NativeInstruction::Block,
                preview.firewall,
                None,
                "Unknown or inferred app identity has no explicit matching permission",
            )));
        }
        match preview.firewall {
            FirewallAction::Block => Ok(Submission::Immediate(self.outcome(
                key,
                policy.generation,
                NativeInstruction::Block,
                preview.firewall,
                None,
                "Matched firewall block",
            ))),
            FirewallAction::Allow => {
                let Some(route) = preview.route else {
                    return Err(self.failure(key, "Allowed flow has no evaluated route"));
                };
                if !self.route_available(&route, availability) {
                    return Ok(Submission::Immediate(self.outcome(
                        key,
                        policy.generation,
                        NativeInstruction::Block,
                        preview.firewall,
                        None,
                        "Required route is unavailable; direct fallback is forbidden",
                    )));
                }
                Ok(Submission::Immediate(self.outcome(
                    key,
                    policy.generation,
                    NativeInstruction::Allow,
                    preview.firewall,
                    Some(route),
                    "Matched firewall allow; native acknowledgement is still required",
                )))
            }
            FirewallAction::Ask => {
                if !ui_connected || !self.session.can_hold_flows || self.pending.len() >= self.session.max_pending {
                    return Ok(Submission::Immediate(self.outcome(
                        key,
                        policy.generation,
                        NativeInstruction::Block,
                        preview.firewall,
                        None,
                        "Prompt unavailable, unsupported or at capacity; default block",
                    )));
                }
                let prompt = PendingPrompt {
                    key,
                    policy_generation: policy.generation,
                    deadline_ms: now_ms.saturating_add(request.timeout_ms.min(self.session.max_timeout_ms)),
                    app: request.app,
                    remote: request.remote,
                    network: request.network,
                };
                self.pending.insert(
                    request.sequence,
                    PendingDecision {
                        prompt: prompt.clone(),
                        input,
                    },
                );
                Ok(Submission::Pending(prompt))
            }
        }
    }

    pub fn reply(
        &mut self,
        policy: &NetworkPolicy,
        reply: DecisionReply,
        now_ms: u64,
        availability: &RouteAvailability,
    ) -> Result<DecisionOutcome, BrokerFailure> {
        if reply.schema_version != 1 || reply.key.scope != self.session.scope || self.disconnected {
            return Err(self.failure(reply.key, "Reply is from an unsupported or stale adapter session"));
        }
        let Some(pending) = self.pending.get(&reply.key.sequence) else {
            return Err(self.failure(reply.key, "Prompt is unknown, completed or replayed"));
        };
        if pending.prompt.key != reply.key {
            return Err(self.failure(reply.key, "Reply is not bound to the original held flow"));
        }
        let Some(pending) = self.pending.remove(&reply.key.sequence) else {
            return Err(self.failure(reply.key, "Prompt is no longer pending"));
        };
        if reply.policy_generation != pending.prompt.policy_generation
            || policy.generation != pending.prompt.policy_generation
            || self.activation.generation != policy.generation
        {
            return Err(self.failure(
                reply.key,
                "Reply generation is stale; native block resolution is required",
            ));
        }
        if now_ms >= pending.prompt.deadline_ms {
            return Err(self.failure(
                reply.key,
                "Prompt deadline expired; native block resolution is required",
            ));
        }
        if reply.verdict == ReplyVerdict::Block {
            return Ok(self.outcome(
                reply.key,
                policy.generation,
                NativeInstruction::Block,
                FirewallAction::Ask,
                None,
                "User selected block for this held flow",
            ));
        }
        let mut allowed = policy.clone();
        for rule in &mut allowed.firewall_rules {
            rule.enabled = false;
        }
        allowed.defaults.firewall = FirewallAction::Allow;
        let preview = allowed
            .preview(&pending.input)
            .map_err(|reason| self.failure(reply.key.clone(), reason))?;
        let Some(route) = preview.route else {
            return Err(self.failure(reply.key, "Prompted flow has no evaluated route"));
        };
        if !self.route_available(&route, availability) {
            return Ok(self.outcome(
                reply.key,
                policy.generation,
                NativeInstruction::Block,
                FirewallAction::Ask,
                None,
                "Required route unavailable at reply; direct fallback is forbidden",
            ));
        }
        Ok(self.outcome(
            reply.key,
            policy.generation,
            NativeInstruction::Allow,
            FirewallAction::Ask,
            Some(route),
            "User selected one-flow allow; native acknowledgement is still required",
        ))
    }

    pub fn expire(&mut self, now_ms: u64) -> Vec<DecisionOutcome> {
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, pending)| now_ms >= pending.prompt.deadline_ms)
            .map(|(sequence, _)| *sequence)
            .collect();
        let mut outcomes = Vec::with_capacity(expired.len());
        for sequence in expired {
            if let Some(pending) = self.pending.remove(&sequence) {
                outcomes.push(self.outcome(
                    pending.prompt.key,
                    pending.prompt.policy_generation,
                    NativeInstruction::Block,
                    FirewallAction::Ask,
                    None,
                    "Prompt timed out; default block",
                ));
            }
        }
        outcomes
    }

    pub fn ui_disconnected(&mut self) -> Vec<DecisionOutcome> {
        let pending = std::mem::take(&mut self.pending);
        pending
            .into_values()
            .map(|pending| {
                self.outcome(
                    pending.prompt.key,
                    pending.prompt.policy_generation,
                    NativeInstruction::Block,
                    FirewallAction::Ask,
                    None,
                    "UI disconnected; default block",
                )
            })
            .collect()
    }

    pub fn policy_changed(&mut self, generation: u64) -> Vec<DecisionOutcome> {
        let outcomes = self.ui_disconnected();
        if !self.enforcing() {
            self.activation = ActivationContext::observe(generation);
        }
        outcomes
    }

    pub fn adapter_disconnected(&mut self) -> Vec<DecisionOutcome> {
        let outcomes = self.ui_disconnected();
        self.disconnected = true;
        outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FirewallRule, PolicyDefaults};

    fn session() -> AdapterSession {
        AdapterSession {
            schema_version: 1,
            scope: AdapterScope {
                adapter_id: "native-test".to_owned(),
                boot_id: "boot-test".to_owned(),
                stream_epoch: "stream-test".to_owned(),
            },
            can_hold_flows: true,
            can_apply_verdicts: true,
            can_require_proxy_route: false,
            can_require_vpn_route: false,
            max_pending: 1,
            max_timeout_ms: 1000,
        }
    }

    fn request(sequence: u64) -> DecisionRequest {
        DecisionRequest {
            schema_version: 1,
            request_id: format!("request-{sequence}"),
            sequence,
            scope: session().scope,
            policy_generation: 0,
            flow_id: format!("flow-{sequence}"),
            timeout_ms: 50_000,
            app: AppEvidence {
                process_path: Some("/test/app".to_owned()),
                confidence: IdentityConfidence::Exact,
                source: EvidenceSource::Native,
            },
            remote: RemoteEvidence {
                ip: "192.0.2.1".to_owned(),
                port: 443,
                hostname: Some("example.com".to_owned()),
                hostname_source: EvidenceSource::Native,
            },
            network: Transport::Tcp,
        }
    }

    fn enforcing() -> Result<DecisionBroker, String> {
        let session = session();
        DecisionBroker::new(session.clone(), ActivationContext::committed_for_test(0, session.scope))
    }

    fn immediate(submission: Submission) -> Result<DecisionOutcome, String> {
        match submission {
            Submission::Immediate(outcome) => Ok(outcome),
            Submission::Pending(_) => Err("Expected an immediate decision".to_owned()),
        }
    }

    fn pending(submission: Submission) -> Result<PendingPrompt, String> {
        match submission {
            Submission::Pending(prompt) => Ok(prompt),
            Submission::Immediate(_) => Err("Expected a held-flow prompt".to_owned()),
        }
    }

    fn ask_policy() -> NetworkPolicy {
        NetworkPolicy {
            defaults: PolicyDefaults {
                firewall: FirewallAction::Ask,
                route: RouteAction::Direct,
            },
            ..NetworkPolicy::default()
        }
    }

    #[test]
    fn observe_activation_cannot_be_upgraded_by_adapter_capabilities() -> Result<(), String> {
        let mut broker = DecisionBroker::new(session(), ActivationContext::observe(0))?;
        let outcome = immediate(
            broker
                .submit(&ask_policy(), request(1), 100, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(outcome.instruction, NativeInstruction::Observe);
        assert!(!outcome.enforced);
        assert!(!outcome.requires_native_ack);
        assert!(outcome.route.is_none());
        assert!(broker.expire(100_000).is_empty());
        Ok(())
    }

    #[test]
    fn inferred_identity_and_missing_required_route_fail_closed() -> Result<(), String> {
        let mut broker = enforcing()?;
        let mut inferred = request(1);
        inferred.app.confidence = IdentityConfidence::Inferred;
        let outcome = immediate(
            broker
                .submit(
                    &NetworkPolicy::default(),
                    inferred,
                    100,
                    true,
                    &RouteAvailability::default(),
                )
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(outcome.instruction, NativeInstruction::Block);
        assert!(!outcome.enforced);
        let allowed_unknown = NetworkPolicy {
            firewall_rules: vec![FirewallRule {
                id: "unknown".to_owned(),
                name: "Explicit unknown permit".to_owned(),
                enabled: true,
                priority: 0,
                matcher: RuleMatcher {
                    unknown_process: true,
                    ..RuleMatcher::default()
                },
                action: FirewallAction::Allow,
            }],
            ..NetworkPolicy::default()
        };
        let mut unknown = request(2);
        unknown.app.process_path = None;
        let permitted = immediate(
            broker
                .submit(&allowed_unknown, unknown, 100, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(permitted.instruction, NativeInstruction::Allow);
        assert!(permitted.requires_native_ack);
        let vpn_policy = NetworkPolicy {
            defaults: PolicyDefaults {
                firewall: FirewallAction::Allow,
                route: RouteAction::Vpn { required: true },
            },
            ..NetworkPolicy::default()
        };
        let blocked = immediate(
            broker
                .submit(
                    &vpn_policy,
                    request(3),
                    100,
                    true,
                    &RouteAvailability {
                        vpn_ready: true,
                        ..RouteAvailability::default()
                    },
                )
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(blocked.instruction, NativeInstruction::Block);
        assert!(blocked.route.is_none());
        Ok(())
    }

    #[test]
    fn prompts_are_bounded_deadline_clamped_and_fail_closed_on_ui_loss() -> Result<(), String> {
        let mut broker = enforcing()?;
        let prompt = pending(
            broker
                .submit(&ask_policy(), request(1), 100, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(prompt.deadline_ms, 1100);
        let overflow = immediate(
            broker
                .submit(&ask_policy(), request(2), 100, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(overflow.instruction, NativeInstruction::Block);
        let timed_out = broker.expire(1100);
        assert_eq!(timed_out.len(), 1);
        assert_eq!(timed_out[0].instruction, NativeInstruction::Block);
        pending(
            broker
                .submit(&ask_policy(), request(3), 1200, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(broker.ui_disconnected().len(), 1);
        let no_ui = immediate(
            broker
                .submit(&ask_policy(), request(4), 1200, false, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        assert_eq!(no_ui.instruction, NativeInstruction::Block);
        Ok(())
    }

    #[test]
    fn replies_reject_stale_generation_expiration_replay_and_route_loss() -> Result<(), String> {
        let mut broker = enforcing()?;
        let policy = ask_policy();
        let prompt = pending(
            broker
                .submit(&policy, request(1), 100, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        let reply = DecisionReply {
            schema_version: 1,
            key: prompt.key,
            policy_generation: 0,
            verdict: ReplyVerdict::Allow,
        };
        let allowed = broker
            .reply(&policy, reply.clone(), 200, &RouteAvailability::default())
            .map_err(|error| error.reason)?;
        assert_eq!(allowed.instruction, NativeInstruction::Allow);
        assert!(!allowed.enforced);
        assert!(
            broker
                .reply(&policy, reply, 300, &RouteAvailability::default())
                .is_err()
        );
        assert!(
            broker
                .submit(&policy, request(1), 300, true, &RouteAvailability::default())
                .is_err()
        );
        let prompt = pending(
            broker
                .submit(&policy, request(2), 300, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        let stale = DecisionReply {
            schema_version: 1,
            key: prompt.key,
            policy_generation: 1,
            verdict: ReplyVerdict::Allow,
        };
        assert!(
            broker
                .reply(&policy, stale, 400, &RouteAvailability::default())
                .is_err()
        );
        let prompt = pending(
            broker
                .submit(&policy, request(3), 400, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        assert!(
            broker
                .reply(
                    &policy,
                    DecisionReply {
                        schema_version: 1,
                        key: prompt.key,
                        policy_generation: 0,
                        verdict: ReplyVerdict::Allow
                    },
                    1400,
                    &RouteAvailability::default()
                )
                .is_err()
        );
        let mut vpn = policy;
        vpn.defaults.route = RouteAction::Vpn { required: true };
        let prompt = pending(
            broker
                .submit(&vpn, request(4), 1500, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        let blocked = broker
            .reply(
                &vpn,
                DecisionReply {
                    schema_version: 1,
                    key: prompt.key,
                    policy_generation: 0,
                    verdict: ReplyVerdict::Allow,
                },
                1600,
                &RouteAvailability::default(),
            )
            .map_err(|error| error.reason)?;
        assert_eq!(blocked.instruction, NativeInstruction::Block);
        assert!(blocked.route.is_none());
        Ok(())
    }

    #[test]
    fn strict_requests_and_generation_changes_cannot_keep_old_prompts() -> Result<(), String> {
        let mut value = serde_json::to_value(request(1)).map_err(|error| error.to_string())?;
        value["untrustedOverride"] = serde_json::json!(true);
        assert!(serde_json::from_value::<DecisionRequest>(value).is_err());
        let mut broker = enforcing()?;
        pending(
            broker
                .submit(&ask_policy(), request(1), 100, true, &RouteAvailability::default())
                .map_err(|error| error.reason)?,
        )?;
        let blocked = broker.policy_changed(1);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].instruction, NativeInstruction::Block);
        let policy = NetworkPolicy {
            generation: 1,
            ..NetworkPolicy::default()
        };
        let mut request = request(2);
        request.policy_generation = 1;
        let uncommitted = broker.submit(&policy, request, 200, true, &RouteAvailability::default());
        assert!(uncommitted.as_ref().is_err_and(|failure| failure.native_block_required));
        broker.adapter_disconnected();
        let mut stale = self::request(3);
        stale.policy_generation = 1;
        assert!(
            broker
                .submit(&policy, stale, 300, true, &RouteAvailability::default())
                .is_err()
        );
        Ok(())
    }
}
