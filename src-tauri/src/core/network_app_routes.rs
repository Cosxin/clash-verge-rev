use crate::{
    config::Config,
    core::{CoreManager, handle::Handle, network_workspace},
};
use clash_verge_network::{APP_ROUTE_DEFAULT_SLOT, APP_ROUTE_SLOT_PREFIX, AppRoutingPolicy, app_route_slot};
use serde::Serialize;
use serde_yaml_ng::{Mapping, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Duration,
};
use tauri_plugin_mihomo::models::{Proxies, Rules};
use tokio::sync::Mutex;

static APPLY_LOCK: Mutex<()> = Mutex::const_new(());

tokio::task_local! {
    pub(crate) static APP_ROUTE_CANDIDATE: (String, AppRoutingPolicy);
}

fn candidate_for(profile_uid: &str) -> Option<AppRoutingPolicy> {
    APP_ROUTE_CANDIDATE
        .try_with(|(profile, policy)| (profile == profile_uid).then(|| policy.clone()))
        .ok()
        .flatten()
}

fn configured_names(config: &Mapping) -> BTreeSet<String> {
    ["proxies", "proxy-groups"]
        .into_iter()
        .flat_map(|key| {
            config
                .get(key)
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .filter_map(|item| item.get("name").and_then(Value::as_str).map(str::to_owned))
        })
        .chain(std::iter::once("DIRECT".to_owned()))
        .collect()
}

fn configured_routes(config: &Mapping) -> BTreeSet<String> {
    ["proxies", "proxy-groups"]
        .into_iter()
        .flat_map(|key| {
            config
                .get(key)
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
                .filter(|item| {
                    !matches!(
                        item.get("type")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_lowercase()
                            .as_str(),
                        "reject" | "reject-drop" | "pass" | "pass-rule" | "dns" | "compatible"
                    )
                })
                .filter_map(|item| item.get("name").and_then(Value::as_str).map(str::to_owned))
        })
        .filter(|name| !name.starts_with(APP_ROUTE_SLOT_PREFIX) && name != "GLOBAL")
        .chain(std::iter::once("DIRECT".to_owned()))
        .collect()
}

fn prefix_matches(expected: &[String], rules: &Rules) -> bool {
    rules.rules.len() >= expected.len()
        && expected.iter().zip(&rules.rules).all(|(expected, actual)| {
            if actual
                .extra
                .get("extra")
                .and_then(|value| value.get("disabled"))
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                return false;
            }
            let fields = expected.split(',').collect::<Vec<_>>();
            if fields[0] == "MATCH" {
                actual.rule_type.as_str() == "Match" && actual.proxy == fields[1]
            } else {
                actual.rule_type.as_str() == "ProcessPath" && actual.payload == fields[1] && actual.proxy == fields[2]
            }
        })
}

fn slot_choices(
    policy: &AppRoutingPolicy,
    available: &BTreeSet<String>,
    proxies: &Proxies,
) -> Result<BTreeMap<String, String>, String> {
    policy
        .managed_groups(available)?
        .into_iter()
        .map(|slot| {
            let proxy = proxies
                .proxies
                .get(&slot.name)
                .ok_or_else(|| format!("Managed selector {} is missing; setup is required", slot.name))?;
            let children = proxy.all.as_ref().ok_or("Managed route is not a selector")?;
            let selected = proxy.now.as_ref().ok_or("Managed selector has no selected route")?;
            let expected = slot.children.iter().collect::<BTreeSet<_>>();
            if proxy.proxy_type.as_str() != "Selector"
                || children.len() != expected.len()
                || children.iter().collect::<BTreeSet<_>>() != expected
                || !children.contains(selected)
            {
                return Err(format!(
                    "Managed selector {} does not match the configured routing slots",
                    slot.name
                ));
            }
            Ok((slot.name, selected.clone()))
        })
        .collect()
}

fn desired_choices(
    policy: &AppRoutingPolicy,
    available: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, String> {
    Ok(policy
        .managed_groups(available)?
        .into_iter()
        .map(|slot| (slot.name, slot.selected))
        .collect())
}

struct RouteActivity {
    applied: bool,
    apply_mode: &'static str,
    live: BTreeMap<String, String>,
    default: Option<String>,
}

fn route_activity(
    active: &AppRoutingPolicy,
    policy: &AppRoutingPolicy,
    slots: bool,
    available: &BTreeSet<String>,
    proxies: &Proxies,
    rules: &Rules,
    core_ready: bool,
) -> Result<RouteActivity, String> {
    let expected = if slots {
        active.managed_rules()?
    } else {
        active.compile(available)?
    };
    let prefix_active = core_ready && prefix_matches(&expected, rules);
    let targets_available = std::iter::once(&policy.default_route)
        .chain(policy.routes.iter().map(|route| &route.route))
        .all(|target| available.contains(target));
    let choices = (slots && prefix_active)
        .then(|| slot_choices(active, available, proxies))
        .transpose()
        .ok()
        .flatten();
    let mut live = BTreeMap::new();
    let default = if !slots && prefix_active {
        for (route, compiled) in active.routes.iter().zip(&expected) {
            if let Some((_, target)) = compiled.rsplit_once(',') {
                live.insert(route.process_path.clone(), target.to_owned());
            }
        }
        expected
            .last()
            .and_then(|compiled| compiled.strip_prefix("MATCH,"))
            .map(str::to_owned)
    } else {
        choices
            .as_ref()
            .and_then(|choices| choices.get(APP_ROUTE_DEFAULT_SLOT).cloned())
    };
    if let Some(choices) = &choices {
        for route in &active.routes {
            if let Some(selected) = choices.get(&app_route_slot(&route.process_path)) {
                live.insert(route.process_path.clone(), selected.clone());
            }
        }
    }
    Ok(RouteActivity {
        applied: active == policy
            && prefix_active
            && targets_available
            && (!slots || choices.as_ref() == Some(&desired_choices(policy, available)?)),
        apply_mode: if slots && prefix_active && targets_available && active.same_apps(policy) && choices.is_some() {
            "live"
        } else {
            "setup"
        },
        live,
        default,
    })
}

fn routes_from_proxies(configured: &BTreeSet<String>, proxies: &Proxies) -> BTreeSet<String> {
    proxies
        .proxies
        .iter()
        .filter(|(name, proxy)| {
            configured.contains(*name)
                && !name.starts_with(APP_ROUTE_SLOT_PREFIX)
                && name.as_str() != "GLOBAL"
                && !matches!(
                    proxy.proxy_type.as_str(),
                    "Reject" | "RejectDrop" | "Pass" | "PassRule" | "Dns" | "Compatible"
                )
        })
        .map(|(name, _)| name.clone())
        .chain(std::iter::once("DIRECT".to_owned()))
        .collect()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRouteCandidate {
    name: String,
    process_path: String,
    sources: Vec<String>,
    identity_confidence: &'static str,
    upload: u64,
    download: u64,
    active_connections: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRouteOption {
    name: String,
    kind: &'static str,
    #[serde(rename = "type")]
    proxy_type: String,
    selected: Option<String>,
    available: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRoutingWorkspace {
    schema_version: u32,
    policy: AppRoutingPolicy,
    profile_uid: Option<String>,
    profile_name: Option<String>,
    applied_generation: Option<u64>,
    applied_profile_uid: Option<String>,
    core_mode: Option<String>,
    process_lookup: Option<String>,
    status: &'static str,
    reason: String,
    storage_writable: bool,
    apps: Vec<AppRouteCandidate>,
    route_options: Vec<AppRouteOption>,
    apply_mode: &'static str,
    live_route_selections: BTreeMap<String, String>,
    default_route: Option<String>,
}

pub async fn enhance(mut config: Mapping, profile_uid: &str) -> anyhow::Result<Mapping> {
    let selected = if let Some(policy) = candidate_for(profile_uid) {
        Some((policy, true))
    } else {
        let current = network_workspace::state()
            .await
            .map_err(anyhow::Error::msg)?
            .lock()
            .await;
        if current.store.active_app_route_profile.as_deref() == Some(profile_uid) {
            current
                .store
                .active_app_routes
                .clone()
                .map(|policy| (policy, current.store.active_app_route_slots))
        } else {
            None
        }
    };
    if let Some((policy, slots)) = selected.filter(|(policy, _)| policy.enabled) {
        let names = configured_names(&config);
        let available = configured_routes(&config);
        let prefix = if slots {
            if names.iter().any(|name| name.starts_with(APP_ROUTE_SLOT_PREFIX)) {
                anyhow::bail!("Profile already defines reserved NetworkControl- proxy names; refusing to adopt them");
            }
            let groups = policy.managed_groups(&available).map_err(anyhow::Error::msg)?;
            let mut configured_groups = config
                .remove("proxy-groups")
                .and_then(|value| value.as_sequence().cloned())
                .unwrap_or_default();
            configured_groups.extend(groups.into_iter().map(|slot| {
                let mut group = Mapping::new();
                group.insert("name".into(), slot.name.into());
                group.insert("type".into(), "select".into());
                group.insert("hidden".into(), true.into());
                group.insert("default-selected".into(), slot.selected.into());
                group.insert(
                    "proxies".into(),
                    Value::Sequence(slot.children.into_iter().map(Value::String).collect()),
                );
                Value::Mapping(group)
            }));
            config.insert("proxy-groups".into(), Value::Sequence(configured_groups));
            policy.managed_rules()
        } else {
            policy.compile(&available)
        }
        .map_err(anyhow::Error::msg)?;
        let mut rules: Vec<Value> = prefix.into_iter().map(Value::String).collect();
        rules.extend(
            config
                .remove("rules")
                .and_then(|value| value.as_sequence().cloned())
                .unwrap_or_default(),
        );
        config.insert("rules".into(), Value::Sequence(rules));
        config.insert("find-process-mode".into(), "always".into());
    }
    Ok(config)
}

async fn profile() -> (Option<String>, Option<String>) {
    let profiles = Config::profiles().await.data_arc();
    let uid = profiles.current.as_ref().map(ToString::to_string);
    let name = profiles
        .current
        .as_ref()
        .and_then(|uid| profiles.get_item(uid).ok())
        .and_then(|item| item.name.as_ref())
        .map(ToString::to_string);
    (uid, name)
}

pub async fn view() -> Result<AppRoutingWorkspace, String> {
    let (policy, active, active_profile, active_slots, writable, records) = {
        let current = network_workspace::state().await?.lock().await;
        (
            current.store.app_routes.clone(),
            current.store.active_app_routes.clone(),
            current.store.active_app_route_profile.clone(),
            current.store.active_app_route_slots,
            current.is_writable(),
            current.store.history.records.clone(),
        )
    };
    let (profile_uid, profile_name) = profile().await;
    let disable_pending =
        !policy.enabled && active.as_ref().is_some_and(|active| active.enabled) && active_profile == profile_uid;
    let mut apps = BTreeMap::<String, AppRouteCandidate>::new();
    let history_ids: BTreeSet<_> = records
        .iter()
        .filter(|record| record.source == "mihomo")
        .map(|record| (record.core_id.clone(), record.start.clone()))
        .collect();
    for record in records {
        if record.process_path.is_empty() {
            continue;
        }
        let app = apps
            .entry(record.process_path.clone())
            .or_insert_with(|| AppRouteCandidate {
                name: if record.process.is_empty() {
                    record.process_path.clone()
                } else {
                    record.process.clone()
                },
                process_path: record.process_path.clone(),
                sources: vec!["history".to_owned()],
                identity_confidence: "inferred",
                upload: 0,
                download: 0,
                active_connections: 0,
            });
        // Route counters describe the core path only; a native observation may
        // describe the same flow and cannot be added to it.
        if record.source == "mihomo" {
            app.upload = app.upload.saturating_add(record.observed_upload);
            app.download = app.download.saturating_add(record.observed_download);
        }
        if record.state == clash_verge_network::HistoryState::Active {
            app.active_connections += 1;
        }
    }
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(
            Handle::mihomo().get_proxies(),
            Handle::mihomo().get_base_config(),
            Handle::mihomo().get_rules(),
            Handle::mihomo().get_connections()
        )
    })
    .await;
    let mut options = vec![AppRouteOption {
        name: "DIRECT".to_owned(),
        kind: "direct",
        proxy_type: "Direct".to_owned(),
        selected: None,
        available: true,
    }];
    let (mut core_mode, mut lookup) = (None, None);
    let mut applied = false;
    let mut apply_mode = "setup";
    let mut live_route_selections = BTreeMap::new();
    let mut default_route = None;
    let reason = if let Ok((Ok(proxies), Ok(config), Ok(rules), connections)) = result {
        for app in apps.values_mut() {
            app.active_connections = 0;
        }
        if let Ok(snapshot) = connections {
            for connection in snapshot.connections.unwrap_or_default() {
                let metadata = connection.metadata;
                if metadata.process_path.is_empty() {
                    continue;
                }
                let app = apps
                    .entry(metadata.process_path.clone())
                    .or_insert_with(|| AppRouteCandidate {
                        name: if metadata.process.is_empty() {
                            metadata.process_path.clone()
                        } else {
                            metadata.process
                        },
                        process_path: metadata.process_path,
                        sources: Vec::new(),
                        identity_confidence: "inferred",
                        upload: 0,
                        download: 0,
                        active_connections: 0,
                    });
                if !app.sources.iter().any(|source| source == "running") {
                    app.sources.push("running".to_owned());
                }
                app.active_connections += 1;
                if !history_ids.contains(&(connection.id, connection.start)) {
                    app.upload = app.upload.saturating_add(connection.upload);
                    app.download = app.download.saturating_add(connection.download);
                }
            }
        }
        core_mode = serde_json::to_value(&config.mode)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned));
        lookup = serde_json::to_value(&config.find_process_mode)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned));
        let configured = Config::runtime()
            .await
            .data_arc()
            .config
            .as_ref()
            .map(configured_routes)
            .unwrap_or_default();
        options.extend(
            proxies
                .proxies
                .iter()
                .filter(|(name, proxy)| {
                    configured.contains(*name)
                        && !name.starts_with(APP_ROUTE_SLOT_PREFIX)
                        && name.as_str() != "DIRECT"
                        && name.as_str() != "GLOBAL"
                        && !matches!(
                            proxy.proxy_type.as_str(),
                            "Reject" | "RejectDrop" | "Pass" | "PassRule" | "Dns" | "Compatible"
                        )
                })
                .map(|(name, proxy)| AppRouteOption {
                    name: name.clone(),
                    kind: if proxy.all.is_some() { "group" } else { "node" },
                    proxy_type: proxy.proxy_type.as_str().to_owned(),
                    selected: proxy.now.clone(),
                    available: true,
                }),
        );
        options.sort_by(|left, right| left.name.cmp(&right.name));
        let available = options
            .iter()
            .map(|option| option.name.clone())
            .collect::<BTreeSet<_>>();
        let missing_route = policy.enabled
            && std::iter::once(&policy.default_route)
                .chain(policy.routes.iter().map(|rule| &rule.route))
                .any(|route| !available.contains(route));
        if let Some(active) = active
            .as_ref()
            .filter(|active| active.enabled && active_profile == profile_uid)
        {
            let observation = route_activity(
                active,
                &policy,
                active_slots,
                &available,
                &proxies,
                &rules,
                core_mode.as_deref() == Some("rule") && lookup.as_deref() == Some("always"),
            )?;
            apply_mode = observation.apply_mode;
            applied = observation.applied;
            live_route_selections = observation.live;
            default_route = observation.default;
        }
        if disable_pending { "Disable saved but not applied: previous application routing remains active for this profile. Apply to restore the profile rules." }
            else if missing_route { "An assigned route disappeared; its live selection is not confirmed active. Choose a current route and review setup before applying. Missing targets at setup use REJECT, not DIRECT." }
            else if applied { "Applied to new connections entering Mihomo; traffic bypassing the core is not routed. Existing connections are not guaranteed to move." }
            else if core_mode.as_deref() != Some("rule") { "Switch Mihomo to Rule mode before applying; this screen does not change mode, TUN, system proxy or profile." }
            else { "Saved assignments are not confirmed active for this profile. Apply explicitly; process identity is engine-inferred." }.to_owned()
    } else {
        "Core unavailable; saved assignments are not confirmed applied".to_owned()
    };
    Ok(AppRoutingWorkspace {
        schema_version: 1,
        policy: policy.clone(),
        profile_uid: profile_uid.clone(),
        profile_name,
        applied_generation: applied.then_some(policy.generation),
        applied_profile_uid: if applied { profile_uid } else { None },
        core_mode,
        process_lookup: lookup,
        status: if applied {
            "applied"
        } else if !policy.enabled && !disable_pending {
            "disabled"
        } else {
            "saved"
        },
        reason,
        storage_writable: writable,
        apps: apps.into_values().collect(),
        route_options: options,
        apply_mode,
        live_route_selections,
        default_route,
    })
}

pub async fn save(mut policy: AppRoutingPolicy, expected_generation: u64) -> Result<AppRoutingWorkspace, String> {
    let _operation = APPLY_LOCK.lock().await;
    {
        let mut current = network_workspace::state().await?.lock().await;
        if current.store.app_routes.generation != expected_generation || policy.generation != expected_generation {
            return Err("App routing generation changed; refresh before saving".to_owned());
        }
        policy.validate()?;
        policy.generation = expected_generation
            .checked_add(1)
            .ok_or("App routing generation exhausted")?;
        let mut next = current.store.clone();
        next.app_routes = policy;
        current.commit(next).await?;
        drop(current);
    }
    view().await
}

async fn current_choices(
    policy: &AppRoutingPolicy,
    available: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, String> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (proxies, config, rules) = tokio::join!(
            Handle::mihomo().get_proxies(),
            Handle::mihomo().get_base_config(),
            Handle::mihomo().get_rules()
        );
        let proxies = proxies.map_err(|error| error.to_string())?;
        let config = config.map_err(|error| error.to_string())?;
        let rules = rules.map_err(|error| error.to_string())?;
        if serde_json::to_value(config.mode)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .as_deref()
            != Some("rule")
            || serde_json::to_value(config.find_process_mode)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .as_deref()
                != Some("always")
            || !prefix_matches(&policy.managed_rules()?, &rules)
            || routes_from_proxies(available, &proxies) != *available
        {
            return Err("Live routing prerequisites changed; no full reload was attempted".to_owned());
        }
        slot_choices(policy, available, &proxies)
    })
    .await
    .map_err(|_| "Timed out verifying routing selectors".to_owned())?
}

async fn select_slot(name: &str, target: &str) -> Result<(), String> {
    tokio::time::timeout(
        Duration::from_secs(5),
        Handle::mihomo().select_node_for_group(name, target),
    )
    .await
    .map_err(|_| format!("Timed out selecting route for {name}"))?
    .map_err(|error| error.to_string())
}

async fn rollback_choices(changes: &[(String, String, String)]) -> Result<(), String> {
    let mut errors = Vec::new();
    for (name, previous, attempted) in changes.iter().rev() {
        let result = async {
            let proxy = tokio::time::timeout(Duration::from_secs(5), Handle::mihomo().get_proxy_by_name(name))
                .await
                .map_err(|_| format!("Timed out inspecting {name} during rollback"))?
                .map_err(|error| error.to_string())?;
            if proxy.now.as_deref() == Some(previous) {
                return Ok(());
            }
            if proxy.now.as_deref() != Some(attempted) {
                return Err(format!(
                    "{name} changed outside this operation; rollback did not overwrite it"
                ));
            }
            select_slot(name, previous).await?;
            let proxy = tokio::time::timeout(Duration::from_secs(5), Handle::mihomo().get_proxy_by_name(name))
                .await
                .map_err(|_| format!("Timed out confirming rollback of {name}"))?
                .map_err(|error| error.to_string())?;
            if proxy.now.as_deref() != Some(previous) {
                return Err(format!("Rollback selection of {name} was not confirmed"));
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

async fn switch_choices(
    policy: &AppRoutingPolicy,
    available: &BTreeSet<String>,
    mut observed: BTreeMap<String, String>,
    changes: &mut Vec<(String, String, String)>,
) -> Result<(), String> {
    for (name, target) in desired_choices(policy, available)? {
        let previous = observed.get(&name).ok_or("Managed selector is missing")?.clone();
        if previous == target {
            continue;
        }
        if current_choices(policy, available).await? != observed {
            return Err("Routing selectors changed outside this operation; selection was not overwritten".to_owned());
        }
        changes.push((name.clone(), previous, target.clone()));
        select_slot(&name, &target).await?;
        observed.insert(name, target);
        if current_choices(policy, available).await? != observed {
            return Err("Routing selection was not acknowledged or changed outside this operation".to_owned());
        }
    }
    if current_choices(policy, available).await? != desired_choices(policy, available)? {
        return Err("Routing selections are not confirmed active".to_owned());
    }
    Ok(())
}

pub(crate) async fn confirm_restored_routes() -> Result<(), String> {
    let profile_uid = profile().await.0;
    let policy = {
        let current = network_workspace::state().await?.lock().await;
        current
            .store
            .active_app_routes
            .as_ref()
            .filter(|policy| {
                policy.enabled
                    && current.store.active_app_route_slots
                    && current.store.active_app_route_profile == profile_uid
            })
            .cloned()
    };
    if let Some(policy) = policy {
        let configured = Config::runtime()
            .await
            .data_arc()
            .config
            .as_ref()
            .map(configured_routes)
            .ok_or("Restored runtime configuration is unavailable")?;
        let proxies = tokio::time::timeout(Duration::from_secs(5), Handle::mihomo().get_proxies())
            .await
            .map_err(|_| "Timed out inspecting restored selector groups")?
            .map_err(|error| error.to_string())?;
        let available = routes_from_proxies(&configured, &proxies);
        let observed = current_choices(&policy, &available).await?;
        switch_choices(&policy, &available, observed, &mut Vec::new()).await?;
    }
    Ok(())
}

async fn apply_live(
    workspace: AppRoutingWorkspace,
    expected_profile_uid: String,
    available: BTreeSet<String>,
) -> Result<AppRoutingWorkspace, String> {
    let guard = {
        let started = CoreManager::global()
            .begin_app_route_update()
            .await
            .map_err(|error| error.to_string())?;
        match started {
            Ok(guard) => guard,
            Err(outcome) => return Err(format!("Live routing was not committed: {outcome}")),
        }
    };
    let previous = {
        let current = network_workspace::state().await?.lock().await;
        current
            .store
            .active_app_routes
            .as_ref()
            .filter(|previous| {
                current.store.active_app_route_slots
                    && current.store.active_app_route_profile.as_deref() == Some(&expected_profile_uid)
                    && previous.same_apps(&workspace.policy)
            })
            .cloned()
    }
    .ok_or("Live routing setup changed; review before applying")?;
    let observed = current_choices(&workspace.policy, &available).await?;
    if observed != desired_choices(&previous, &available)?
        && observed != desired_choices(&workspace.policy, &available)?
    {
        return Err(
            "Live routing selections changed outside this operation; refresh and review before applying".to_owned(),
        );
    }
    let mut changes = Vec::new();
    if let Err(error) = switch_choices(&workspace.policy, &available, observed, &mut changes).await {
        let rollback = rollback_choices(&changes).await;
        return Err(format!(
            "Live routing was not committed: {error}; selection rollback: {rollback:?}"
        ));
    }
    let committed = {
        let mut current = network_workspace::state().await?.lock().await;
        let mut next = current.store.clone();
        next.active_app_routes = Some(workspace.policy);
        next.active_app_route_profile = Some(expected_profile_uid);
        next.active_app_route_slots = true;
        current.commit(next).await
    };
    if let Err(error) = committed {
        let rollback = rollback_choices(&changes).await;
        return Err(format!(
            "Live routing persistence failed: {error}; selection rollback: {rollback:?}"
        ));
    }
    drop(guard);
    view().await
}

pub async fn apply(
    expected_generation: u64,
    expected_profile_uid: String,
    expected_apply_mode: String,
) -> Result<AppRoutingWorkspace, String> {
    let _operation = APPLY_LOCK.lock().await;
    let workspace = view().await?;
    if workspace.policy.generation != expected_generation
        || workspace.profile_uid.as_deref() != Some(&expected_profile_uid)
    {
        return Err("Routing policy or profile changed; review before applying".to_owned());
    }
    if !workspace.storage_writable || workspace.core_mode.as_deref() != Some("rule") {
        return Err(workspace.reason);
    }
    if workspace.apply_mode != expected_apply_mode || !matches!(expected_apply_mode.as_str(), "live" | "setup") {
        return Err("Routing apply mode changed; review the live-switch or setup warning again".to_owned());
    }
    let available: BTreeSet<_> = workspace
        .route_options
        .iter()
        .filter(|option| option.available)
        .map(|option| option.name.clone())
        .collect();
    if workspace.policy.enabled
        && std::iter::once(&workspace.policy.default_route)
            .chain(workspace.policy.routes.iter().map(|rule| &rule.route))
            .any(|route| !available.contains(route))
    {
        return Err("An assigned route is unavailable; choose a current route before applying".to_owned());
    }
    let _profile_write = crate::config::profiles::PROFILE_WRITE_LOCK.lock().await;
    if profile().await.0.as_deref() != Some(&expected_profile_uid) {
        return Err("Profile changed while applying routing".to_owned());
    }
    if expected_apply_mode == "live" {
        return apply_live(workspace, expected_profile_uid, available).await;
    }
    let guard = match CoreManager::global()
        .update_config_forced_with_app_routes(expected_profile_uid.clone(), workspace.policy.clone())
        .await
    {
        Ok(Ok(guard)) => guard,
        Ok(Err(outcome)) => return Err(format!("App routing was not committed: {outcome}")),
        Err(error) => return Err(format!("App routing was not committed: {error}")),
    };
    let mut changes = Vec::new();
    if workspace.policy.enabled {
        let acknowledgement = async {
            let observed = current_choices(&workspace.policy, &available).await?;
            switch_choices(&workspace.policy, &available, observed, &mut changes).await
        }
        .await;
        if let Err(error) = acknowledgement {
            let selections = rollback_choices(&changes).await;
            let previous = guard.restore_previous().await;
            return Err(format!(
                "Routing setup was not committed: {error}; selection rollback: {selections:?}; previous routing restore: {previous:?}"
            ));
        }
    }
    let committed = {
        let mut current = network_workspace::state().await?.lock().await;
        let mut next = current.store.clone();
        next.active_app_routes = Some(workspace.policy);
        next.active_app_route_profile = Some(expected_profile_uid);
        next.active_app_route_slots = true;
        current.commit(next).await
    };
    if let Err(error) = committed {
        let selections = rollback_choices(&changes).await;
        let rollback = guard.restore_previous().await;
        drop(guard);
        return Err(format!(
            "Routing persistence failed: {error}; selection rollback: {selections:?}; previous routing restore: {rollback:?}"
        ));
    }
    drop(guard);
    view().await
}

pub async fn resolve_path(path: String) -> Result<AppRouteCandidate, String> {
    clash_verge_network::AppBanPolicy {
        schema_version: 1,
        generation: 0,
        process_paths: vec![path.clone()],
    }
    .validate()?;
    let mut path = PathBuf::from(path);
    #[cfg(target_os = "macos")]
    if path.is_dir() && path.extension().is_some_and(|extension| extension == "app") {
        let info = path.join("Contents/Info.plist");
        if std::fs::metadata(&info).map_err(|error| error.to_string())?.len() > 1024 * 1024 {
            return Err("App bundle metadata exceeds size limit".to_owned());
        }
        let output = tokio::process::Command::new("/usr/libexec/PlistBuddy")
            .args(["-c", "Print :CFBundleExecutable"])
            .arg(info)
            .output()
            .await
            .map_err(|error| error.to_string())?;
        let name = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
        let name = name.trim();
        if !output.status.success() || name.is_empty() || name.contains(['/', '\\']) || name == "." || name == ".." {
            return Err("App bundle executable is invalid".to_owned());
        }
        path = path.join("Contents/MacOS").join(name);
    }
    let resolved = crate::process::AsyncHandler::spawn_blocking(move || dunce::canonicalize(path))
        .await
        .map_err(|error| error.to_string())?
        .map_err(|error| error.to_string())?;
    if !resolved.is_file() {
        return Err("Choose an executable file or macOS application bundle".to_owned());
    }
    let mut binary = tokio::fs::File::open(&resolved)
        .await
        .map_err(|error| error.to_string())?;
    let mut header = [0_u8; 4];
    tokio::io::AsyncReadExt::read_exact(&mut binary, &mut header)
        .await
        .map_err(|_| "Choose a native application binary; scripts run as their interpreter")?;
    #[cfg(target_os = "macos")]
    let native_binary = matches!(
        u32::from_be_bytes(header),
        0xfeed_face | 0xcefa_edfe | 0xfeed_facf | 0xcffa_edfe | 0xcafe_babe | 0xbeba_feca | 0xcafe_babf | 0xbfba_feca
    );
    #[cfg(target_os = "linux")]
    let native_binary = header == *b"\x7fELF";
    #[cfg(target_os = "windows")]
    let native_binary = header[..2] == *b"MZ";
    if !native_binary {
        return Err(
            "Choose a native application binary; scripts must be assigned through their interpreter".to_owned(),
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if resolved
            .metadata()
            .map_err(|error| error.to_string())?
            .permissions()
            .mode()
            & 0o111
            == 0
        {
            return Err("Selected application binary is not executable".to_owned());
        }
    }
    let process_path = resolved
        .to_str()
        .ok_or("Executable path is not valid Unicode")?
        .to_owned();
    let candidate = AppRoutingPolicy {
        routes: vec![clash_verge_network::AppRouteRule {
            process_path: process_path.clone(),
            route: "DIRECT".to_owned(),
        }],
        ..Default::default()
    };
    candidate.validate()?;
    Ok(AppRouteCandidate {
        name: resolved
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Application")
            .to_owned(),
        process_path,
        sources: vec!["installed".to_owned()],
        identity_confidence: "inferred",
        upload: 0,
        download: 0,
        active_connections: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managed_status_checks_actual_selection_and_complete_enabled_prefix() -> Result<(), String> {
        let policy = AppRoutingPolicy {
            enabled: true,
            default_route: "VPN-A".to_owned(),
            routes: vec![clash_verge_network::AppRouteRule {
                process_path: "/usr/bin/curl".to_owned(),
                route: "DIRECT".to_owned(),
            }],
            ..Default::default()
        };
        let available = BTreeSet::from(["DIRECT".to_owned(), "VPN-A".to_owned()]);
        let mut proxies = Proxies::default();
        for slot in policy.managed_groups(&available)? {
            proxies.proxies.insert(
                slot.name.clone(),
                tauri_plugin_mihomo::models::Proxy {
                    proxy_type: tauri_plugin_mihomo::models::ProxyType::Selector,
                    all: Some(slot.children),
                    now: Some(slot.selected),
                    name: slot.name,
                    ..Default::default()
                },
            );
        }
        let mut rules = Rules::default();
        for expected in policy.managed_rules()? {
            let fields = expected.split(',').collect::<Vec<_>>();
            let is_match = fields[0] == "MATCH";
            rules.rules.push(tauri_plugin_mihomo::models::Rule {
                rule_type: if is_match {
                    tauri_plugin_mihomo::models::RuleType::Match
                } else {
                    tauri_plugin_mihomo::models::RuleType::ProcessPath
                },
                payload: if is_match { String::new() } else { fields[1].to_owned() },
                proxy: if is_match { fields[1] } else { fields[2] }.to_owned(),
                ..Default::default()
            });
        }
        assert!(route_activity(&policy, &policy, true, &available, &proxies, &rules, true)?.applied);
        let inactive = route_activity(&policy, &policy, true, &available, &proxies, &rules, false)?;
        assert!(!inactive.applied);
        assert!(inactive.live.is_empty());
        assert!(inactive.default.is_none());
        assert_eq!(inactive.apply_mode, "setup");
        proxies
            .proxies
            .get_mut(APP_ROUTE_DEFAULT_SLOT)
            .ok_or("Missing test default")?
            .now = Some("DIRECT".to_owned());
        let observation = route_activity(&policy, &policy, true, &available, &proxies, &rules, true)?;
        assert!(!observation.applied);
        assert_eq!(observation.default.as_deref(), Some("DIRECT"));
        assert_eq!(observation.apply_mode, "live");
        rules.rules[1]
            .extra
            .insert("extra".to_owned(), serde_json::json!({"disabled":true}));
        assert_eq!(
            route_activity(&policy, &policy, true, &available, &proxies, &rules, true)?.apply_mode,
            "setup"
        );
        proxies
            .proxies
            .get_mut(APP_ROUTE_DEFAULT_SLOT)
            .ok_or("Missing test default")?
            .all = Some(vec!["DIRECT".to_owned()]);
        assert!(slot_choices(&policy, &available, &proxies).is_err());
        let mut legacy: Rules = serde_json::from_value(serde_json::json!({"rules":[
            {"type":"ProcessPath","payload":"/usr/bin/curl","proxy":"DIRECT"},
            {"type":"Match","proxy":"VPN-A"}
        ]}))
        .map_err(|error| error.to_string())?;
        let observed = route_activity(&policy, &policy, false, &available, &proxies, &legacy, true)?;
        assert!(observed.applied);
        assert_eq!(observed.apply_mode, "setup");
        assert_eq!(observed.live.get("/usr/bin/curl").map(String::as_str), Some("DIRECT"));
        assert_eq!(observed.default.as_deref(), Some("VPN-A"));
        legacy.rules[1].proxy = "REJECT".to_owned();
        let observed = route_activity(
            &policy,
            &policy,
            false,
            &BTreeSet::from(["DIRECT".to_owned()]),
            &proxies,
            &legacy,
            true,
        )?;
        assert_eq!(observed.default.as_deref(), Some("REJECT"));
        assert!(!observed.applied);
        assert_eq!(observed.apply_mode, "setup");
        assert!(
            route_activity(&policy, &policy, false, &available, &proxies, &legacy, true)?
                .default
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn interleaved_routing_candidates_do_not_leak_into_other_config_generations() {
        let first = AppRoutingPolicy {
            generation: 11,
            ..Default::default()
        };
        let second = AppRoutingPolicy {
            generation: 22,
            ..Default::default()
        };
        let barrier = tokio::sync::Barrier::new(2);
        let first_task = APP_ROUTE_CANDIDATE.scope(("profile".to_owned(), first.clone()), async {
            barrier.wait().await;
            tokio::task::yield_now().await;
            assert_eq!(candidate_for("profile"), Some(first.clone()));
            assert_eq!(candidate_for("different-profile"), None);
            tokio::spawn(async { assert_eq!(candidate_for("profile"), None) })
                .await
                .map_err(|error| error.to_string())
        });
        let second_task = APP_ROUTE_CANDIDATE.scope(("profile".to_owned(), second.clone()), async {
            barrier.wait().await;
            tokio::task::yield_now().await;
            assert_eq!(candidate_for("profile"), Some(second.clone()));
        });
        let (spawned, ()) = tokio::join!(first_task, second_task);
        assert_eq!(spawned, Ok(()));
        assert_eq!(candidate_for("profile"), None);
    }
}
