use crate::{
    config::Config,
    core::{CoreManager, handle::Handle, network_workspace},
};
use clash_verge_network::AppRoutingPolicy;
use serde::Serialize;
use serde_yaml_ng::{Mapping, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    time::Duration,
};
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

fn configured_routes(config: &Mapping) -> BTreeSet<String> {
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
}

pub async fn enhance(mut config: Mapping, profile_uid: &str) -> anyhow::Result<Mapping> {
    let policy = if let Some(policy) = candidate_for(profile_uid) {
        Some(policy)
    } else {
        let current = network_workspace::state()
            .await
            .map_err(anyhow::Error::msg)?
            .lock()
            .await;
        if current.store.active_app_route_profile.as_deref() == Some(profile_uid) {
            current.store.active_app_routes.clone()
        } else {
            None
        }
    };
    if let Some(policy) = policy.filter(|policy| policy.enabled) {
        let available = configured_routes(&config);
        let prefix = policy.compile(&available).map_err(anyhow::Error::msg)?;
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
    let (policy, active, active_profile, writable, records) = {
        let current = network_workspace::state().await?.lock().await;
        (
            current.store.app_routes.clone(),
            current.store.active_app_routes.clone(),
            current.store.active_app_route_profile.clone(),
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
                .into_iter()
                .filter(|(name, proxy)| {
                    configured.contains(name)
                        && name != "DIRECT"
                        && name != "GLOBAL"
                        && !matches!(
                            proxy.proxy_type.as_str(),
                            "Reject" | "RejectDrop" | "Pass" | "PassRule" | "Dns" | "Compatible"
                        )
                })
                .map(|(name, proxy)| AppRouteOption {
                    name,
                    kind: if proxy.all.is_some() { "group" } else { "node" },
                    proxy_type: proxy.proxy_type.as_str().to_owned(),
                    selected: proxy.now,
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
        if let Some(active) =
            active.filter(|active| active.enabled && active == &policy && active_profile == profile_uid)
        {
            let expected = active.compile(&available)?;
            applied = !missing_route
                && core_mode.as_deref() == Some("rule")
                && lookup.as_deref() == Some("always")
                && rules.rules.len() >= expected.len()
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
                    let fields: Vec<_> = expected.split(',').collect();
                    if fields[0] == "MATCH" {
                        actual.rule_type.as_str() == "Match" && actual.proxy == fields[1]
                    } else {
                        actual.rule_type.as_str() == "ProcessPath"
                            && actual.payload == fields[1]
                            && actual.proxy == fields[2]
                    }
                });
        }
        if disable_pending { "Disable saved but not applied: previous application routing remains active for this profile. Apply to restore the profile rules." }
            else if missing_route { "An assigned route disappeared. Previously applied assignments to missing targets are blocked with REJECT, not silently sent direct. Choose a current route and apply again." }
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

pub async fn apply(expected_generation: u64, expected_profile_uid: String) -> Result<AppRoutingWorkspace, String> {
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
    let guard = match CoreManager::global()
        .update_config_forced_with_app_routes(expected_profile_uid.clone(), workspace.policy.clone())
        .await
    {
        Ok(Ok(guard)) => guard,
        Ok(Err(outcome)) => return Err(format!("App routing was not committed: {outcome}")),
        Err(error) => return Err(format!("App routing was not committed: {error}")),
    };
    let committed = {
        let mut current = network_workspace::state().await?.lock().await;
        let mut next = current.store.clone();
        next.active_app_routes = Some(workspace.policy);
        next.active_app_route_profile = Some(expected_profile_uid);
        current.commit(next).await
    };
    if let Err(error) = committed {
        let rollback = guard.restore_previous().await;
        drop(guard);
        return Err(format!(
            "Routing persistence failed: {error}; previous routing restore: {rollback:?}"
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
    use super::{APP_ROUTE_CANDIDATE, AppRoutingPolicy, candidate_for};

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
