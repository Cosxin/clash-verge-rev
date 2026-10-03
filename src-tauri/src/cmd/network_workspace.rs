use super::{CmdResult, StringifyErr as _};
use crate::core::network_workspace::{self, NetworkWorkspace};
use clash_verge_network::lsrules::{LsExportReport, LsImportReport, export_lsrules, import_lsrules};
use clash_verge_network::{
    ConnectionHistory, HistoryLimits, HistoryPage, HistoryQuery, NativeAdapterStatus, NetworkPolicy, PolicyPreview,
    PreviewInput,
};

#[tauri::command]
pub async fn get_network_app_routes() -> CmdResult<crate::core::network_app_routes::AppRoutingWorkspace> {
    crate::core::network_app_routes::view().await.stringify_err()
}

#[tauri::command]
pub async fn save_network_app_routes(
    policy: clash_verge_network::AppRoutingPolicy,
    expected_generation: u64,
) -> CmdResult<crate::core::network_app_routes::AppRoutingWorkspace> {
    crate::core::network_app_routes::save(policy, expected_generation)
        .await
        .stringify_err()
}

#[tauri::command]
pub async fn apply_network_app_routes(
    expected_generation: u64,
    expected_profile_uid: String,
    expected_apply_mode: String,
) -> CmdResult<crate::core::network_app_routes::AppRoutingWorkspace> {
    crate::core::network_app_routes::apply(expected_generation, expected_profile_uid, expected_apply_mode)
        .await
        .stringify_err()
}

#[tauri::command]
pub async fn resolve_network_app_route_path(
    path: String,
) -> CmdResult<crate::core::network_app_routes::AppRouteCandidate> {
    crate::core::network_app_routes::resolve_path(path)
        .await
        .stringify_err()
}

#[tauri::command]
pub async fn get_native_firewall_status() -> CmdResult<NativeAdapterStatus> {
    Ok(crate::core::native_firewall::status().await)
}

#[tauri::command]
pub async fn set_native_app_ban(
    process_path: String,
    blocked: bool,
    expected_generation: u64,
    expected_instance_id: String,
) -> CmdResult<NativeAdapterStatus> {
    crate::core::native_firewall::set_app_ban(process_path, blocked, expected_generation, expected_instance_id)
        .await
        .stringify_err()
}

#[tauri::command]
pub async fn get_network_workspace() -> CmdResult<NetworkWorkspace> {
    Ok(network_workspace::state().await.stringify_err()?.lock().await.view())
}

#[tauri::command]
pub async fn save_network_policy(policy: NetworkPolicy, expected_generation: u64) -> CmdResult<NetworkPolicy> {
    let mut current = network_workspace::state().await.stringify_err()?.lock().await;
    let mut next = current.store.clone();
    next.replace_policy(policy, expected_generation).stringify_err()?;
    current.commit(next).await.stringify_err()?;
    Ok(current.store.policy.clone())
}

#[tauri::command]
pub async fn preview_network_policy(input: PreviewInput) -> CmdResult<PolicyPreview> {
    network_workspace::state()
        .await
        .stringify_err()?
        .lock()
        .await
        .store
        .policy
        .preview(&input)
        .stringify_err()
}

#[tauri::command]
pub async fn set_network_history_enabled(enabled: bool) -> CmdResult<NetworkWorkspace> {
    let mut current = network_workspace::state().await.stringify_err()?.lock().await;
    current.set_recording(enabled).await.stringify_err()?;
    Ok(current.view())
}

#[tauri::command]
pub async fn set_network_history_limits(retention_days: u32, max_records: usize) -> CmdResult<NetworkWorkspace> {
    let mut current = network_workspace::state().await.stringify_err()?.lock().await;
    current
        .set_limits(HistoryLimits {
            retention_days,
            max_records,
        })
        .await
        .stringify_err()?;
    Ok(current.view())
}

#[tauri::command]
pub async fn get_network_history(query: Option<HistoryQuery>) -> CmdResult<HistoryPage> {
    let current = network_workspace::state().await.stringify_err()?.lock().await;
    Ok(current.store.history.query(&query.unwrap_or_default()))
}

#[tauri::command]
pub async fn clear_network_history() -> CmdResult<()> {
    let mut current = network_workspace::state().await.stringify_err()?.lock().await;
    let mut next = current.store.clone();
    next.history = ConnectionHistory::default();
    current.commit(next).await.stringify_err()
}

#[tauri::command]
pub async fn export_network_history() -> CmdResult<String> {
    network_workspace::state()
        .await
        .stringify_err()?
        .lock()
        .await
        .store
        .history
        .export_redacted()
        .stringify_err()
}

#[tauri::command]
pub fn import_network_lsrules(content: String) -> CmdResult<LsImportReport> {
    import_lsrules(&content).stringify_err()
}

#[tauri::command]
pub fn export_network_lsrules(policy: NetworkPolicy) -> CmdResult<LsExportReport> {
    policy.validate().stringify_err()?;
    export_lsrules(&policy).stringify_err()
}

#[cfg(all(test, feature = "clippy"))]
mod tests {
    use super::*;
    use clash_verge_network::{FirewallAction, FirewallRule, FlowSample, RuleMatcher};
    use serde_json::{Value, json};
    use tauri::{
        WebviewWindow,
        ipc::{CallbackFn, InvokeBody},
        test::{INVOKE_KEY, MockRuntime, get_ipc_response, mock_builder, mock_context, noop_assets},
        webview::InvokeRequest,
    };

    fn invoke(window: &WebviewWindow<MockRuntime>, command: &str, arguments: Value) -> Result<Value, String> {
        let request = InvokeRequest {
            cmd: command.to_owned(),
            callback: CallbackFn(0),
            error: CallbackFn(1),
            url: if cfg!(windows) {
                "http://tauri.localhost"
            } else {
                "tauri://localhost"
            }
            .parse::<tauri::Url>()
            .map_err(|error| error.to_string())?,
            body: InvokeBody::Json(arguments),
            headers: Default::default(),
            invoke_key: INVOKE_KEY.to_owned(),
        };
        get_ipc_response(window, request)
            .map_err(|error| error.to_string())?
            .deserialize()
            .map_err(|error| error.to_string())
    }

    #[test]
    fn network_commands_roundtrip_drafts_and_history_without_native_activation() -> Result<(), String> {
        let now = network_workspace::now_ms();
        let directory = std::env::temp_dir().join(format!(
            "verge-network-ipc-{}-{}",
            std::process::id(),
            nanoid::nanoid!()
        ));
        let path = directory.join("workspace.json");
        let mut store = clash_verge_network::NetworkStore::default();
        store.history.sample(
            "fixture",
            &[FlowSample {
                core_id: "fixture".to_owned(),
                start: "2026-10-02T00:00:00Z".to_owned(),
                process: "Private".to_owned(),
                process_path: "/private/fixture".to_owned(),
                host: "private.example".to_owned(),
                source_ip: "127.0.0.1".to_owned(),
                source_port: "50001".to_owned(),
                uid: Some(501),
                destination_ip: "192.0.2.1".to_owned(),
                destination_port: "443".to_owned(),
                network: "tcp".to_owned(),
                upload: 100,
                download: 200,
                chains: Vec::new(),
                rule: "DOMAIN".to_owned(),
                rule_payload: "private.example".to_owned(),
            }],
            now,
            &store.limits,
        );
        network_workspace::initialize_test_store(path.clone(), store)?;
        let app = mock_builder()
            .invoke_handler(tauri::generate_handler![
                get_network_workspace,
                save_network_policy,
                preview_network_policy,
                set_network_history_enabled,
                set_network_history_limits,
                get_network_history,
                clear_network_history,
                export_network_history,
                import_network_lsrules,
                export_network_lsrules,
            ])
            .build(mock_context(noop_assets()))
            .map_err(|error| error.to_string())?;
        let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
            .build()
            .map_err(|error| error.to_string())?;
        let workspace = invoke(&window, "get_network_workspace", json!({}))?;
        assert_eq!(workspace["schemaVersion"], 1);
        assert_eq!(workspace["effectiveMode"], "observe");
        for capability in ["nativeFirewall", "perAppRouting", "wholeSystemMonitor", "killSwitch"] {
            assert_eq!(workspace["capabilities"][capability], false);
        }
        assert_eq!(workspace["recordingEnabled"], false);
        let policy = NetworkPolicy {
            firewall_rules: vec![FirewallRule {
                id: "ipc-rule".to_owned(),
                name: "IPC draft".to_owned(),
                enabled: true,
                priority: 100,
                matcher: RuleMatcher {
                    host: Some("example.com".to_owned()),
                    ..RuleMatcher::default()
                },
                action: FirewallAction::Block,
            }],
            ..NetworkPolicy::default()
        };
        let saved = invoke(
            &window,
            "save_network_policy",
            json!({"policy": policy, "expectedGeneration": 0}),
        )?;
        assert_eq!(saved["generation"], 1);
        assert!(
            invoke(
                &window,
                "save_network_policy",
                json!({"policy": policy, "expectedGeneration": 0})
            )
            .is_err()
        );
        let preview = invoke(
            &window,
            "preview_network_policy",
            json!({"input": {"host": "example.com", "identityConfidence": "unknown"}}),
        )?;
        assert_eq!(preview["firewall"], "block");
        assert_eq!(preview["enforced"], false);
        assert_eq!(preview["route"], Value::Null);
        let imported = invoke(
            &window,
            "import_network_lsrules",
            json!({"content": r#"{"rules":[{"process":"/test/app","action":"deny","remote-hosts":"example.com"}]}"#}),
        )?;
        assert_eq!(imported["acceptedCount"], 1);
        assert_eq!(imported["rules"][0]["matcher"]["processPath"], "/test/app");
        let export = invoke(&window, "export_network_lsrules", json!({"policy": saved}))?;
        assert_eq!(export["exportedCount"], 1);
        let limits = invoke(
            &window,
            "set_network_history_limits",
            json!({"retentionDays": 1, "maxRecords": 100}),
        )?;
        assert_eq!(limits["retentionDays"], 1);
        let history = invoke(
            &window,
            "get_network_history",
            json!({"query": {"search":"private.example", "offset":0, "limit":100}}),
        )?;
        assert_eq!(history["total"], 1);
        assert_eq!(history["observedUpload"], 0);
        let redacted = invoke(&window, "export_network_history", json!({}))?;
        let redacted = redacted.as_str().ok_or("History export must be a JSON string")?;
        assert!(!redacted.contains("private.example"));
        assert!(!redacted.contains("/private/fixture"));
        let enabled = invoke(&window, "set_network_history_enabled", json!({"enabled":true}))?;
        assert_eq!(enabled["recordingEnabled"], true);
        invoke(&window, "set_network_history_enabled", json!({"enabled":false}))?;
        invoke(&window, "clear_network_history", json!({}))?;
        assert_eq!(invoke(&window, "get_network_history", json!({}))?["total"], 0);
        let persisted = clash_verge_network::NetworkStore::load(&path, now)?;
        assert_eq!(persisted.policy.generation, 1);
        assert_eq!(persisted.limits.retention_days, 1);
        assert!(!persisted.recording_enabled);
        assert!(persisted.history.records.is_empty());
        std::fs::remove_file(&path).map_err(|error| error.to_string())?;
        std::fs::remove_dir(&directory).map_err(|error| error.to_string())?;
        Ok(())
    }
}
