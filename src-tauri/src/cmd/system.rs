use crate::core::{
    notification::{self, PendingFailure},
    runstate::{RUN_STATE, RunStateView},
};

/// Returns one coherent core/service snapshot instead of independently refreshed state.
#[tauri::command]
pub async fn get_runtime_state() -> Result<RunStateView, String> {
    Ok(RUN_STATE.settled().await.to_view())
}

/// Whether this build may change the host's system proxy, TUN, service or launch-at-login state.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildCapabilities {
    flavor: &'static str,
    host_network_changes: bool,
}

#[tauri::command]
pub const fn get_build_capabilities() -> BuildCapabilities {
    BuildCapabilities {
        flavor: if cfg!(feature = "network-dev") {
            "network-dev"
        } else if cfg!(feature = "network-control") {
            "network-control"
        } else {
            "upstream"
        },
        host_network_changes: !cfg!(feature = "network-dev"),
    }
}

#[tauri::command]
pub async fn get_pending_failures() -> Vec<PendingFailure> {
    notification::pending_failures()
}
