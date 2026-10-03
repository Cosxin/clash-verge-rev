use crate::{core::handle::Handle, process::AsyncHandler, utils::dirs};
use clash_verge_network::{FlowSample, HistoryLimits, NativeAdapterStatus, NetworkPolicy, NetworkStore};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, OnceCell};

static STATE: OnceCell<Mutex<NetworkState>> = OnceCell::const_new();
static STARTED: AtomicBool = AtomicBool::new(false);

#[cfg(all(test, feature = "clippy"))]
pub(crate) fn initialize_test_store(path: PathBuf, store: NetworkStore) -> Result<(), String> {
    STATE
        .set(Mutex::new(NetworkState {
            store,
            path,
            epoch: "ipc-test-epoch".to_owned(),
            recording_epoch: "ipc-test-recording-epoch".to_owned(),
            last_sample_at: None,
            sample_error: None,
            storage_error: None,
            writable: true,
            samples_since_save: 0,
            native_status: NativeAdapterStatus::unavailable("No authenticated native provider"),
            native_error: None,
        }))
        .map_err(|_| "Network workspace test state was already initialized".to_owned())
}

pub struct NetworkState {
    pub store: NetworkStore,
    path: PathBuf,
    epoch: String,
    recording_epoch: String,
    last_sample_at: Option<u64>,
    sample_error: Option<String>,
    storage_error: Option<String>,
    writable: bool,
    samples_since_save: u32,
    native_status: NativeAdapterStatus,
    native_error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkCapabilities {
    native_firewall: bool,
    per_app_routing: bool,
    whole_system_monitor: bool,
    kill_switch: bool,
    core_history: bool,
    native_monitor: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkWorkspace {
    schema_version: u32,
    policy: NetworkPolicy,
    capabilities: NetworkCapabilities,
    effective_mode: &'static str,
    coverage: &'static str,
    adapter_reason: &'static str,
    os: &'static str,
    recording_enabled: bool,
    retention_days: u32,
    max_records: usize,
    last_sample_at: Option<u64>,
    last_error: Option<String>,
    gap_count: u64,
    dropped_records: u64,
    storage_writable: bool,
    sample_interval_ms: u64,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub async fn state() -> Result<&'static Mutex<NetworkState>, String> {
    STATE
        .get_or_try_init(|| async {
            let path = dirs::app_home_dir()
                .map_err(|error| error.to_string())?
                .join("network-workspace")
                .join("workspace.json");
            let load_path = path.clone();
            let loaded = AsyncHandler::spawn_blocking(move || NetworkStore::load(&load_path, now_ms()))
                .await
                .map_err(|error| error.to_string())?;
            let (store, storage_error, writable) = match loaded {
                Ok(store) => (store, None, true),
                Err(error) => (
                    NetworkStore::default(),
                    Some(format!(
                        "Cannot load network workspace; original file preserved: {error}"
                    )),
                    false,
                ),
            };
            Ok(Mutex::new(NetworkState {
                store,
                path,
                epoch: nanoid::nanoid!(),
                recording_epoch: nanoid::nanoid!(),
                last_sample_at: None,
                sample_error: None,
                storage_error,
                writable,
                samples_since_save: 0,
                native_status: NativeAdapterStatus::unavailable("No authenticated native provider"),
                native_error: None,
            }))
        })
        .await
}

impl NetworkState {
    pub const fn is_writable(&self) -> bool {
        self.writable
    }

    pub fn view(&self) -> NetworkWorkspace {
        NetworkWorkspace {
            schema_version: 1,
            policy: self.store.policy.clone(),
            capabilities: NetworkCapabilities {
                native_firewall: self.native_status.can_apply_bans(),
                per_app_routing: false,
                whole_system_monitor: false,
                kill_switch: false,
                core_history: true,
                native_monitor: self.native_status.authenticated
                    && self.native_status.active
                    && self.native_status.monitoring,
            },
            effective_mode: "observe",
            coverage: if self.native_status.authenticated && self.native_status.active && self.native_status.monitoring
            {
                "native_tcp_udp_and_core"
            } else {
                "core_only"
            },
            adapter_reason: "Draft policy preview, native executable bans, and core-only app routing are separate. Whole-IP monitoring, durable independent history, native app routing and kill-switch qualification are incomplete.",
            os: std::env::consts::OS,
            recording_enabled: self.store.recording_enabled,
            retention_days: self.store.limits.retention_days,
            max_records: self.store.limits.max_records,
            last_sample_at: self.last_sample_at,
            last_error: self
                .storage_error
                .clone()
                .or_else(|| self.native_error.clone())
                .or_else(|| self.sample_error.clone()),
            gap_count: self.store.history.gap_count,
            dropped_records: self.store.history.dropped_records,
            storage_writable: self.writable,
            sample_interval_ms: 2000,
        }
    }

    pub async fn commit(&mut self, next: NetworkStore) -> Result<(), String> {
        if !self.writable {
            return Err("Network workspace is read-only because its original file could not be loaded".to_owned());
        }
        let path = self.path.clone();
        let disk = next.clone();
        let saved = AsyncHandler::spawn_blocking(move || disk.save(&path))
            .await
            .map_err(|error| error.to_string())?;
        match saved {
            Ok(()) => {
                self.store = next;
                self.storage_error = None;
                self.samples_since_save = 0;
                Ok(())
            }
            Err(error) => {
                self.storage_error = Some(format!("Network history persistence failed: {error}"));
                Err(error)
            }
        }
    }

    pub async fn set_recording(&mut self, enabled: bool) -> Result<(), String> {
        let mut next = self.store.clone();
        next.recording_enabled = enabled;
        if !enabled {
            next.history.interrupt(now_ms(), false);
        }
        self.commit(next).await?;
        self.epoch = nanoid::nanoid!();
        self.recording_epoch.clone_from(&self.epoch);
        self.last_sample_at = None;
        self.sample_error = None;
        self.native_error = None;
        Ok(())
    }

    pub async fn set_limits(&mut self, limits: HistoryLimits) -> Result<(), String> {
        limits.validate()?;
        let mut next = self.store.clone();
        next.limits = limits;
        next.history.prune(now_ms(), &next.limits);
        self.commit(next).await
    }

    async fn native_outage(&mut self, recorder: &mut NativeRecorderCursor, reason: String) -> bool {
        self.native_error = Some(reason);
        if recorder.outage {
            return true;
        }
        let mut next = self.store.clone();
        next.history.interrupt_native(now_ms());
        if self.commit(next).await.is_err() {
            return false;
        }
        recorder.outage = true;
        true
    }
}

pub fn start() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    AsyncHandler::spawn(|| async {
        let Ok(state) = state().await else {
            return;
        };
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if Handle::global().is_exiting() {
                return;
            }
            let epoch = {
                let current = state.lock().await;
                if !current.store.recording_enabled {
                    continue;
                }
                current.epoch.clone()
            };
            let result = tokio::time::timeout(Duration::from_secs(3), Handle::mihomo().get_connections()).await;
            let mut current = state.lock().await;
            if !current.store.recording_enabled || current.epoch != epoch {
                continue;
            }
            match result {
                Ok(Ok(snapshot)) => {
                    let samples: Vec<FlowSample> = snapshot
                        .connections
                        .unwrap_or_default()
                        .into_iter()
                        .map(|connection| FlowSample {
                            core_id: connection.id,
                            start: connection.start,
                            process: connection.metadata.process,
                            process_path: connection.metadata.process_path,
                            host: connection.metadata.host,
                            source_ip: connection.metadata.source_ip,
                            source_port: connection.metadata.source_port,
                            uid: Some(connection.metadata.uid),
                            destination_ip: connection.metadata.destination_ip,
                            destination_port: connection.metadata.destination_port,
                            network: connection.metadata.network.as_str().to_owned(),
                            upload: connection.upload,
                            download: connection.download,
                            chains: connection.chains,
                            rule: connection.rule,
                            rule_payload: connection.rule_payload,
                        })
                        .collect();
                    let limits = current.store.limits.clone();
                    current.store.history.sample(&epoch, &samples, now_ms(), &limits);
                    current.last_sample_at = Some(now_ms());
                    current.sample_error = None;
                    current.samples_since_save += 1;
                    if current.samples_since_save >= 5 {
                        let next = current.store.clone();
                        let _ = current.commit(next).await;
                    }
                }
                _ => {
                    if current.sample_error.is_none() {
                        current.store.history.interrupt_core(now_ms());
                        current.epoch = nanoid::nanoid!();
                        let next = current.store.clone();
                        let _ = current.commit(next).await;
                    }
                    current.sample_error =
                        Some("Core connection snapshot unavailable; recording has a coverage gap".to_owned());
                }
            }
        }
    });
    start_native_recorder();
}

#[derive(Default)]
struct NativeRecorderCursor {
    instance: String,
    recording_epoch: String,
    sequence: u64,
    dropped: u64,
    outage: bool,
}

impl NativeRecorderCursor {
    fn needs_baseline(&self, epoch: &str, status: &NativeAdapterStatus) -> bool {
        self.recording_epoch != epoch || self.instance != status.instance_id
    }

    fn baseline(&mut self, epoch: &str, status: &NativeAdapterStatus) {
        self.instance.clone_from(&status.instance_id);
        epoch.clone_into(&mut self.recording_epoch);
        self.sequence = status.event_sequence;
        self.dropped = status.dropped_events;
        self.outage = false;
    }
}

fn start_native_recorder() {
    AsyncHandler::spawn(|| async {
        let Ok(state) = state().await else {
            return;
        };
        let mut recorder = NativeRecorderCursor::default();
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if Handle::global().is_exiting() {
                return;
            }
            let status_epoch = state.lock().await.recording_epoch.clone();
            let status = super::native_firewall::status().await;
            let epoch = {
                let mut current = state.lock().await;
                current.native_status = status.clone();
                if !current.store.recording_enabled || !current.writable {
                    recorder = NativeRecorderCursor::default();
                    drop(current);
                    continue;
                }
                if current.recording_epoch != status_epoch {
                    drop(current);
                    continue;
                }
                if !status.authenticated || !status.active || !status.monitoring {
                    if !recorder.instance.is_empty() {
                        let reason = if status.reason.is_empty() {
                            "Native provider unavailable; recording has a coverage gap".to_owned()
                        } else {
                            status.reason.clone()
                        };
                        current.native_outage(&mut recorder, reason).await;
                    }
                    drop(current);
                    continue;
                }
                let epoch = current.recording_epoch.clone();
                if recorder.needs_baseline(&epoch, &status) {
                    if !recorder.instance.is_empty()
                        && recorder.instance != status.instance_id
                        && !current
                            .native_outage(
                                &mut recorder,
                                "Native provider instance changed; recording has a coverage gap".to_owned(),
                            )
                            .await
                    {
                        drop(current);
                        continue;
                    }
                    // Never persist a provider's pre-enable ring or advance past an unpersisted interruption.
                    recorder.baseline(&epoch, &status);
                    current.native_error = None;
                    drop(current);
                    continue;
                }
                drop(current);
                epoch
            };
            let result = super::native_firewall::events(recorder.sequence).await;
            let mut current = state.lock().await;
            if !current.store.recording_enabled || current.recording_epoch != epoch {
                drop(current);
                continue;
            }
            match result {
                Ok(batch) if batch.instance_id == recorder.instance => {
                    let limits = current.store.limits.clone();
                    let mut next = current.store.clone();
                    if batch.dropped_events > recorder.dropped && !recorder.outage {
                        next.history.interrupt_native(now_ms());
                    }
                    let mut error = None;
                    for event in &batch.events {
                        if let Err(failure) =
                            next.history
                                .native_event(&recorder.instance, &status.platform, event, &limits)
                        {
                            error = Some(failure);
                            break;
                        }
                    }
                    if let Some(error) = error {
                        current.native_outage(&mut recorder, error).await;
                        drop(current);
                        continue;
                    }
                    let nonempty = !batch.events.is_empty();
                    if (!nonempty && batch.dropped_events == recorder.dropped) || current.commit(next).await.is_ok() {
                        if nonempty {
                            recorder.sequence = batch.next_sequence;
                            current.last_sample_at = Some(now_ms());
                        }
                        recorder.dropped = batch.dropped_events;
                        recorder.outage = false;
                        current.native_error = None;
                    }
                    drop(current);
                }
                result => {
                    let reason = match result {
                        Err(error) => error,
                        _ => "Native provider instance changed during event read; recording has a gap".to_owned(),
                    };
                    current.native_outage(&mut recorder, reason).await;
                    drop(current);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_verge_network::{HistoryState, NativeFlowEvent};
    use serde_json::json;

    #[tokio::test]
    async fn native_recording_skips_disabled_backlogs_and_persists_one_outage() -> Result<(), String> {
        let directory = std::env::temp_dir().join(format!("native-recorder-{}", nanoid::nanoid!()));
        let path = directory.join("workspace.json");
        let mut current = NetworkState {
            store: NetworkStore {
                recording_enabled: true,
                ..NetworkStore::default()
            },
            path: path.clone(),
            epoch: "core-epoch".to_owned(),
            recording_epoch: "recording-epoch".to_owned(),
            last_sample_at: None,
            sample_error: None,
            storage_error: None,
            writable: true,
            samples_since_save: 0,
            native_status: NativeAdapterStatus::unavailable("fixture"),
            native_error: None,
        };
        let status = NativeAdapterStatus {
            instance_id: "native-instance".to_owned(),
            event_sequence: 10,
            dropped_events: 3,
            ..NativeAdapterStatus::unavailable("fixture")
        };
        let mut recorder = NativeRecorderCursor::default();
        recorder.baseline(&current.recording_epoch, &status);
        current.epoch = "core-outage-epoch".to_owned();
        assert!(!recorder.needs_baseline(&current.recording_epoch, &status));
        current.set_recording(false).await?;
        current.set_recording(true).await?;
        assert!(recorder.needs_baseline(&current.recording_epoch, &status));
        let resumed = NativeAdapterStatus {
            event_sequence: 50,
            dropped_events: 7,
            ..status
        };
        recorder.baseline(&current.recording_epoch, &resumed);
        assert_eq!((recorder.sequence, recorder.dropped), (50, 7));

        let now = now_ms();
        let core: FlowSample = serde_json::from_value(json!({
            "coreId":"core-flow","start":"fixture","process":"core-app","processPath":"/bin/core-app",
            "host":"","destinationIp":"192.0.2.2","destinationPort":"443","network":"tcp",
            "upload":0,"download":0,"chains":[],"rule":"MATCH","rulePayload":""
        }))
        .map_err(|error| error.to_string())?;
        let native: NativeFlowEvent = serde_json::from_value(json!({
            "flowId":"native-flow","sequence":51,"timeMs":now,"processPath":"/bin/native-app",
            "identityConfidence":"inferred","sourceIp":"192.0.2.1","sourcePort":50100,
            "destinationIp":"192.0.2.2","destinationPort":443,"network":"tcp",
            "packetBytes":40,"direction":"outbound","verdict":"allow","policyGeneration":1
        }))
        .map_err(|error| error.to_string())?;
        let limits = current.store.limits.clone();
        current.store.history.sample(&current.epoch, &[core], now, &limits);
        current
            .store
            .history
            .native_event(&recorder.instance, "linux", &native, &limits)?;
        assert!(current.native_outage(&mut recorder, "provider lost".to_owned()).await);
        assert!(
            current
                .native_outage(&mut recorder, "provider still lost".to_owned())
                .await
        );
        let persisted: NetworkStore = serde_json::from_slice(&std::fs::read(&path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
        assert_eq!(persisted.history.gap_count, 1);
        for record in &persisted.history.records {
            assert_eq!(
                record.state,
                if record.source == "mihomo" {
                    HistoryState::Active
                } else {
                    HistoryState::EndedIncomplete
                }
            );
        }
        recorder.baseline(&current.recording_epoch, &resumed);
        let denied = directory.join("not-a-directory");
        std::fs::write(&denied, b"fixture").map_err(|error| error.to_string())?;
        current.path = denied.join("workspace.json");
        assert!(
            !current
                .native_outage(&mut recorder, "provider lost again".to_owned())
                .await
        );
        assert!(!recorder.outage);
        assert_eq!(recorder.sequence, 50);
        assert_eq!(current.store.history.gap_count, 1);
        std::fs::remove_file(denied).map_err(|error| error.to_string())?;
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
        std::fs::remove_dir(directory).map_err(|error| error.to_string())?;
        Ok(())
    }
}
