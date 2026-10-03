use crate::{core::handle::Handle, process::AsyncHandler, utils::dirs};
use clash_verge_network::{FlowSample, HistoryLimits, NativeAdapterStatus, NetworkPolicy, NetworkStore};
use serde::Serialize;
use std::{
    future::Future,
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

    async fn accept_native_page(
        &mut self,
        recorder: &mut NativeRecorderCursor,
        epoch: &str,
        platform: &str,
        result: Result<super::native_firewall::NativeEvents, String>,
    ) -> bool {
        if !self.store.recording_enabled || !self.writable || self.recording_epoch != epoch {
            return false;
        }
        let batch = match result {
            Ok(batch)
                if batch.instance_id == recorder.instance && self.native_status.instance_id == recorder.instance =>
            {
                batch
            }
            result => {
                let reason = result.err().unwrap_or_else(|| {
                    "Native provider instance changed during event read; recording has a gap".to_owned()
                });
                self.native_outage(recorder, reason).await;
                return false;
            }
        };
        let mut next = self.store.clone();
        let mut previous = recorder.sequence;
        let mut prior_outage = recorder.outage;
        for event in &batch.events {
            if previous.checked_add(1) != Some(event.sequence) {
                let gaps = next.history.gap_count;
                next.history.interrupt_native(now_ms());
                // A known outage covers the first boundary only, not distinct losses after newly observed flows.
                if prior_outage {
                    next.history.gap_count = gaps;
                }
            }
            prior_outage = false;
            previous = event.sequence;
            if let Err(error) = next
                .history
                .native_event(&recorder.instance, epoch, platform, event, &next.limits)
            {
                self.native_outage(recorder, error).await;
                return false;
            }
        }
        if !batch.events.is_empty() {
            if let Err(error) = self.commit(next).await {
                self.native_outage(recorder, error).await;
                return false;
            }
            recorder.sequence = batch.next_sequence;
            self.last_sample_at = Some(now_ms());
        }
        // Lifetime ring evictions include records this cursor already consumed; only sequence gaps prove missed events.
        recorder.dropped = batch.dropped_events;
        recorder.outage = false;
        self.native_error = None;
        batch.events.len() == NATIVE_PAGE_SIZE
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

const NATIVE_PAGE_SIZE: usize = 256;
const NATIVE_MAX_PAGES: usize = 8;
const NATIVE_DRAIN_BUDGET: Duration = Duration::from_secs(2);

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

async fn drain_native_events<F, R>(
    state: &Mutex<NetworkState>,
    recorder: &mut NativeRecorderCursor,
    epoch: &str,
    platform: &str,
    mut read: F,
) where
    F: FnMut(u64) -> R + Send,
    R: Future<Output = Result<super::native_firewall::NativeEvents, String>> + Send,
{
    let deadline = tokio::time::Instant::now() + NATIVE_DRAIN_BUDGET;
    for _ in 0..NATIVE_MAX_PAGES {
        let Ok(current) = tokio::time::timeout_at(deadline, state.lock()).await else {
            return;
        };
        if !current.store.recording_enabled || !current.writable || current.recording_epoch != epoch {
            return;
        }
        drop(current);
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        let result = tokio::time::timeout_at(deadline, read(recorder.sequence))
            .await
            .unwrap_or_else(|_| Err("Native event catch-up read timed out; recording has a coverage gap".to_owned()));
        let mut current = state.lock().await;
        if !current.accept_native_page(recorder, epoch, platform, result).await {
            return;
        }
        // Do not cancel a persistence operation: its blocking writer could otherwise race a later recording toggle.
        drop(current);
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
            drain_native_events(
                state,
                &mut recorder,
                &epoch,
                &status.platform,
                super::native_firewall::events,
            )
            .await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use clash_verge_network::{HistoryState, NativeFlowEvent};
    use serde_json::json;

    fn recorder_fixture() -> NetworkState {
        NetworkState {
            store: NetworkStore {
                recording_enabled: true,
                ..NetworkStore::default()
            },
            path: std::env::temp_dir()
                .join(format!("native-catch-up-{}", nanoid::nanoid!()))
                .join("workspace.json"),
            epoch: "core-epoch".to_owned(),
            recording_epoch: "recording-epoch".to_owned(),
            last_sample_at: None,
            sample_error: None,
            storage_error: None,
            writable: true,
            samples_since_save: 0,
            native_status: NativeAdapterStatus {
                instance_id: "native-instance".to_owned(),
                active: true,
                authenticated: true,
                monitoring: true,
                ..NativeAdapterStatus::unavailable("fixture")
            },
            native_error: None,
        }
    }

    fn native_page(
        instance: &str,
        start: u64,
        count: usize,
        dropped_events: u64,
    ) -> Result<super::super::native_firewall::NativeEvents, String> {
        let events: Vec<NativeFlowEvent> = (start..)
            .take(count)
            .map(|sequence| {
                serde_json::from_value(json!({
                    "flowId":"native-flow","sequence":sequence,"timeMs":now_ms(),"processPath":"/bin/native-app",
                    "identityConfidence":"inferred","sourceIp":"192.0.2.1","sourcePort":50100,
                    "destinationIp":"192.0.2.2","destinationPort":443,"network":"tcp",
                    "packetBytes":40,"direction":"outbound","verdict":"allow","policyGeneration":1
                }))
                .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()?;
        Ok(super::super::native_firewall::NativeEvents {
            instance_id: instance.to_owned(),
            next_sequence: events
                .last()
                .map_or_else(|| start.saturating_sub(1), |event| event.sequence),
            events,
            dropped_events,
        })
    }

    fn remove_recorder_fixture(path: &std::path::Path) -> Result<(), String> {
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
        std::fs::remove_dir(path.parent().ok_or("Fixture directory missing")?).map_err(|error| error.to_string())
    }

    fn saved_recorder_fixture(path: &std::path::Path) -> Result<NetworkStore, String> {
        serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())
    }

    #[tokio::test]
    async fn native_catch_up_drains_bounded_pages_without_false_eviction_gaps() -> Result<(), String> {
        let current = recorder_fixture();
        let path = current.path.clone();
        let mut recorder = NativeRecorderCursor::default();
        recorder.baseline(&current.recording_epoch, &current.native_status);
        let state = Mutex::new(current);
        let mut cursors = Vec::new();
        drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |after| {
            cursors.push(after);
            let count = if after < 512 { NATIVE_PAGE_SIZE } else { 3 };
            async move { native_page("native-instance", after + 1, count, 5000 + after) }
        })
        .await;
        assert_eq!(cursors, [0, 256, 512]);
        assert_eq!(recorder.sequence, 515);
        {
            let current = state.lock().await;
            assert_eq!(current.store.history.gap_count, 0);
            assert_eq!(current.store.history.records[0].observed_upload, 515 * 40);
        }
        cursors.clear();
        drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |after| {
            cursors.push(after);
            async move { native_page("native-instance", after + 1, NATIVE_PAGE_SIZE, 10_000 + after) }
        })
        .await;
        assert_eq!(cursors.len(), NATIVE_MAX_PAGES);
        assert_eq!(recorder.sequence, 515 + 2048);
        assert_eq!(state.lock().await.store.history.gap_count, 0);
        let before = std::fs::read(&path).map_err(|error| error.to_string())?;
        drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |after| async move {
            native_page("native-instance", after + 1, 0, 99_999)
        })
        .await;
        assert_eq!((recorder.sequence, recorder.dropped), (515 + 2048, 99_999));
        assert_eq!(std::fs::read(&path).map_err(|error| error.to_string())?, before);
        remove_recorder_fixture(&path)
    }

    #[tokio::test]
    async fn native_catch_up_missing_sequences_and_read_failures_persist_one_outage() -> Result<(), String> {
        let current = recorder_fixture();
        let path = current.path.clone();
        let mut recorder = NativeRecorderCursor::default();
        recorder.baseline(&current.recording_epoch, &current.native_status);
        let state = Mutex::new(current);
        drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |_| async {
            let mut page = native_page("native-instance", 1, 2, 0)?;
            page.events[1].sequence = 3;
            page.events[1].flow_id = "unrelated-flow".to_owned();
            page.next_sequence = 3;
            Ok(page)
        })
        .await;
        assert_eq!(recorder.sequence, 3);
        {
            let current = state.lock().await;
            assert_eq!(current.store.history.gap_count, 1);
            assert_eq!(current.store.history.records[0].state, HistoryState::EndedIncomplete);
            assert_eq!(current.store.history.records[1].state, HistoryState::Active);
        }
        for _ in 0..2 {
            drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |_| async {
                Err("Fixture provider unavailable".to_owned())
            })
            .await;
        }
        assert_eq!(recorder.sequence, 3);
        assert!(recorder.outage);
        assert_eq!(state.lock().await.store.history.gap_count, 2);
        drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |after| async move {
            let mut page = native_page("native-instance", after + 1, 2, 9999)?;
            page.events[0].flow_id = "prefix-after-outage".to_owned();
            page.events[1].sequence += 1;
            page.events[1].flow_id = "after-later-gap".to_owned();
            page.next_sequence = page.events[1].sequence;
            Ok(page)
        })
        .await;
        {
            let current = state.lock().await;
            assert_eq!(current.store.history.gap_count, 3);
            assert_eq!(current.store.history.records[2].state, HistoryState::EndedIncomplete);
            assert_eq!(current.store.history.records[3].state, HistoryState::Active);
        }
        drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |after| async move {
            native_page("native-instance", after + 1, 1, 9999)
        })
        .await;
        assert!(!recorder.outage);
        assert_eq!(recorder.sequence, 7);
        assert_eq!(state.lock().await.store.history.gap_count, 3);
        let saved = saved_recorder_fixture(&path)?;
        assert_eq!(saved.history.gap_count, 3);
        assert_eq!(
            saved
                .history
                .records
                .iter()
                .find(|record| record.core_id == "native-flow")
                .ok_or("Fixture native flow missing")?
                .observed_upload,
            80
        );
        remove_recorder_fixture(&path)
    }

    #[tokio::test(start_paused = true)]
    async fn native_catch_up_deadline_stops_reads_and_persists_timeout_once() -> Result<(), String> {
        let current = recorder_fixture();
        let path = current.path.clone();
        let mut recorder = NativeRecorderCursor::default();
        recorder.baseline(&current.recording_epoch, &current.native_status);
        let state = Mutex::new(current);
        let mut calls = 0;
        for _ in 0..2 {
            drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |_| {
                calls += 1;
                std::future::pending()
            })
            .await;
        }
        assert_eq!(calls, 2);
        assert_eq!(recorder.sequence, 0);
        assert!(recorder.outage);
        assert_eq!(state.lock().await.store.history.gap_count, 1);
        assert_eq!(saved_recorder_fixture(&path)?.history.gap_count, 1);
        remove_recorder_fixture(&path)
    }

    #[tokio::test]
    async fn native_catch_up_fences_toggle_restart_and_failed_persistence() -> Result<(), String> {
        let current = recorder_fixture();
        let path = current.path.clone();
        let mut recorder = NativeRecorderCursor::default();
        recorder.baseline(&current.recording_epoch, &current.native_status);
        let state = Mutex::new(current);
        drain_native_events(&state, &mut recorder, "recording-epoch", "linux", |after| {
            let state = &state;
            async move {
                if after != 0 {
                    let mut current = state.lock().await;
                    current.set_recording(false).await?;
                    current.set_recording(true).await?;
                    current.native_status.event_sequence = 1000;
                }
                native_page("native-instance", after + 1, NATIVE_PAGE_SIZE, 0)
            }
        })
        .await;
        assert_eq!(recorder.sequence, 256);
        let epoch = {
            let current = state.lock().await;
            assert_eq!(current.store.history.records[0].observed_upload, 256 * 40);
            recorder.baseline(&current.recording_epoch, &current.native_status);
            current.recording_epoch.clone()
        };
        assert_eq!(recorder.sequence, 1000);
        drain_native_events(&state, &mut recorder, &epoch, "linux", |after| {
            let state = &state;
            async move {
                if after == 1000 {
                    native_page("native-instance", after + 1, NATIVE_PAGE_SIZE, 0)
                } else {
                    let mut current = state.lock().await;
                    current.native_status.instance_id = "restarted-instance".to_owned();
                    current.native_status.event_sequence = 2000;
                    drop(current);
                    native_page("restarted-instance", 2001, 1, 0)
                }
            }
        })
        .await;
        assert_eq!(recorder.sequence, 1256);
        assert!(recorder.outage);
        let denied = path.with_file_name("not-a-directory");
        std::fs::write(&denied, b"fixture").map_err(|error| error.to_string())?;
        let before = std::fs::read(&path).map_err(|error| error.to_string())?;
        {
            let mut current = state.lock().await;
            assert_eq!(current.store.history.gap_count, 1);
            recorder.baseline(&current.recording_epoch, &current.native_status);
            current.path = denied.join("workspace.json");
        }
        drain_native_events(&state, &mut recorder, &epoch, "linux", |after| async move {
            native_page("restarted-instance", after + 1, 1, 10)
        })
        .await;
        assert_eq!((recorder.sequence, recorder.dropped), (2000, 0));
        assert!(!recorder.outage);
        {
            let current = state.lock().await;
            assert_eq!(current.store.history.records.len(), 2);
            assert_eq!(current.store.history.gap_count, 1);
            assert!(current.storage_error.is_some());
            drop(current);
        }
        assert_eq!(std::fs::read(&path).map_err(|error| error.to_string())?, before);
        std::fs::remove_file(denied).map_err(|error| error.to_string())?;
        remove_recorder_fixture(&path)
    }

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
            .native_event(&recorder.instance, &current.recording_epoch, "linux", &native, &limits)?;
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
