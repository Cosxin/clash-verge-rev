use crate::{core::handle::Handle, process::AsyncHandler, utils::dirs};
use clash_verge_network::{
    ConnectionHistory, FlowSample, HistoryLimits, NativeAdapterStatus, NativeJournalEnrollment, NativeJournalPage,
    NetworkPolicy, NetworkStore,
};
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
    background_recording: bool,
    background_recording_reason: String,
    background_recording_available: bool,
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
            adapter_reason: "Draft policy preview, native executable bans, and core-only app routing are separate. Whole-IP monitoring, cross-platform independent history, native app routing and kill-switch qualification are incomplete.",
            os: std::env::consts::OS,
            recording_enabled: self.store.recording_enabled,
            background_recording: self.background_recording(),
            background_recording_reason: self.background_recording_reason(),
            background_recording_available: !cfg!(feature = "network-dev")
                && self.native_status.authenticated
                && self.native_status.active
                && self.native_status.monitoring
                && self
                    .native_status
                    .journal
                    .as_ref()
                    .is_some_and(|journal| journal.healthy),
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
        self.set_recording_with(enabled, |status, enabled, epoch, limits| async move {
            super::native_firewall::journal_recording(&status, enabled, &epoch, &limits).await
        })
        .await
    }

    pub fn update_native_status(&mut self, status: NativeAdapterStatus) {
        self.native_status = status;
    }

    async fn set_recording_with<F, R>(&mut self, enabled: bool, configure: F) -> Result<(), String>
    where
        F: FnOnce(NativeAdapterStatus, bool, String, HistoryLimits) -> R,
        R: Future<Output = Result<NativeAdapterStatus, String>>,
    {
        if self.store.recording_enabled == enabled && self.store.native_journal.is_some() {
            let status = self.native_status.clone();
            return self.synchronize_journal_with(&status, configure).await;
        }
        let mut next = self.store.clone();
        next.recording_enabled = enabled;
        if let Some(previous) = &self.store.native_journal {
            let mut intent = previous.clone();
            if let Some(journal) = &self.native_status.journal
                && journal.journal_id == previous.journal_id
                && journal.healthy
                && self.native_status.authenticated
                && self.native_status.active
            {
                intent.generation = journal.generation;
                intent.sequence = journal.last_sequence.max(intent.sequence);
                intent.provider_restarts = journal.provider_restarts.max(intent.provider_restarts);
            }
            intent.recording_epoch = nanoid::nanoid!();
            intent.producer_instance_id.clear();
            intent.pending = true;
            next.native_journal = Some(intent);
        } else if let Some(journal) = &self.native_status.journal
            && journal.healthy
            && self.native_status.authenticated
            && self.native_status.active
        {
            next.native_journal = Some(NativeJournalEnrollment {
                journal_id: journal.journal_id.clone(),
                recording_epoch: nanoid::nanoid!(),
                generation: journal.generation,
                sequence: journal.last_sequence,
                provider_restarts: journal.provider_restarts,
                producer_instance_id: String::new(),
                pending: true,
            });
        }
        if !enabled {
            next.history.interrupt(now_ms(), false);
        }
        self.commit(next).await?;
        self.epoch = nanoid::nanoid!();
        self.recording_epoch.clone_from(&self.epoch);
        self.last_sample_at = None;
        self.sample_error = None;
        self.native_error = None;
        let status = self.native_status.clone();
        self.synchronize_journal_with(&status, configure).await
    }

    fn background_recording(&self) -> bool {
        self.store.recording_enabled
            && self
                .store
                .native_journal
                .as_ref()
                .is_some_and(|enrollment| !enrollment.pending && journal_matches(&self.native_status, enrollment, true))
    }

    fn background_recording_reason(&self) -> String {
        if self.background_recording() {
            return "Authenticated native flow history continues when the desktop exits, within the provider's storage bounds".to_owned();
        }
        if self
            .store
            .native_journal
            .as_ref()
            .is_some_and(|enrollment| enrollment.pending)
        {
            return self.native_error.clone().unwrap_or_else(|| {
                "Native recording change is pending; provider capture may continue until a durable acknowledgment"
                    .to_owned()
            });
        }
        if let Some(enrollment) = &self.store.native_journal {
            return self.native_error.clone().unwrap_or_else(|| {
                if journal_matches(&self.native_status, enrollment, false) {
                    "Native background recording is off".to_owned()
                } else {
                    "Native recording state is unconfirmed; the provider may retain its previous recording setting"
                        .to_owned()
                }
            });
        }
        "This workspace has not opted into an authenticated durable native journal".to_owned()
    }

    async fn synchronize_journal_with<F, R>(&mut self, status: &NativeAdapterStatus, configure: F) -> Result<(), String>
    where
        F: FnOnce(NativeAdapterStatus, bool, String, HistoryLimits) -> R,
        R: Future<Output = Result<NativeAdapterStatus, String>>,
    {
        let Some(enrollment) = self.store.native_journal.clone() else {
            return Ok(());
        };
        let result = async {
            enrollment.validate()?;
            let journal = status
                .journal
                .as_ref()
                .ok_or("Native journal unavailable; recording change is unconfirmed")?;
            if !status.authenticated
                || !status.active
                || !journal.healthy
                || journal.journal_id != enrollment.journal_id
            {
                return Err("Native journal is unavailable, unhealthy or belongs to a different enrollment".to_owned());
            }
            if !enrollment.pending {
                if !journal_matches(status, &enrollment, self.store.recording_enabled) {
                    return Err(
                        "Native recording configuration changed elsewhere; review it before continuing".to_owned(),
                    );
                }
                return Ok(());
            }
            let accepted_generation = enrollment
                .generation
                .checked_add(1)
                .ok_or("Native recording generation exhausted")?;
            let accepted = journal.generation == accepted_generation
                && journal.recording_epoch == enrollment.recording_epoch
                && journal.recording == self.store.recording_enabled
                && journal.retention_days == self.store.limits.retention_days
                && journal.max_records == self.store.limits.max_records;
            let acknowledged = if accepted {
                status.clone()
            } else {
                if journal.generation != enrollment.generation {
                    return Err(
                        "Native recording generation changed elsewhere; pending intent was not rebased".to_owned(),
                    );
                }
                configure(
                    status.clone(),
                    self.store.recording_enabled,
                    enrollment.recording_epoch.clone(),
                    self.store.limits.clone(),
                )
                .await?
            };
            let acknowledged_journal = acknowledged
                .journal
                .as_ref()
                .ok_or("Native recording acknowledgment missing")?;
            let durable_head = acknowledged_journal.last_sequence;
            if !acknowledged.authenticated
                || !acknowledged.active
                || acknowledged.instance_id != status.instance_id
                || !acknowledged_journal.healthy
                || acknowledged_journal.journal_id != enrollment.journal_id
                || acknowledged_journal.generation != accepted_generation
                || acknowledged_journal.recording_epoch != enrollment.recording_epoch
                || acknowledged_journal.recording != self.store.recording_enabled
                || acknowledged_journal.retention_days != self.store.limits.retention_days
                || acknowledged_journal.max_records != self.store.limits.max_records
                || durable_head < enrollment.sequence
                || acknowledged_journal.provider_restarts < enrollment.provider_restarts
            {
                return Err("Native recording acknowledgment did not match the persisted intent".to_owned());
            }
            let mut next = self.store.clone();
            let mut confirmed = enrollment;
            confirmed.generation = accepted_generation;
            confirmed.pending = false;
            confirmed.sequence = confirmed.sequence.max(acknowledged_journal.acknowledged_sequence);
            // A lost acknowledgment may span a provider restart. Older committed events must remain replayable.
            next.native_journal = Some(confirmed);
            self.native_status = acknowledged;
            self.commit(next).await
        }
        .await;
        if let Err(error) = &result {
            self.native_error = Some(error.clone());
        } else {
            self.native_error = None;
        }
        result
    }

    async fn accept_journal_page(
        &mut self,
        expected: &NativeJournalEnrollment,
        status: &NativeAdapterStatus,
        page: &NativeJournalPage,
    ) -> Result<bool, String> {
        if !self.store.recording_enabled
            || !self.writable
            || self.store.native_journal.as_ref() != Some(expected)
            || expected.pending
            || !journal_matches(&self.native_status, expected, true)
            || self.native_status.instance_id != status.instance_id
            || page.instance_id != status.instance_id
        {
            return Err("Native journal read was superseded by a recording or provider change".to_owned());
        }
        page.validate(expected)?;
        let mut next = self.store.clone();
        let mut cursor = expected.clone();
        for envelope in &page.events {
            if cursor.sequence.checked_add(1) != Some(envelope.journal_sequence)
                || envelope.provider_restarts > cursor.provider_restarts
            {
                next.history.interrupt_native(envelope.event.time_ms);
            }
            next.history.native_event(
                &envelope.producer_instance_id,
                &envelope.recording_epoch,
                &status.platform,
                &envelope.event,
                &next.limits,
            )?;
            cursor.sequence = envelope.journal_sequence;
            cursor.provider_restarts = envelope.provider_restarts;
            cursor.producer_instance_id.clone_from(&envelope.producer_instance_id);
        }
        if page.events.is_empty() && cursor.sequence < page.last_sequence {
            next.history.interrupt_native(now_ms());
            cursor.sequence = page.last_sequence;
        }
        let caught_up = cursor.sequence == page.last_sequence;
        if caught_up && page.provider_restarts > cursor.provider_restarts {
            next.history.interrupt_native(now_ms());
            cursor.provider_restarts = page.provider_restarts;
            cursor.producer_instance_id.clone_from(&page.instance_id);
        }
        let changed = &cursor != expected;
        if changed {
            next.native_journal = Some(cursor);
            self.commit(next).await?;
            if !page.events.is_empty() {
                self.last_sample_at = Some(now_ms());
            }
        }
        Ok(!page.events.is_empty() && page.next_sequence < page.last_sequence)
    }

    pub async fn clear_history(&mut self, status: Option<&NativeAdapterStatus>) -> Result<(), String> {
        self.clear_history_with(status, |status, enabled, epoch, limits| async move {
            super::native_firewall::journal_recording(&status, enabled, &epoch, &limits).await
        })
        .await
    }

    async fn clear_history_with<F, R>(
        &mut self,
        status: Option<&NativeAdapterStatus>,
        configure: F,
    ) -> Result<(), String>
    where
        F: FnOnce(NativeAdapterStatus, bool, String, HistoryLimits) -> R,
        R: Future<Output = Result<NativeAdapterStatus, String>>,
    {
        let mut next = self.store.clone();
        let configuration = if let Some(enrollment) = &mut next.native_journal {
            let status = status.ok_or("Native history source unavailable; clear cannot establish a durable cutoff")?;
            if enrollment.pending || !journal_matches(status, enrollment, self.store.recording_enabled) {
                return Err(
                    "Native recording is pending or changed; clear cannot establish a confirmed cutoff".to_owned(),
                );
            }
            let journal = status.journal.as_ref().ok_or("Native journal missing")?;
            if journal.last_sequence < enrollment.sequence {
                return Err("Native journal durable head is behind the saved cursor".to_owned());
            }
            enrollment.sequence = journal.last_sequence;
            enrollment.provider_restarts = journal.provider_restarts;
            enrollment.producer_instance_id.clear();
            enrollment.recording_epoch = nanoid::nanoid!();
            enrollment.pending = true;
            Some(status.clone())
        } else {
            None
        };
        next.history = ConnectionHistory::default();
        self.commit(next).await?;
        self.epoch = nanoid::nanoid!();
        self.recording_epoch.clone_from(&self.epoch);
        if let Some(status) = configuration {
            self.synchronize_journal_with(&status, configure)
                .await
                .map_err(|error| {
                    format!("Local history cleared; native deletion is pending durable confirmation: {error}")
                })?;
        }
        Ok(())
    }

    pub async fn set_limits(&mut self, limits: HistoryLimits) -> Result<(), String> {
        self.set_limits_with(limits, |status, enabled, epoch, limits| async move {
            super::native_firewall::journal_recording(&status, enabled, &epoch, &limits).await
        })
        .await
    }

    async fn set_limits_with<F, R>(&mut self, limits: HistoryLimits, configure: F) -> Result<(), String>
    where
        F: FnOnce(NativeAdapterStatus, bool, String, HistoryLimits) -> R,
        R: Future<Output = Result<NativeAdapterStatus, String>>,
    {
        limits.validate()?;
        let mut next = self.store.clone();
        next.limits = limits;
        next.history.prune(now_ms(), &next.limits);
        if let Some(enrollment) = &mut next.native_journal {
            if enrollment.pending {
                return Err("Finish the pending native recording change before changing retention".to_owned());
            }
            enrollment.pending = true;
        }
        self.commit(next).await?;
        let status = self.native_status.clone();
        self.synchronize_journal_with(&status, configure).await
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

fn journal_matches(status: &NativeAdapterStatus, enrollment: &NativeJournalEnrollment, enabled: bool) -> bool {
    status.authenticated
        && status.active
        && status.monitoring
        && status.journal.as_ref().is_some_and(|journal| {
            journal.healthy
                && journal.journal_id == enrollment.journal_id
                && journal.generation == enrollment.generation
                && journal.recording_epoch == enrollment.recording_epoch
                && journal.recording == enabled
        })
}

async fn drain_journal_events(state: &Mutex<NetworkState>) {
    let deadline = tokio::time::Instant::now() + NATIVE_DRAIN_BUDGET;
    for _ in 0..NATIVE_MAX_PAGES {
        let (status, enrollment) = {
            let current = state.lock().await;
            let Some(enrollment) = current.store.native_journal.clone() else {
                return;
            };
            if !current.writable
                || !current.store.recording_enabled
                || enrollment.pending
                || !journal_matches(&current.native_status, &enrollment, true)
            {
                return;
            }
            let result = (current.native_status.clone(), enrollment);
            drop(current);
            result
        };
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        let result = tokio::time::timeout_at(deadline, async {
            super::native_firewall::journal_ack(&status, &enrollment).await?;
            super::native_firewall::journal_events(&status, &enrollment).await
        })
        .await
        .unwrap_or_else(|_| Err("Native journal request timed out; retained history will be retried".to_owned()));
        let mut current = state.lock().await;
        if current.store.native_journal.as_ref() != Some(&enrollment) {
            return;
        }
        let accepted = match result {
            Ok(page) => current.accept_journal_page(&enrollment, &status, &page).await,
            Err(error) => Err(error),
        };
        match accepted {
            Ok(more) => {
                current.native_error = None;
                if !more {
                    return;
                }
            }
            Err(error) => {
                current.native_error = Some(error);
                return;
            }
        }
        drop(current);
    }
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
                if current.recording_epoch != status_epoch {
                    drop(current);
                    continue;
                }
                current.native_status = status.clone();
                if current.store.native_journal.is_some() {
                    if current.writable {
                        let _ = current
                            .synchronize_journal_with(&status, |status, enabled, epoch, limits| async move {
                                super::native_firewall::journal_recording(&status, enabled, &epoch, &limits).await
                            })
                            .await;
                    }
                    recorder = NativeRecorderCursor::default();
                    drop(current);
                    drain_journal_events(state).await;
                    continue;
                }
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

    fn journal_status() -> NativeAdapterStatus {
        NativeAdapterStatus {
            platform: "macos".to_owned(),
            instance_id: "provider-current".to_owned(),
            active: true,
            authenticated: true,
            monitoring: true,
            journal: Some(clash_verge_network::NativeJournalStatus {
                journal_id: "journal".to_owned(),
                generation: 0,
                recording: false,
                recording_epoch: String::new(),
                first_sequence: 1,
                last_sequence: 0,
                acknowledged_sequence: 0,
                dropped_events: 0,
                provider_restarts: 1,
                retention_days: 7,
                max_records: 10_000,
                healthy: true,
                reason: String::new(),
            }),
            ..NativeAdapterStatus::unavailable("fixture")
        }
    }

    fn configured(
        mut status: NativeAdapterStatus,
        enabled: bool,
        epoch: String,
        limits: HistoryLimits,
    ) -> Result<NativeAdapterStatus, String> {
        let journal = status.journal.as_mut().ok_or("Missing fixture journal")?;
        let fresh_epoch = journal.recording_epoch != epoch;
        journal.generation += 1;
        journal.recording = enabled;
        journal.recording_epoch = epoch;
        if fresh_epoch {
            journal.acknowledged_sequence = journal.last_sequence;
            journal.first_sequence = journal.last_sequence + 1;
        }
        journal.retention_days = limits.retention_days;
        journal.max_records = limits.max_records;
        Ok(status)
    }

    #[tokio::test]
    async fn journal_intent_is_durable_before_ipc_and_lost_ack_reconciles_without_reenabling() -> Result<(), String> {
        let mut current = recorder_fixture();
        current.store.recording_enabled = false;
        current.update_native_status(journal_status());
        let path = current.path.clone();
        let inspect = path.clone();
        assert!(
            current
                .set_recording_with(true, move |_, enabled, epoch, _| async move {
                    let stored = saved_recorder_fixture(&inspect)?;
                    let enrollment = stored.native_journal.ok_or("Missing persisted consent")?;
                    assert!(enabled && stored.recording_enabled && enrollment.pending);
                    assert_eq!(enrollment.recording_epoch, epoch);
                    Err("Lost native acknowledgment".to_owned())
                })
                .await
                .is_err()
        );
        let intent = current.store.native_journal.clone().ok_or("Missing intent")?;
        let mut accepted = configured(
            current.native_status.clone(),
            true,
            intent.recording_epoch.clone(),
            current.store.limits.clone(),
        )?;
        accepted.instance_id = "provider-resumed".to_owned();
        accepted
            .journal
            .as_mut()
            .ok_or("Missing fixture journal")?
            .provider_restarts = 2;
        current
            .synchronize_journal_with(&accepted, |_, _, _, _| async {
                Err("Must not repeat accepted consent".to_owned())
            })
            .await?;
        assert!(current.background_recording());
        let confirmed = current
            .store
            .native_journal
            .clone()
            .ok_or("Missing confirmed consent")?;
        assert!(!confirmed.pending);
        assert_eq!(confirmed.generation, 1);
        assert_eq!(confirmed.provider_restarts, 1);
        let resumed = NetworkStore::load(&path, now_ms())?;
        assert_eq!(resumed.native_journal, Some(confirmed));
        remove_recorder_fixture(&path)
    }

    #[tokio::test]
    async fn journal_confirmed_recording_retry_preserves_unreplayed_backlog() -> Result<(), String> {
        let mut current = recorder_fixture();
        current.store.recording_enabled = false;
        current.update_native_status(journal_status());
        let path = current.path.clone();
        current
            .set_recording_with(true, |status, enabled, epoch, limits| async move {
                configured(status, enabled, epoch, limits)
            })
            .await?;
        let confirmed = current
            .store
            .native_journal
            .clone()
            .ok_or("Missing confirmed enrollment")?;
        let core_epoch = current.epoch.clone();
        let recording_epoch = current.recording_epoch.clone();
        let persisted = std::fs::read(&path).map_err(|error| error.to_string())?;
        let mut status = current.native_status.clone();
        status.journal.as_mut().ok_or("Missing fixture journal")?.last_sequence = 1;
        current.update_native_status(status.clone());

        // The initial desktop reply can be lost after consent is confirmed while native capture continues.
        current
            .set_recording_with(true, |_, _, _, _| async {
                Err("A duplicate confirmed toggle must not configure or clear native history".to_owned())
            })
            .await?;
        assert_eq!(current.store.native_journal.as_ref(), Some(&confirmed));
        assert_eq!(current.epoch, core_epoch);
        assert_eq!(current.recording_epoch, recording_epoch);
        assert_eq!(std::fs::read(&path).map_err(|error| error.to_string())?, persisted);

        let page: NativeJournalPage = serde_json::from_value(json!({
            "instanceId":"provider-current","journalId":"journal","recordingEpoch":confirmed.recording_epoch,
            "firstSequence":1,"lastSequence":1,"nextSequence":1,"providerRestarts":1,"droppedEvents":0,
            "events":[{"journalSequence":1,"producerInstanceId":"provider-current","recordingEpoch":confirmed.recording_epoch,"providerRestarts":1,
                "event":{"flowId":"retry-backlog","sequence":1,"timeMs":now_ms(),"kind":"open","identityConfidence":"unknown",
                    "sourceIp":"127.0.0.1","sourcePort":1234,"destinationIp":"127.0.0.1","destinationPort":443,
                    "network":"tcp","counterSemantics":"cumulative","upload":10,"verdict":"observe"}}]
        }))
        .map_err(|error| error.to_string())?;
        assert!(!current.accept_journal_page(&confirmed, &status, &page).await?);
        let saved = saved_recorder_fixture(&path)?;
        assert_eq!(saved.native_journal.ok_or("Missing replay cursor")?.sequence, 1);
        assert_eq!(saved.history.records.len(), 1);
        assert_eq!(saved.history.records[0].observed_upload, 10);
        remove_recorder_fixture(&path)
    }

    #[tokio::test]
    async fn journal_replay_preserves_producer_and_atomically_saves_cursor_before_ack() -> Result<(), String> {
        let mut current = recorder_fixture();
        let path = current.path.clone();
        let status = configured(
            journal_status(),
            true,
            "recording".to_owned(),
            current.store.limits.clone(),
        )?;
        let enrollment = NativeJournalEnrollment {
            journal_id: "journal".to_owned(),
            recording_epoch: "recording".to_owned(),
            generation: 1,
            sequence: 0,
            provider_restarts: 1,
            producer_instance_id: "provider-old".to_owned(),
            pending: false,
        };
        current.native_status = status.clone();
        current.store.native_journal = Some(enrollment.clone());
        let page: NativeJournalPage = serde_json::from_value(json!({
            "instanceId":"provider-current","journalId":"journal","recordingEpoch":"recording",
            "firstSequence":1,"lastSequence":2,"nextSequence":2,"providerRestarts":2,"droppedEvents":0,
            "events":[
                {"journalSequence":1,"producerInstanceId":"provider-old","recordingEpoch":"recording","providerRestarts":1,
                 "event":{"flowId":"old-flow","sequence":41,"timeMs":now_ms(),"kind":"open","identityConfidence":"unknown",
                 "sourceIp":"127.0.0.1","sourcePort":1234,"destinationIp":"127.0.0.1","destinationPort":443,"network":"tcp","counterSemantics":"cumulative","upload":10,"verdict":"observe"}},
                {"journalSequence":2,"producerInstanceId":"provider-current","recordingEpoch":"recording","providerRestarts":2,
                 "event":{"flowId":"new-flow","sequence":1,"timeMs":now_ms()+1,"kind":"update","identityConfidence":"unknown",
                 "sourceIp":"127.0.0.1","sourcePort":1235,"destinationIp":"127.0.0.1","destinationPort":443,"network":"tcp","counterSemantics":"cumulative","upload":900,"verdict":"observe"}}
            ]
        })).map_err(|error| error.to_string())?;
        let mut first = page.clone();
        first.events.truncate(1);
        first.next_sequence = 1;
        assert!(current.accept_journal_page(&enrollment, &status, &first).await?);
        let first_cursor = current
            .store
            .native_journal
            .clone()
            .ok_or("Missing first-page cursor")?;
        assert_eq!(
            saved_recorder_fixture(&path)?.native_journal,
            Some(first_cursor.clone())
        );
        let mut remainder = page.clone();
        remainder.events.remove(0);
        assert!(!current.accept_journal_page(&first_cursor, &status, &remainder).await?);
        let saved = saved_recorder_fixture(&path)?;
        let cursor = saved.native_journal.ok_or("Missing persisted cursor")?;
        assert_eq!(cursor.sequence, 2);
        assert_eq!(cursor.provider_restarts, 2);
        assert_eq!(saved.history.records[0].epoch, "provider-old");
        assert_eq!(saved.history.records[0].state, HistoryState::EndedIncomplete);
        assert_eq!(saved.history.records[1].observed_upload, 0);
        assert_eq!(saved.history.gap_count, 1);
        assert!(current.accept_journal_page(&enrollment, &status, &page).await.is_err());
        let denied = path.with_file_name("not-a-directory");
        std::fs::write(&denied, b"fixture").map_err(|error| error.to_string())?;
        current.path = denied.join("workspace.json");
        let mut later = page;
        later.events.drain(..1);
        later.events[0].journal_sequence = 3;
        later.events[0].event.sequence = 2;
        later.events[0].event.upload = 950;
        later.last_sequence = 3;
        later.next_sequence = 3;
        assert!(current.accept_journal_page(&cursor, &status, &later).await.is_err());
        assert_eq!(current.store.native_journal, Some(cursor));
        assert_eq!(saved_recorder_fixture(&path)?.history.records[1].observed_upload, 0);
        std::fs::remove_file(denied).map_err(|error| error.to_string())?;
        remove_recorder_fixture(&path)
    }

    #[tokio::test]
    async fn journal_retention_change_preserves_replay_scope_and_advances_generation() -> Result<(), String> {
        let mut current = recorder_fixture();
        let path = current.path.clone();
        current.update_native_status(journal_status());
        current
            .set_recording_with(true, |status, enabled, epoch, limits| async move {
                configured(status, enabled, epoch, limits)
            })
            .await?;
        let before = current.store.native_journal.clone().ok_or("Missing enrollment")?;
        current
            .set_limits_with(
                HistoryLimits {
                    retention_days: 3,
                    max_records: 100,
                },
                |status, enabled, epoch, limits| async move { configured(status, enabled, epoch, limits) },
            )
            .await?;
        let after = current.store.native_journal.clone().ok_or("Missing enrollment")?;
        assert_eq!(before.recording_epoch, after.recording_epoch);
        assert_eq!(before.sequence, after.sequence);
        assert_eq!(after.generation, before.generation + 1);
        assert!(!after.pending);
        assert!(current.background_recording());
        assert_eq!(saved_recorder_fixture(&path)?.limits.max_records, 100);
        remove_recorder_fixture(&path)
    }

    #[tokio::test]
    async fn journal_clear_fences_pending_source_data_and_unconfirmed_off_stays_pending() -> Result<(), String> {
        let mut current = recorder_fixture();
        let path = current.path.clone();
        current.native_status = journal_status();
        current
            .set_recording_with(true, |status, enabled, epoch, limits| async move {
                configured(status, enabled, epoch, limits)
            })
            .await?;
        let old = current.store.native_journal.clone().ok_or("Missing enrollment")?;
        let status = current.native_status.clone();
        current
            .clear_history_with(Some(&status), |status, enabled, epoch, limits| async move {
                configured(status, enabled, epoch, limits)
            })
            .await?;
        let cleared = current.store.native_journal.clone().ok_or("Missing clear cutoff")?;
        assert_ne!(old.recording_epoch, cleared.recording_epoch);
        assert!(!cleared.pending);
        assert!(
            current
                .set_recording_with(false, |_, _, _, _| async { Err("Native stop unavailable".to_owned()) })
                .await
                .is_err()
        );
        let saved = saved_recorder_fixture(&path)?;
        assert!(!saved.recording_enabled);
        assert!(saved.native_journal.as_ref().is_some_and(|intent| intent.pending));
        assert!(!current.background_recording());
        assert!(current.background_recording_reason().contains("unavailable"));
        remove_recorder_fixture(&path)
    }

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
