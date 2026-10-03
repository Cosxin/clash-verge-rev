use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryLimits {
    pub retention_days: u32,
    pub max_records: usize,
}

impl Default for HistoryLimits {
    fn default() -> Self {
        Self {
            retention_days: 7,
            max_records: 5000,
        }
    }
}

impl HistoryLimits {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=90).contains(&self.retention_days) || !(100..=20_000).contains(&self.max_records) {
            return Err("History limits require 1–90 days and 100–20000 records".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HistoryState {
    Active,
    EndedIncomplete,
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowSample {
    pub core_id: String,
    pub start: String,
    pub process: String,
    pub process_path: String,
    pub host: String,
    #[serde(default)]
    pub source_ip: String,
    #[serde(default)]
    pub source_port: String,
    #[serde(default)]
    pub uid: Option<u32>,
    pub destination_ip: String,
    pub destination_port: String,
    pub network: String,
    pub upload: u64,
    pub download: u64,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryRecord {
    pub id: String,
    pub core_id: String,
    pub epoch: String,
    pub first_seen_at: u64,
    pub last_seen_at: u64,
    pub observed_ended_at: Option<u64>,
    pub state: HistoryState,
    pub start: String,
    pub process: String,
    pub process_path: String,
    pub identity_confidence: crate::IdentityConfidence,
    pub host: String,
    #[serde(default)]
    pub source_ip: String,
    #[serde(default)]
    pub source_port: String,
    #[serde(default)]
    pub uid: Option<u32>,
    pub hostname_source: String,
    pub destination_ip: String,
    pub destination_port: String,
    pub network: String,
    pub upload: u64,
    pub download: u64,
    pub observed_upload: u64,
    pub observed_download: u64,
    pub counter_resets: u32,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub source: String,
    pub completeness: String,
    pub counter_semantics: String,
    #[serde(default)]
    pub pid: Option<u64>,
    #[serde(default)]
    pub native_sequence: u64,
    #[serde(default)]
    pub policy_generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryQuery {
    #[serde(default)]
    pub search: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_page_limit")]
    pub limit: usize,
}

impl Default for HistoryQuery {
    fn default() -> Self {
        Self {
            search: String::new(),
            source: None,
            offset: 0,
            limit: 100,
        }
    }
}

const fn default_page_limit() -> usize {
    100
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryPage {
    pub records: Vec<HistoryRecord>,
    pub total: usize,
    pub observed_upload: Option<u64>,
    pub observed_download: Option<u64>,
    pub source_totals: Vec<HistorySourceTotals>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistorySourceTotals {
    pub source: String,
    pub records: usize,
    pub observed_upload: u64,
    pub observed_download: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionHistory {
    pub records: Vec<HistoryRecord>,
    pub gap_count: u64,
    pub dropped_records: u64,
}

fn bounded(value: &str, max: usize) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(max)
        .collect()
}

const fn observed_delta(previous: u64, current: u64) -> u64 {
    if current >= previous {
        current - previous
    } else {
        current
    }
}

impl ConnectionHistory {
    pub fn sample(&mut self, epoch: &str, samples: &[FlowSample], now: u64, limits: &HistoryLimits) {
        let mut seen = HashSet::new();
        let mut indexes: HashMap<(String, String), usize> = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.source == "mihomo")
            .map(|(index, record)| ((record.core_id.clone(), record.start.clone()), index))
            .collect();
        for sample in samples {
            let key = (bounded(&sample.core_id, 128), bounded(&sample.start, 128));
            if !seen.insert(key.clone()) {
                continue;
            }
            if let Some(record) = indexes.get(&key).and_then(|index| self.records.get_mut(*index)) {
                if sample.upload < record.upload || sample.download < record.download {
                    record.counter_resets = record.counter_resets.saturating_add(1);
                }
                record.observed_upload = record
                    .observed_upload
                    .saturating_add(observed_delta(record.upload, sample.upload));
                record.observed_download = record
                    .observed_download
                    .saturating_add(observed_delta(record.download, sample.download));
                record.upload = sample.upload;
                record.download = sample.download;
                record.last_seen_at = now;
                record.epoch = epoch.to_owned();
                record.state = HistoryState::Active;
                record.observed_ended_at = None;
            } else {
                indexes.insert(key.clone(), self.records.len());
                let id = format!("{epoch}:{}:{}", key.0, key.1);
                self.records.push(HistoryRecord {
                    id,
                    core_id: bounded(&sample.core_id, 128),
                    epoch: epoch.to_owned(),
                    first_seen_at: now,
                    last_seen_at: now,
                    observed_ended_at: None,
                    state: HistoryState::Active,
                    start: bounded(&sample.start, 128),
                    process: bounded(&sample.process, 256),
                    process_path: bounded(&sample.process_path, 2048),
                    identity_confidence: if sample.process_path.is_empty() {
                        crate::IdentityConfidence::Unknown
                    } else {
                        crate::IdentityConfidence::Inferred
                    },
                    host: bounded(&sample.host, 253),
                    source_ip: bounded(&sample.source_ip, 128),
                    source_port: bounded(&sample.source_port, 16),
                    uid: sample.uid,
                    hostname_source: "engine_inferred".to_owned(),
                    destination_ip: bounded(&sample.destination_ip, 128),
                    destination_port: bounded(&sample.destination_port, 16),
                    network: bounded(&sample.network, 16),
                    upload: sample.upload,
                    download: sample.download,
                    observed_upload: sample.upload,
                    observed_download: sample.download,
                    counter_resets: 0,
                    chains: sample.chains.iter().take(16).map(|value| bounded(value, 256)).collect(),
                    rule: bounded(&sample.rule, 256),
                    rule_payload: bounded(&sample.rule_payload, 2048),
                    source: "mihomo".to_owned(),
                    completeness: "sampled_incomplete".to_owned(),
                    counter_semantics: "cumulative_snapshot".to_owned(),
                    pid: None,
                    native_sequence: 0,
                    policy_generation: None,
                });
            }
        }
        for record in &mut self.records {
            if record.state == HistoryState::Active
                && record.source == "mihomo"
                && (record.epoch != epoch || !seen.contains(&(record.core_id.clone(), record.start.clone())))
            {
                record.state = HistoryState::EndedIncomplete;
                record.observed_ended_at = Some(now);
            }
        }
        self.prune(now, limits);
        self.prune_to_bytes(32 * 1024 * 1024);
    }

    pub fn interrupt(&mut self, now: u64, record_gap: bool) {
        if record_gap {
            self.gap_count = self.gap_count.saturating_add(1);
        }
        for record in &mut self.records {
            if record.state == HistoryState::Active {
                record.state = HistoryState::EndedIncomplete;
                record.observed_ended_at = Some(now);
            }
        }
    }

    pub fn interrupt_core(&mut self, now: u64) {
        self.gap_count = self.gap_count.saturating_add(1);
        for record in &mut self.records {
            if record.state == HistoryState::Active && record.source == "mihomo" {
                record.state = HistoryState::EndedIncomplete;
                record.observed_ended_at = Some(now);
            }
        }
    }

    pub fn interrupt_native(&mut self, now: u64) {
        self.gap_count = self.gap_count.saturating_add(1);
        for record in &mut self.records {
            if record.state == HistoryState::Active && record.source != "mihomo" {
                record.state = HistoryState::EndedIncomplete;
                record.observed_ended_at = Some(now);
            }
        }
    }

    pub fn prune(&mut self, now: u64, limits: &HistoryLimits) {
        let cutoff = now.saturating_sub(u64::from(limits.retention_days) * 86_400_000);
        self.records.retain(|record| record.last_seen_at >= cutoff);
        self.records.sort_by_key(|record| record.last_seen_at);
        if self.records.len() > limits.max_records {
            let removed = self.records.len() - limits.max_records;
            let active_removed = self.records[..removed]
                .iter()
                .any(|record| record.state == HistoryState::Active);
            self.dropped_records = self.dropped_records.saturating_add(removed as u64);
            if active_removed {
                self.gap_count = self.gap_count.saturating_add(1);
            }
            self.records.drain(..removed);
        }
    }

    pub fn prune_to_bytes(&mut self, budget: usize) {
        let sizes: Vec<_> = self
            .records
            .iter()
            .map(|record| serde_json::to_vec(record).map_or(usize::MAX, |encoded| encoded.len().saturating_add(1)))
            .collect();
        let mut remaining = sizes.iter().fold(0_usize, |total, size| total.saturating_add(*size));
        let mut removed = 0;
        while remaining > budget && removed < sizes.len() {
            remaining = remaining.saturating_sub(sizes[removed]);
            removed += 1;
        }
        if removed > 0 {
            if self.records[..removed]
                .iter()
                .any(|record| record.state == HistoryState::Active)
            {
                self.gap_count = self.gap_count.saturating_add(1);
            }
            self.dropped_records = self.dropped_records.saturating_add(removed as u64);
            self.records.drain(..removed);
        }
    }

    pub fn query(&self, query: &HistoryQuery) -> HistoryPage {
        let search = query.search.to_lowercase();
        let filtered: Vec<_> = self
            .records
            .iter()
            .rev()
            .filter(|record| query.source.as_ref().is_none_or(|source| source == &record.source))
            .filter(|record| {
                search.is_empty()
                    || [
                        &record.process,
                        &record.process_path,
                        &record.host,
                        &record.source_ip,
                        &record.destination_ip,
                        &record.rule,
                    ]
                    .into_iter()
                    .any(|value| value.to_lowercase().contains(&search))
            })
            .collect();
        // Core and native observations can describe the same traffic. Do not
        // manufacture a system total by adding their independent counters.
        let mut source_totals = std::collections::BTreeMap::<String, HistorySourceTotals>::new();
        for record in &filtered {
            let totals = source_totals
                .entry(record.source.clone())
                .or_insert_with(|| HistorySourceTotals {
                    source: record.source.clone(),
                    records: 0,
                    observed_upload: 0,
                    observed_download: 0,
                });
            totals.records += 1;
            totals.observed_upload = totals.observed_upload.saturating_add(record.observed_upload);
            totals.observed_download = totals.observed_download.saturating_add(record.observed_download);
        }
        let sole_source = (source_totals.len() <= 1).then(|| source_totals.values().next());
        HistoryPage {
            total: filtered.len(),
            observed_upload: sole_source.map(|source| source.map_or(0, |totals| totals.observed_upload)),
            observed_download: sole_source.map(|source| source.map_or(0, |totals| totals.observed_download)),
            source_totals: source_totals.into_values().collect(),
            records: filtered
                .into_iter()
                .skip(query.offset)
                .take(query.limit.clamp(1, 200))
                .cloned()
                .collect(),
        }
    }

    pub fn export_redacted(&self) -> Result<String, String> {
        let records: Vec<_> = self
            .records
            .iter()
            .map(|record| {
                serde_json::json!({
                    "firstSeenAt": record.first_seen_at,
                    "lastSeenAt": record.last_seen_at,
                    "observedEndedAt": record.observed_ended_at,
                    "state": record.state,
                    "network": record.network,
                    "upload": record.upload,
                    "download": record.download,
                    "observedUpload": record.observed_upload,
                    "observedDownload": record.observed_download,
                    "counterResets": record.counter_resets,
                    "source": record.source,
                    "completeness": record.completeness,
                    "counterSemantics": record.counter_semantics,
                })
            })
            .collect();
        serde_json::to_string_pretty(&serde_json::json!({
            "schemaVersion": 1,
            "redacted": true,
            "coverage": if self.records.iter().any(|record| record.source != "mihomo") { "mixed_scoped_sources" } else { "core_only" },
            "gapCount": self.gap_count,
            "droppedRecords": self.dropped_records,
            "records": records,
        }))
        .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(upload: u64, download: u64) -> FlowSample {
        FlowSample {
            core_id: "core-a".to_owned(),
            start: "2026-10-02T00:00:00Z".to_owned(),
            process: "secret-app".to_owned(),
            process_path: "/secret/app".to_owned(),
            host: "private.example".to_owned(),
            source_ip: "127.0.0.1".to_owned(),
            source_port: "50001".to_owned(),
            uid: Some(501),
            destination_ip: "192.0.2.1".to_owned(),
            destination_port: "443".to_owned(),
            network: "tcp".to_owned(),
            upload,
            download,
            chains: vec!["Private group".to_owned()],
            rule: "DOMAIN".to_owned(),
            rule_payload: "private.example".to_owned(),
        }
    }

    #[test]
    fn snapshots_are_idempotent_reset_aware_and_never_claim_a_final_close() {
        let mut history = ConnectionHistory::default();
        let limits = HistoryLimits::default();
        history.sample("epoch", &[sample(100, 200), sample(100, 200)], 1000, &limits);
        history.sample("epoch", &[sample(150, 250)], 2000, &limits);
        history.sample("epoch", &[sample(10, 20)], 3000, &limits);
        history.sample("epoch", &[], 4000, &limits);
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].observed_upload, 160);
        assert_eq!(history.records[0].counter_resets, 1);
        assert_eq!(history.records[0].state, HistoryState::EndedIncomplete);
        assert_eq!(history.records[0].last_seen_at, 3000);
        assert_eq!(history.records[0].observed_ended_at, Some(4000));
        assert_eq!(history.records[0].completeness, "sampled_incomplete");
    }

    #[test]
    fn retention_bounds_history_and_exports_omit_sensitive_metadata() {
        let mut history = ConnectionHistory::default();
        let limits = HistoryLimits {
            retention_days: 1,
            max_records: 100,
        };
        let samples: Vec<_> = (0..101)
            .map(|index| {
                let mut flow = sample(10, 20);
                flow.core_id = index.to_string();
                flow
            })
            .collect();
        history.sample("epoch", &samples, 1000, &limits);
        assert_eq!(history.records.len(), 100);
        assert_eq!(history.dropped_records, 1);
        assert_eq!(history.gap_count, 1);
        let exported = history.export_redacted().unwrap_or_default();
        for sensitive in [
            "private.example",
            "192.0.2.1",
            "/secret/app",
            "secret-app",
            "Private group",
        ] {
            assert!(!exported.contains(sensitive));
        }
        history.prune(86_402_000, &limits);
        assert!(history.records.is_empty());
    }

    #[test]
    fn resampling_after_a_gap_or_missing_snapshot_does_not_double_count() {
        let mut history = ConnectionHistory::default();
        let limits = HistoryLimits::default();
        history.sample("epoch-a", &[sample(100, 200)], 1000, &limits);
        history.interrupt(2000, true);
        history.sample("epoch-b", &[sample(100, 200)], 3000, &limits);
        history.sample("epoch-b", &[], 4000, &limits);
        history.sample("epoch-b", &[sample(150, 250)], 5000, &limits);
        assert_eq!(history.records.len(), 1);
        assert_eq!(history.records[0].observed_upload, 150);
        assert_eq!(history.records[0].state, HistoryState::Active);
        assert_eq!(history.gap_count, 1);
        history.prune_to_bytes(1);
        assert!(history.records.is_empty());
        assert_eq!(history.dropped_records, 1);
    }

    #[test]
    fn overlapping_native_and_core_sources_never_publish_a_combined_traffic_total() {
        let mut history = ConnectionHistory::default();
        history.sample("epoch", &[sample(100, 200)], 1000, &HistoryLimits::default());
        let mut native = history.records[0].clone();
        native.id = "native:flow".to_owned();
        native.source = "native_macos".to_owned();
        history.records.push(native);
        let page = history.query(&HistoryQuery::default());
        assert_eq!(page.total, 2);
        assert_eq!(page.observed_upload, None);
        assert_eq!(page.source_totals.len(), 2);
        let page = history.query(&HistoryQuery {
            source: Some("mihomo".to_owned()),
            ..Default::default()
        });
        assert_eq!(page.total, 1);
        assert_eq!(page.observed_upload, Some(100));
        assert_eq!(page.observed_download, Some(200));
    }
}
