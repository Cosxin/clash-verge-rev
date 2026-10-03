use crate::{ConnectionHistory, HistoryLimits, HistoryRecord, HistoryState, IdentityConfidence};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeFlowEvent {
    pub flow_id: String,
    pub sequence: u64,
    pub time_ms: u64,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub pid: Option<u64>,
    #[serde(default)]
    pub uid: Option<u32>,
    #[serde(default)]
    pub process_path: Option<String>,
    pub identity_confidence: IdentityConfidence,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub network: String,
    #[serde(default)]
    pub upload: u64,
    #[serde(default)]
    pub download: u64,
    #[serde(default)]
    pub packet_bytes: u64,
    #[serde(default)]
    pub direction: String,
    #[serde(default)]
    pub counter_semantics: String,
    pub verdict: String,
    #[serde(default)]
    pub policy_generation: Option<u64>,
}

impl NativeFlowEvent {
    pub fn validate(&self) -> Result<(), String> {
        if self.flow_id.is_empty()
            || self.flow_id.len() > 512
            || self.flow_id.chars().any(char::is_control)
            || self.sequence == 0
            || self.time_ms == 0
            || !matches!(self.network.as_str(), "tcp" | "udp")
            || self.source_ip.len() > 128
            || self.destination_ip.len() > 128
            || self
                .process_path
                .as_ref()
                .is_some_and(|path| path.len() > 2048 || path.chars().any(char::is_control))
            || !matches!(self.verdict.as_str(), "allow" | "block" | "unknown" | "observe")
            || (!matches!(self.kind.as_str(), "open" | "update" | "close") && self.packet_bytes == 0)
            || (!matches!(self.counter_semantics.as_str(), "cumulative" | "delta" | "unavailable")
                && self.packet_bytes == 0)
            || (self.packet_bytes > 0 && !matches!(self.direction.as_str(), "inbound" | "outbound"))
        {
            return Err("Malformed or unsupported native flow event".to_owned());
        }
        Ok(())
    }
}

impl ConnectionHistory {
    pub fn native_event(
        &mut self,
        instance: &str,
        platform: &str,
        event: &NativeFlowEvent,
        limits: &HistoryLimits,
    ) -> Result<(), String> {
        event.validate()?;
        if instance.is_empty()
            || instance.len() > 128
            || instance.chars().any(char::is_control)
            || !matches!(platform, "macos" | "windows" | "linux")
        {
            return Err("Invalid native event scope".to_owned());
        }
        let id = format!("native:{platform}:{instance}:{}", event.flow_id);
        let index = self.records.iter().position(|record| record.id == id);
        let index = if let Some(index) = index {
            index
        } else {
            let path = event.process_path.clone().unwrap_or_default();
            self.records.push(HistoryRecord {
                id,
                core_id: event.flow_id.clone(),
                epoch: instance.to_owned(),
                first_seen_at: event.time_ms,
                last_seen_at: event.time_ms,
                observed_ended_at: None,
                state: HistoryState::Active,
                start: event.time_ms.to_string(),
                process: path.rsplit(['/', '\\']).next().unwrap_or_default().to_owned(),
                process_path: path,
                identity_confidence: event.identity_confidence,
                host: String::new(),
                source_ip: event.source_ip.clone(),
                source_port: event.source_port.to_string(),
                uid: event.uid,
                hostname_source: "unavailable".to_owned(),
                destination_ip: event.destination_ip.clone(),
                destination_port: event.destination_port.to_string(),
                network: event.network.clone(),
                upload: 0,
                download: 0,
                observed_upload: 0,
                observed_download: 0,
                counter_resets: 0,
                chains: Vec::new(),
                rule: event.verdict.clone(),
                rule_payload: String::new(),
                source: format!("native_{platform}"),
                completeness: "native_events_incomplete".to_owned(),
                counter_semantics: if event.packet_bytes > 0 {
                    "observed_ip_packet_bytes".to_owned()
                } else {
                    event.counter_semantics.clone()
                },
                pid: event.pid,
                native_sequence: 0,
                policy_generation: event.policy_generation,
            });
            self.records.len() - 1
        };
        let record = &mut self.records[index];
        if event.sequence <= record.native_sequence {
            return Ok(());
        }
        record.native_sequence = event.sequence;
        record.last_seen_at = record.last_seen_at.max(event.time_ms);
        record.rule = event.verdict.clone();
        record.policy_generation = event.policy_generation;
        let (upload, download) = if event.packet_bytes > 0 {
            if event.direction == "outbound" {
                (event.packet_bytes, 0)
            } else {
                (0, event.packet_bytes)
            }
        } else {
            (event.upload, event.download)
        };
        let cumulative = event.packet_bytes == 0 && event.counter_semantics == "cumulative";
        if cumulative && (upload < record.upload || download < record.download) {
            record.counter_resets = record.counter_resets.saturating_add(1);
        }
        record.observed_upload = record.observed_upload.saturating_add(if cumulative {
            if upload >= record.upload {
                upload - record.upload
            } else {
                upload
            }
        } else {
            upload
        });
        record.observed_download = record.observed_download.saturating_add(if cumulative {
            if download >= record.download {
                download - record.download
            } else {
                download
            }
        } else {
            download
        });
        record.upload = if cumulative {
            upload
        } else {
            record.upload.saturating_add(upload)
        };
        record.download = if cumulative {
            download
        } else {
            record.download.saturating_add(download)
        };
        if event.kind == "close" {
            record.state = HistoryState::Closed;
            record.observed_ended_at = Some(event.time_ms);
        } else if record.state != HistoryState::Closed {
            record.state = HistoryState::Active;
            record.observed_ended_at = None;
        }
        self.prune(event.time_ms, limits);
        self.prune_to_bytes(32 * 1024 * 1024);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_cumulative_reports_and_packet_deltas_do_not_double_count_replays() -> Result<(), String> {
        let mut event: NativeFlowEvent = serde_json::from_value(serde_json::json!({
            "flowId":"flow","sequence":1,"timeMs":1000,"kind":"open","processPath":"/bin/app","identityConfidence":"exact",
            "sourceIp":"127.0.0.1","sourcePort":50100,"destinationIp":"127.0.0.1","destinationPort":8889,
            "network":"tcp","upload":0,"download":0,"counterSemantics":"cumulative","verdict":"allow","policyGeneration":4
        })).map_err(|error| error.to_string())?;
        let mut history = ConnectionHistory::default();
        let limits = HistoryLimits::default();
        history.native_event("boot", "macos", &event, &limits)?;
        event.sequence = 2;
        event.kind = "update".to_owned();
        event.upload = 100;
        event.download = 200;
        history.native_event("boot", "macos", &event, &limits)?;
        history.native_event("boot", "macos", &event, &limits)?;
        event.sequence = 3;
        event.kind = "close".to_owned();
        event.upload = 150;
        history.native_event("boot", "macos", &event, &limits)?;
        assert_eq!(history.records[0].observed_upload, 150);
        assert_eq!(history.records[0].state, HistoryState::Closed);
        event.kind.clear();
        event.counter_semantics.clear();
        event.packet_bytes = 64;
        event.direction = "outbound".to_owned();
        event.sequence = 1;
        history.native_event("linux-boot", "linux", &event, &limits)?;
        history.native_event("linux-boot", "linux", &event, &limits)?;
        assert_eq!(
            history
                .records
                .iter()
                .find(|record| record.source == "native_linux")
                .map(|record| record.observed_upload),
            Some(64)
        );
        Ok(())
    }
}
