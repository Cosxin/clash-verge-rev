use crate::NativeFlowEvent;
use serde::{Deserialize, Serialize};

const MAX_SEQUENCE: u64 = i64::MAX as u64;

fn valid_scope(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeJournalStatus {
    pub journal_id: String,
    pub generation: u64,
    pub recording: bool,
    pub recording_epoch: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub acknowledged_sequence: u64,
    pub dropped_events: u64,
    pub provider_restarts: u64,
    pub retention_days: u32,
    pub max_records: usize,
    pub healthy: bool,
    pub reason: String,
}

impl NativeJournalStatus {
    pub fn validate(&self) -> Result<(), String> {
        if self.reason.len() > 2048
            || self.generation > MAX_SEQUENCE
            || self.last_sequence > MAX_SEQUENCE
            || self.acknowledged_sequence > self.last_sequence
            || self.provider_restarts > MAX_SEQUENCE
            || self.dropped_events > MAX_SEQUENCE
            || !(1..=90).contains(&self.retention_days)
            || !(100..=20_000).contains(&self.max_records)
            || (self.healthy
                && (!valid_scope(&self.journal_id)
                    || !(1..=self.last_sequence + 1).contains(&self.first_sequence)
                    || (!valid_scope(&self.recording_epoch)
                        && !(self.generation == 0 && !self.recording && self.recording_epoch.is_empty()))))
        {
            return Err("Invalid native journal status".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeJournalEnrollment {
    pub journal_id: String,
    pub recording_epoch: String,
    pub generation: u64,
    pub sequence: u64,
    pub provider_restarts: u64,
    pub producer_instance_id: String,
    pub pending: bool,
}

impl NativeJournalEnrollment {
    pub fn validate(&self) -> Result<(), String> {
        if !valid_scope(&self.journal_id)
            || !valid_scope(&self.recording_epoch)
            || (!self.producer_instance_id.is_empty() && !valid_scope(&self.producer_instance_id))
            || self.generation > MAX_SEQUENCE
            || self.sequence > MAX_SEQUENCE
            || self.provider_restarts > MAX_SEQUENCE
        {
            return Err("Invalid native recording enrollment".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeJournalEvent {
    pub journal_sequence: u64,
    pub producer_instance_id: String,
    pub recording_epoch: String,
    pub provider_restarts: u64,
    pub event: NativeFlowEvent,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeJournalPage {
    pub instance_id: String,
    pub journal_id: String,
    pub recording_epoch: String,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub next_sequence: u64,
    pub provider_restarts: u64,
    pub dropped_events: u64,
    pub events: Vec<NativeJournalEvent>,
}

impl NativeJournalPage {
    pub fn validate(&self, expected: &NativeJournalEnrollment) -> Result<(), String> {
        expected.validate()?;
        if !valid_scope(&self.instance_id)
            || self.journal_id != expected.journal_id
            || self.recording_epoch != expected.recording_epoch
            || self.events.len() > 256
            || !(expected.sequence..=MAX_SEQUENCE).contains(&self.last_sequence)
            || self.provider_restarts < expected.provider_restarts
            || self.provider_restarts > MAX_SEQUENCE
            || !(1..=self.last_sequence + 1).contains(&self.first_sequence)
            || self.dropped_events > MAX_SEQUENCE
        {
            return Err("Native journal page scope or durable bounds changed".to_owned());
        }
        let mut previous = expected.sequence;
        let mut restarts = expected.provider_restarts;
        for envelope in &self.events {
            envelope.event.validate()?;
            if envelope.recording_epoch != expected.recording_epoch
                || !valid_scope(&envelope.producer_instance_id)
                || envelope.journal_sequence <= previous
                || !(self.first_sequence..=self.last_sequence).contains(&envelope.journal_sequence)
                || envelope.provider_restarts < restarts
                || envelope.provider_restarts > self.provider_restarts
            {
                return Err("Native journal event provenance or sequence is invalid".to_owned());
            }
            previous = envelope.journal_sequence;
            restarts = envelope.provider_restarts;
        }
        if self.next_sequence != previous
            || (self.events.is_empty()
                && expected.sequence < self.last_sequence
                && self.first_sequence <= self.last_sequence)
        {
            return Err("Native journal cursor does not acknowledge its returned durable events".to_owned());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn journal_pages_preserve_delivery_and_original_producer_scopes() -> Result<(), String> {
        let enrollment = NativeJournalEnrollment {
            journal_id: "journal".to_owned(),
            recording_epoch: "recording".to_owned(),
            generation: 1,
            sequence: 40,
            provider_restarts: 1,
            producer_instance_id: "previous-provider".to_owned(),
            pending: false,
        };
        let mut page: NativeJournalPage = serde_json::from_value(json!({
            "instanceId":"current-provider", "journalId":"journal", "recordingEpoch":"recording",
            "firstSequence":41,"lastSequence":45,"nextSequence":45,"providerRestarts":2,"droppedEvents":1,
            "events":[{"journalSequence":45,"producerInstanceId":"previous-provider","recordingEpoch":"recording","providerRestarts":1,
                "event":{"flowId":"flow","sequence":7,"timeMs":1000,"kind":"open","identityConfidence":"unknown",
                    "sourceIp":"127.0.0.1","sourcePort":1234,"destinationIp":"127.0.0.1","destinationPort":443,
                    "network":"tcp","counterSemantics":"cumulative","verdict":"observe"}}]
        }))
        .map_err(|error| error.to_string())?;
        page.validate(&enrollment)?;
        page.events[0].recording_epoch = "disabled-period".to_owned();
        assert!(page.validate(&enrollment).is_err());
        page.events.clear();
        page.next_sequence = 40;
        assert!(page.validate(&enrollment).is_err());
        page.first_sequence = 46;
        page.validate(&enrollment)?;
        page.next_sequence = 45;
        assert!(page.validate(&enrollment).is_err());
        page.next_sequence = 40;
        page.last_sequence = 39;
        assert!(page.validate(&enrollment).is_err());
        Ok(())
    }
}
