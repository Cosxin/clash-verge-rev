use clash_verge_network::{AppBanPolicy, NativeAdapterStatus};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const MAX_RESPONSE: u64 = 1024 * 1024;

#[cfg(target_os = "linux")]
async fn exchange(command: &str, mut request: Value) -> Result<Value, String> {
    use std::os::{
        fd::AsRawFd as _,
        unix::fs::{FileTypeExt as _, MetadataExt as _},
    };
    const SOCKET: &str = "/run/networkcontrol/adapter.sock";
    for path in ["/run/networkcontrol", SOCKET] {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        let unsafe_permissions = if path == SOCKET {
            metadata.mode() & 0o007 != 0
        } else {
            metadata.mode() & 0o022 != 0
        };
        if metadata.uid() != 0 || unsafe_permissions || metadata.file_type().is_symlink() {
            return Err("Native adapter endpoint is not protected by its root owner".to_owned());
        }
        if path == SOCKET && !metadata.file_type().is_socket() {
            return Err("Native adapter endpoint is not a Unix socket".to_owned());
        }
    }
    request["schemaVersion"] = json!(1);
    request["command"] = json!(command);
    if command == "apply-bans" {
        request["processPaths"] = request["policy"]["processPaths"].clone();
        request
            .as_object_mut()
            .ok_or("Invalid native request")?
            .remove("policy");
    }
    let operation = async {
        let mut socket = tokio::net::UnixStream::connect(SOCKET)
            .await
            .map_err(|error| error.to_string())?;
        let mut credential: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut credential).cast(),
                &raw mut size,
            )
        };
        if result != 0 || size as usize != std::mem::size_of::<libc::ucred>() || credential.uid != 0 {
            return Err("Native adapter peer is not the privileged policy owner".to_owned());
        }
        let mut encoded = serde_json::to_vec(&request).map_err(|error| error.to_string())?;
        encoded.push(b'\n');
        socket.write_all(&encoded).await.map_err(|error| error.to_string())?;
        let mut response = Vec::new();
        let mut reader = tokio::io::BufReader::new(socket).take(MAX_RESPONSE + 1);
        // A single bounded newline frame avoids waiting for a daemon that keeps its socket open.
        use tokio::io::AsyncBufReadExt as _;
        reader
            .read_until(b'\n', &mut response)
            .await
            .map_err(|error| error.to_string())?;
        decode_response(&response)
    };
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .map_err(|_| "Native adapter request timed out; enforcement state is unconfirmed".to_owned())?
}

#[cfg(not(target_os = "linux"))]
async fn exchange(command: &str, request: Value) -> Result<Value, String> {
    use std::process::Stdio;
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let parent = executable.parent().ok_or("Desktop executable directory unavailable")?;
    let controller = parent.join(if cfg!(windows) {
        "network-control-native.exe"
    } else {
        "network-control-native"
    });
    if !controller.is_file() {
        return Err("Native controller is not packaged; build and qualify the platform provider first".to_owned());
    }
    let operation = async {
        let mut child = tokio::process::Command::new(controller)
            .arg(command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| error.to_string())?;
        let mut input = child.stdin.take().ok_or("Native controller stdin unavailable")?;
        input
            .write_all(&serde_json::to_vec(&request).map_err(|error| error.to_string())?)
            .await
            .map_err(|error| error.to_string())?;
        input.shutdown().await.map_err(|error| error.to_string())?;
        drop(input);
        let output = child.stdout.take().ok_or("Native controller stdout unavailable")?;
        let mut response = Vec::new();
        output
            .take(MAX_RESPONSE + 1)
            .read_to_end(&mut response)
            .await
            .map_err(|error| error.to_string())?;
        if response.len() as u64 > MAX_RESPONSE {
            return Err("Native controller response exceeds its bound".to_owned());
        }
        let result = child.wait().await.map_err(|error| error.to_string())?;
        let value = decode_response(&response)?;
        if !result.success() {
            return Err(value["error"].as_str().unwrap_or("Native controller failed").to_owned());
        }
        Ok(value)
    };
    tokio::time::timeout(Duration::from_secs(5), operation)
        .await
        .map_err(|_| "Native controller timed out; enforcement state is unconfirmed".to_owned())?
}

fn decode_response(response: &[u8]) -> Result<Value, String> {
    if response.is_empty() || response.len() as u64 > MAX_RESPONSE {
        return Err("Native adapter returned an empty or oversized response".to_owned());
    }
    let value: Value = serde_json::from_slice(response).map_err(|error| error.to_string())?;
    if value["schemaVersion"] != 1 || value["ok"] != true {
        return Err(value["error"]
            .as_str()
            .unwrap_or("Native adapter rejected the request")
            .to_owned());
    }
    Ok(value)
}

fn parse_status(value: Value) -> Result<NativeAdapterStatus, String> {
    let status: NativeAdapterStatus = serde_json::from_value(value).map_err(|error| error.to_string())?;
    if status.schema_version != 1 || status.platform != std::env::consts::OS {
        return Err("Native adapter belongs to a different platform or schema".to_owned());
    }
    (AppBanPolicy {
        schema_version: 1,
        generation: status.generation,
        process_paths: status.process_paths.clone(),
    })
    .validate()?;
    Ok(status)
}

pub async fn status() -> NativeAdapterStatus {
    match exchange("status", json!({})).await.and_then(parse_status) {
        Ok(status) => status,
        Err(error) => NativeAdapterStatus::unavailable(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeEvents {
    pub instance_id: String,
    #[serde(default)]
    pub events: Vec<clash_verge_network::NativeFlowEvent>,
    #[serde(default)]
    pub next_sequence: u64,
    pub dropped_events: u64,
}

pub async fn events(after_sequence: u64) -> Result<NativeEvents, String> {
    let value = exchange("events", json!({"afterSequence": after_sequence, "limit":256})).await?;
    parse_events(value, after_sequence)
}

fn parse_events(value: Value, after_sequence: u64) -> Result<NativeEvents, String> {
    let batch: NativeEvents = serde_json::from_value(value).map_err(|error| error.to_string())?;
    if batch.events.len() > 256
        || batch.instance_id.is_empty()
        || batch.instance_id.len() > 128
        || batch.instance_id.chars().any(char::is_control)
    {
        return Err("Invalid native event page scope or bound".to_owned());
    }
    let mut sequence = after_sequence;
    for event in &batch.events {
        event.validate()?;
        if event.sequence <= sequence {
            return Err("Native event page is not monotonic".to_owned());
        }
        sequence = event.sequence;
    }
    if batch.next_sequence != sequence {
        return Err("Native event cursor is not acknowledged".to_owned());
    }
    Ok(batch)
}

#[cfg(feature = "network-dev")]
#[allow(clippy::unused_async)]
pub async fn set_app_ban(_: String, _: bool, _: u64, _: String) -> Result<NativeAdapterStatus, String> {
    Err("NETWORK_DEV_HOST_MUTATION_DISABLED: native app bans require a qualified native build".to_owned())
}

#[cfg(not(feature = "network-dev"))]
pub async fn set_app_ban(
    process_path: String,
    blocked: bool,
    expected_generation: u64,
    expected_instance_id: String,
) -> Result<NativeAdapterStatus, String> {
    let before = status().await;
    if before.instance_id != expected_instance_id {
        return Err("Native provider instance changed; review the ban again".to_owned());
    }
    if !before.can_configure_bans() {
        return Err(format!("Native app ban unavailable: {}", before.reason));
    }
    let policy = AppBanPolicy {
        schema_version: 1,
        generation: before.generation,
        process_paths: before.process_paths.clone(),
    }
    .replace(process_path, blocked, expected_generation)?;
    let request = json!({
        "policy": policy,
        "expectedGeneration": expected_generation,
        "expectedInstanceId": expected_instance_id,
    });
    let acknowledgement = parse_status(exchange("apply-bans", request).await?)?;
    if !acknowledgement.can_apply_bans()
        || acknowledgement.instance_id != before.instance_id
        || acknowledgement.generation != policy.generation
        || acknowledgement.process_paths != policy.process_paths
    {
        return Err("Native ban acknowledgement did not match the requested instance, generation and executable paths; refresh native state".to_owned());
    }
    Ok(acknowledgement)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_replies_must_be_bounded_versioned_and_explicitly_acknowledged() {
        assert!(decode_response(b"{}").is_err());
        assert!(decode_response(br#"{"schemaVersion":1,"ok":false,"error":"not installed"}"#).is_err());
        assert!(decode_response(br#"{"schemaVersion":1,"ok":true}"#).is_ok());
        assert!(decode_response(&vec![b' '; MAX_RESPONSE as usize + 1]).is_err());
    }

    #[test]
    fn native_event_cursor_acknowledges_only_valid_returned_events() {
        let event = json!({
            "flowId":"flow", "sequence":42, "timeMs":1,
            "kind":"open", "identityConfidence":"unknown",
            "sourceIp":"127.0.0.1", "sourcePort":1234,
            "destinationIp":"127.0.0.1", "destinationPort":443,
            "network":"tcp", "counterSemantics":"unavailable", "verdict":"observe"
        });
        let page = |events: Vec<Value>, next: u64| {
            json!({
                "instanceId":"provider", "events":events,
                "nextSequence":next, "droppedEvents":100
            })
        };
        assert!(parse_events(page(vec![], 41), 41).is_ok());
        assert!(parse_events(page(vec![], 42), 41).is_err());
        assert!(parse_events(page(vec![], 40), 41).is_err());
        assert!(parse_events(page(vec![event.clone()], 42), 41).is_ok());
        assert!(parse_events(page(vec![event.clone()], 43), 41).is_err());
        assert!(parse_events(page(vec![event.clone(), event.clone()], 42), 41).is_err());
        assert!(parse_events(page(vec![event.clone(); 257], 42), 41).is_err());
        let mut gap = event;
        gap["sequence"] = json!(45);
        // A valid discontinuity reaches the recorder, which persists the coverage gap.
        assert!(parse_events(page(vec![gap], 45), 41).is_ok());
        let mut invalid_scope = page(vec![], 41);
        invalid_scope["instanceId"] = json!("provider\n");
        assert!(parse_events(invalid_scope, 41).is_err());
    }
}
