// SPDX-License-Identifier: GPL-3.0-only
mod wfp;

use crate::model::{AppBanPolicy, ApplyRequest, EventsRequest, MAX_MESSAGE};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    io::{self, Read},
    ptr::{null, null_mut},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use windows_service::{
    define_windows_service,
    service::{ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType},
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{IO::*, Pipes::*, Threading::*},
};
use windows_sys::core::BOOL;

pub const SERVICE_NAME: &str = "NetworkControlNative";
const PIPE_NAME: &str = r"\\.\pipe\NetworkControlNative-v1";
const MONITORING_GAP: &str = "Windows native monitoring is unavailable: dedicated signed-driver lifecycle and real Windows qualification are required; no driver is opened";
static OWNER: OnceLock<String> = OnceLock::new();
static STOP: AtomicBool = AtomicBool::new(false);

pub(super) fn wide(value: &str) -> Result<Vec<u16>, String> {
    if value.contains('\0') {
        return Err("NUL is not valid in a Windows name".into());
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}
pub(super) fn win_error(operation: &str, code: u32) -> String {
    format!("{operation}: Windows error {code:#x}")
}
fn last_error(operation: &str) -> String {
    win_error(operation, unsafe { GetLastError() })
}
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

pub(super) struct Handle(pub HANDLE);
// Handles are kernel-managed. Every pending operation retains its own event/buffer.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
impl Handle {
    fn checked(raw: HANDLE, operation: &str) -> Result<Self, String> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(last_error(operation))
        } else {
            Ok(Self(raw))
        }
    }
}

fn completion(handle: HANDLE, overlapped: &mut OVERLAPPED, started: BOOL, timeout: u32) -> io::Result<u32> {
    if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
        return Err(io::Error::last_os_error());
    }
    if unsafe { WaitForSingleObject(overlapped.hEvent, timeout) } != WAIT_OBJECT_0 {
        unsafe {
            CancelIoEx(handle, overlapped);
        }
        let mut count = 0;
        // OVERLAPPED and its data buffer must outlive cancellation completion.
        unsafe {
            GetOverlappedResult(handle, overlapped, &mut count, 1);
        }
        return Err(io::Error::new(io::ErrorKind::TimedOut, "Native transport timed out"));
    }
    let mut count = 0;
    if unsafe { GetOverlappedResult(handle, overlapped, &mut count, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(count)
}
pub(super) fn read_io(handle: HANDLE, bytes: &mut [u8], timeout: u32) -> io::Result<usize> {
    let event =
        Handle::checked(unsafe { CreateEventW(null(), 1, 0, null()) }, "Create I/O event").map_err(io::Error::other)?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.0;
    let started = unsafe {
        ReadFile(
            handle,
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            null_mut(),
            &mut overlapped,
        )
    };
    completion(handle, &mut overlapped, started, timeout).map(|n| n as usize)
}
pub(super) fn write_io(handle: HANDLE, bytes: &[u8], timeout: u32) -> io::Result<()> {
    let event =
        Handle::checked(unsafe { CreateEventW(null(), 1, 0, null()) }, "Create I/O event").map_err(io::Error::other)?;
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.0;
    let started = unsafe { WriteFile(handle, bytes.as_ptr(), bytes.len() as u32, null_mut(), &mut overlapped) };
    let count = completion(handle, &mut overlapped, started, timeout)?;
    if count as usize != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "Incomplete native transport write",
        ));
    }
    Ok(())
}
fn read_exact(handle: HANDLE, bytes: &mut [u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let count = read_io(handle, &mut bytes[offset..], 5000).map_err(|e| e.to_string())?;
        if count == 0 {
            return Err("Native pipe closed before complete request".into());
        }
        offset += count;
    }
    Ok(())
}
fn read_message(handle: HANDLE) -> Result<Value, String> {
    let mut header = [0; 4];
    read_exact(handle, &mut header)?;
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > MAX_MESSAGE {
        return Err("Native request exceeds its bounded message size".into());
    }
    let mut bytes = vec![0; length];
    read_exact(handle, &mut bytes)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("Invalid native request JSON: {e}"))
}
fn write_message(handle: HANDLE, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_MESSAGE {
        return Err("Native response exceeds message limit".into());
    }
    write_io(handle, &(bytes.len() as u32).to_le_bytes(), 5000).map_err(|e| e.to_string())?;
    write_io(handle, &bytes, 5000).map_err(|e| e.to_string())
}

fn process_identity(pid: u32) -> Result<(String, String), String> {
    let process = Handle::checked(
        unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) },
        "Inspect native peer",
    )?;
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut length) } == 0 {
        return Err(last_error("Resolve native peer executable"));
    }
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut token) } == 0 {
        return Err(last_error("Inspect native peer SID"));
    }
    let token = Handle(token);
    let mut size = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut size);
    }
    if size == 0 || size > 65536 {
        return Err("Native peer token has invalid length".into());
    }
    let mut data = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe { GetTokenInformation(token.0, TokenUser, data.as_mut_ptr().cast(), size, &mut size) } == 0 {
        return Err(last_error("Read native peer SID"));
    }
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return Err(last_error("Format native peer SID"));
    }
    let mut sid_len = 0;
    unsafe {
        while *sid.add(sid_len) != 0 {
            sid_len += 1;
        }
    }
    let sid_string = String::from_utf16(unsafe { std::slice::from_raw_parts(sid, sid_len) }).map_err(|e| e.to_string());
    unsafe {
        LocalFree(sid.cast());
    }
    Ok((
        String::from_utf16(&path[..length as usize]).map_err(|e| e.to_string())?,
        sid_string?,
    ))
}
fn verify_peer(pid: u32, allowed_sid: &str) -> Result<(), String> {
    let (path, sid) = process_identity(pid)?;
    let own = std::env::current_exe().map_err(|e| e.to_string())?;
    if sid != allowed_sid && sid != "S-1-5-18" {
        return Err("Native peer does not belong to the configured owner or LocalSystem".into());
    }
    if std::fs::canonicalize(path).map_err(|e| e.to_string())?
        != std::fs::canonicalize(own).map_err(|e| e.to_string())?
    {
        return Err("Native peer is not the installed fixed controller executable".into());
    }
    Ok(())
}

fn sid_text(sid: PSID) -> Result<String, String> {
    let mut text = null_mut();
    if sid.is_null() || unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(last_error("Inspect installed-controller ACL identity"));
    }
    let mut length = 0;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).map_err(|e| e.to_string());
    unsafe {
        LocalFree(text.cast());
    }
    result
}

fn protected_installation() -> Result<(), String> {
    let account = wide(r"NT SERVICE\TrustedInstaller")?;
    let (mut sid_size, mut domain_size, mut account_kind) = (0, 0, 0);
    unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            null_mut(),
            &mut sid_size,
            null_mut(),
            &mut domain_size,
            &mut account_kind,
        );
    }
    if sid_size == 0 || sid_size > 4096 || domain_size > 32768 {
        return Err("Cannot resolve the Windows installer security identity".into());
    }
    let mut installer_sid = vec![0usize; (sid_size as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut domain = vec![0u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            null(),
            account.as_ptr(),
            installer_sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut account_kind,
        )
    } == 0
    {
        return Err(last_error("Resolve Windows installer security identity"));
    }
    let installer_sid = sid_text(installer_sid.as_mut_ptr().cast())?;
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    for (index, path) in executable.ancestors().enumerate() {
        let name = wide(path.to_str().ok_or("Installed-controller path is not Unicode")?)?;
        let attributes = unsafe { GetFileAttributesW(name.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("Installed-controller path must not contain reparse points".into());
        }
        let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
        let code = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if code != 0 {
            return Err(win_error("Inspect installed-controller protections", code));
        }
        let result = (|| {
            let privileged = |sid: &str| sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == installer_sid;
            if !privileged(&sid_text(owner)?) || dacl.is_null() {
                return Err(
                    "Native controller and parent directories must have privileged owners and explicit DACLs".into(),
                );
            }
            let writes = DELETE
                | WRITE_DAC
                | WRITE_OWNER
                | FILE_DELETE_CHILD
                | if index <= 1 {
                    GENERIC_WRITE
                        | GENERIC_ALL
                        | FILE_WRITE_DATA
                        | FILE_APPEND_DATA
                        | FILE_WRITE_EA
                        | FILE_WRITE_ATTRIBUTES
                } else {
                    GENERIC_ALL
                };
            for number in 0..unsafe { (*dacl).AceCount } {
                let mut ace = null_mut();
                if unsafe { GetAce(dacl, u32::from(number), &mut ace) } == 0 {
                    return Err(last_error("Inspect native controller access rule"));
                }
                let header = unsafe { &*ace.cast::<ACE_HEADER>() };
                if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 || header.AceType == 1 {
                    continue;
                }
                if header.AceType != 0 {
                    return Err("Native controller has an unsupported conditional/object ACL; administrator installation must use ordinary access rules".into());
                }
                let allow = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let sid = (&raw const allow.SidStart).cast_mut().cast();
                if allow.Mask & writes != 0 && !privileged(&sid_text(sid)?) {
                    return Err("Native controller or its path is writable by an unprivileged identity".into());
                }
            }
            Ok(())
        })();
        unsafe {
            LocalFree(descriptor);
        }
        result?;
    }
    Ok(())
}

pub(super) struct State {
    engine: wfp::Engine,
    policy: Option<AppBanPolicy>,
    owner_sid: String,
    instance_id: String,
}
impl State {
    fn status(&mut self) -> Result<Value, String> {
        self.policy = self.engine.policy()?;
        Ok(
            json!({"schemaVersion":1,"ok":true,"platform":"windows","installed":true,"active":true,"enforcementActive":self.policy.is_some(),"authenticated":true,"policyInitialized":self.policy.is_some(),"generation":self.policy.as_ref().map_or(0, |p|p.generation),"processPaths":self.policy.as_ref().map_or_else(Vec::new, |p|p.process_paths.clone()),"instanceId":self.instance_id,"ownerSid":self.owner_sid,"monitoring":false,"driverReady":false,"coverageGap":MONITORING_GAP,"reason":MONITORING_GAP,"existingFlowBehavior":"new_flows_only","routing":false,"killSwitch":false}),
        )
    }
    fn request(&mut self, value: Value) -> Result<Value, String> {
        match value.get("command").and_then(Value::as_str) {
            Some("status") => self.status(),
            Some("apply-bans") => {
                let request: ApplyRequest =
                    serde_json::from_value(value.get("data").cloned().ok_or("Missing app-ban request")?)
                        .map_err(|e| e.to_string())?;
                self.policy = self.engine.policy()?;
                request.validate(&self.instance_id, self.policy.as_ref().map_or(0, |p| p.generation))?;
                self.engine.replace(&request.policy)?;
                self.status()
            }
            Some("events") => {
                let request: EventsRequest =
                    serde_json::from_value(value.get("data").cloned().unwrap_or_else(|| json!({})))
                        .map_err(|e| e.to_string())?;
                if !(1..=1000).contains(&request.limit) || request.after_sequence != 0 {
                    return Err("Invalid native events cursor or limit".into());
                }
                Ok(
                    json!({"schemaVersion":1,"ok":true,"instanceId":self.instance_id,"events":[],"nextSequence":0,"droppedEvents":0,"monitoring":false,"coverageGap":MONITORING_GAP}),
                )
            }
            _ => Err("Unsupported native command".into()),
        }
    }
}

fn connect_server(pipe: HANDLE) -> Result<bool, String> {
    let event = Handle::checked(unsafe { CreateEventW(null(), 1, 0, null()) }, "Create pipe event")?;
    let mut operation: OVERLAPPED = unsafe { std::mem::zeroed() };
    operation.hEvent = event.0;
    if unsafe { ConnectNamedPipe(pipe, &mut operation) } != 0 {
        return Ok(true);
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_PIPE_CONNECTED {
        return Ok(true);
    }
    if error != ERROR_IO_PENDING {
        return Err(win_error("Connect native pipe", error));
    }
    while !STOP.load(Ordering::Acquire) {
        if unsafe { WaitForSingleObject(event.0, 200) } == WAIT_OBJECT_0 {
            let mut bytes = 0;
            if unsafe { GetOverlappedResult(pipe, &operation, &mut bytes, 0) } == 0 {
                return Err(last_error("Complete pipe connection"));
            }
            return Ok(true);
        }
    }
    unsafe {
        CancelIoEx(pipe, &operation);
    }
    let mut bytes = 0;
    unsafe {
        GetOverlappedResult(pipe, &operation, &mut bytes, 1);
    }
    Ok(false)
}
fn serve(owner: &str) -> Result<(), String> {
    protected_installation()?;
    let (_, own_sid) = process_identity(unsafe { GetCurrentProcessId() })?;
    if own_sid != "S-1-5-18" {
        return Err("Native owner service must run as LocalSystem".into());
    }
    let sddl = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner})"))?;
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(last_error("Create owner-only pipe security"));
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateNamedPipeW(
            wide(PIPE_NAME)?.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_MESSAGE as u32,
            MAX_MESSAGE as u32,
            5000,
            &attributes,
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    let pipe = Handle::checked(raw, "Create native owner pipe")?;
    let engine = wfp::Engine::open()?;
    let policy = engine.policy()?;
    let mut state = State {
        engine,
        policy,
        owner_sid: owner.into(),
        instance_id: format!("windows-{}-{}", unsafe { GetCurrentProcessId() }, now_ms()),
    };
    while !STOP.load(Ordering::Acquire) && connect_server(pipe.0)? {
        let response = (|| {
            let mut pid = 0;
            if unsafe { GetNamedPipeClientProcessId(pipe.0, &mut pid) } == 0 {
                return Err(last_error("Authenticate native client"));
            }
            verify_peer(pid, owner)?;
            let request = read_message(pipe.0)?;
            state.request(request)
        })()
        .unwrap_or_else(|error| json!({"schemaVersion":1,"ok":false,"error":error}));
        let _ = write_message(pipe.0, &response);
        unsafe {
            DisconnectNamedPipe(pipe.0);
        }
    }
    Ok(())
}

define_windows_service!(ffi_service_main, service_main);
fn service_main(_arguments: Vec<OsString>) {
    let handler = service_control_handler::register(SERVICE_NAME, |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP.store(true, Ordering::Release);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    });
    let Ok(handle) = handler else {
        return;
    };
    let mut status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    if handle.set_service_status(status.clone()).is_err() {
        return;
    }
    let result = OWNER
        .get()
        .ok_or_else(|| "Missing configured owner SID".to_owned())
        .and_then(|owner| serve(owner));
    status.current_state = ServiceState::Stopped;
    status.controls_accepted = ServiceControlAccept::empty();
    status.exit_code = ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 });
    let _ = handle.set_service_status(status);
}

pub fn run() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let command = arguments
        .first()
        .map(String::as_str)
        .ok_or("Use status, apply-bans, events, or service --owner-sid SID")?;
    if command == "service" {
        if arguments.len() != 3 || arguments[1] != "--owner-sid" {
            return Err("SCM service requires explicit --owner-sid SID".into());
        }
        let owner = &arguments[2];
        if !owner.starts_with("S-1-")
            || owner.len() > 184
            || !owner.bytes().all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
        {
            return Err("Invalid owner SID".into());
        }
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(wide(owner)?.as_ptr(), &mut sid) } == 0 {
            return Err(last_error("Validate owner SID"));
        }
        let valid = unsafe { IsValidSid(sid) } != 0;
        let canonical_owner = sid_text(sid);
        unsafe {
            LocalFree(sid);
        }
        if !valid {
            return Err("Invalid owner SID".into());
        }
        OWNER
            .set(canonical_owner?)
            .map_err(|_| "Owner already configured".to_owned())?;
        return service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| e.to_string());
    }
    if arguments.len() != 1 || !matches!(command, "status" | "apply-bans" | "events") {
        return Err("Unsupported native controller arguments".into());
    }
    protected_installation()?;
    let data = if command == "status" {
        Value::Null
    } else {
        let mut bytes = Vec::new();
        io::stdin()
            .take((MAX_MESSAGE + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > MAX_MESSAGE {
            return Err("Native stdin request exceeds byte limit".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid native stdin JSON: {e}"))?
    };
    let pipe_name = wide(PIPE_NAME)?;
    if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), 3000) } == 0 {
        return Err(last_error("Native service is not available"));
    }
    let pipe = Handle::checked(
        unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        },
        "Connect installed native service",
    )?;
    let mut server_pid = 0;
    if unsafe { GetNamedPipeServerProcessId(pipe.0, &mut server_pid) } == 0 {
        return Err(last_error("Authenticate native service"));
    }
    verify_peer(server_pid, "S-1-5-18")?;
    write_message(pipe.0, &json!({"command":command,"data":data}))?;
    let response = read_message(pipe.0)?;
    println!("{response}");
    Ok(())
}
