# Windows native owner

`network-control-native.exe` is a Windows SCM service and a fixed named-pipe
controller. It does not load, install, stop, delete, or download any kernel driver.
The desktop must invoke its packaged sibling, never a PATH lookup.

The service requires an administrator-installed SCM entry named
`NetworkControlNative` with automatic start, a quoted, administrator-only writable executable path and
arguments `service --owner-sid S-1-...`. The configured SID identifies the desktop
owner. Pipe access is restricted by DACL to that SID, LocalSystem, and Administrators;
requests additionally require the owner SID or LocalSystem and the fixed controller
executable path. Remote pipe clients are rejected. Startup without an explicit SID fails.
The controller and service reject reparse-point paths, unprivileged path owners,
unprivileged write/delete ACLs, and unsupported conditional/object ACLs. A per-user
AppData installation is not a valid LocalSystem service location. Both desktop
and its fixed sibling must be installed in the protected machine-level directory.

Commands: `status`; `apply-bans` with stdin JSON
`{"policy":{"schemaVersion":1,"generation":1,"processPaths":[]},"expectedGeneration":0}`;
`events` with stdin JSON `{"afterSequence":0,"limit":100}`. Responses are JSON.
`apply-bans` is the only controller command that changes native network policy.

Bans are persistent exact-path WFP ALE filters for IPv4/IPv6 inbound and outbound
connections. Replacement and the persistent WFP general-context generation marker
are one WFP transaction.
No existing user or Portmaster filters are removed. Existing-flow teardown is
not guaranteed: `existingFlowBehavior` is `new_flows_only`. Renaming/replacing a
binary changes what an executable-path identity means; this is not code-signature
or application-package identity. There is no native proxy/VPN routing, prompt
holding, or kill-switch guarantee.

Native monitoring is unavailable in this milestone. `events` returns no records,
`monitoring: false`, and an explicit coverage gap. No Portmaster driver is opened.
The shared Portmaster decoder remains groundwork only: its donor shutdown closes
the event queue but leaves callouts active, so a separately signed, dedicated driver
lifecycle and real Windows qualification are required before safe attachment.

Reuse provenance: Safing Portmaster commit
`21a2b0647fe98bd67cd2738853c29f736eb888a7`, GPL-3.0,
`windows_kext/kextinterface/{kext.go,ioctl.go,command.go}` and
`windows_kext/protocol/src/info.rs`. The existing
`clash-verge-network::portmaster` decoder holds this compatibility groundwork;
the Windows WFP service does not link or open the donor driver. The driver is not
copied or modified. Repository `LICENSE` supplies the GPL text.

Build/check on Windows with the repository's Rust toolchain:
`cargo build --manifest-path native/windows/Cargo.toml --release --target x86_64-pc-windows-msvc`.
Cross `cargo check` can verify Windows FFI without a linker. Windows BFE/SCM,
protected administrator installation, and a real Windows networking run are
required to qualify WFP enforcement; host/pure tests cannot do so. Native monitoring
additionally requires the signed, dedicated driver lifecycle described above.
