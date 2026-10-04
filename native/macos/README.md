# macOS native filter

This is a real `NEFilterDataProvider` system-extension source, not a Mihomo rule
or packet-capture prototype. `node native/macos/build.mjs` compiles it and an XPC
controller using the installed SDK; it does not install, launch, sign or activate
the provider. Unsigned builds reject native control before opening XPC.

A qualified build needs a real `NETWORK_CONTROL_TEAM_ID`, explicit
`NETWORK_CONTROL_OWNER_UID`, hardened-runtime Developer ID signatures, authorized
content-filter entitlements and provisioning. The controller identifier is
`io.github.cosxin.network-control.native`; the provider identifier is
`io.github.cosxin.network-control.filter`. Package the controller beside the
desktop executable and the extension under `Contents/Library/SystemExtensions`.
The containing app needs system-extension installation and content-filter
entitlements. There is no activation command in this controller: installation,
user consent, removal and coexistence with other filters remain release work.

`status`, `apply-bans`, `events` and the journal commands use the desktop's bounded JSON contract.
The listener accepts only the configured publisher's controller and owner UID
(or root); the controller verifies the provider's signing requirement. Ban
policies are root-owned, private, persistent and instance/generation-checked. An
`apply-bans` input is `{ "policy": { "schemaVersion": 1, "generation": 8,
"processPaths": [] }, "expectedGeneration": 7, "expectedInstanceId": "<current
status.instanceId>" }`. Refresh status after a provider restart: the instance and
generation checks run together under the policy mutation lock before any save;
missing or stale instance IDs cannot mutate the policy. Missing
policy means fail-closed until an explicit policy is applied; corrupt policy is
preserved and cannot be replaced through this interface.

The controller's `self-test` exercises bounded policy/JSON validation only. To
test the provider's exact CAS guard without launching a filter, compile
`Native.m` plus `Provider.m` with `-DNC_PROVIDER_SELF_TEST` and the same SDK/link
flags as `build.mjs`, then run that separate test executable. It performs no
provider construction, XPC, policy persistence or activation.

Coverage is TCP/UDP socket flows in both directions, including explicit loopback
rules so an app's connection to a local proxy is not intentionally bypassed.
Origin identity comes from OS audit tokens, not a PID cache. Unknown identities
are dropped. Bans target exact canonical executable files, not every helper in
an app bundle. Existing-flow teardown is not guaranteed (`new_flows_only`).

Monitoring uses OS `NEFilterReport` cumulative bytes and close reports, without
exporting packet payloads. The provider's lifetime is independent of the GUI.
The live event ring is bounded and volatile. Optional background recording uses
a separate private, root-owned SQLite journal under
`/Library/Application Support/NetworkControl/native-macos/history.sqlite`.
It is off by default and requires explicit, durable recording consent; legacy
desktop recording settings do not enroll it automatically. `journal-recording`
compares provider instance, journal identity and configuration generation.
`journal-events` preserves the original producer identity and recording epoch;
`journal-ack` removes only a committed prefix after desktop history and its cursor
have been saved together. Restarted providers replay committed frames independently
of GUI lifetime. Disable/clear uses a fresh epoch to fence queued and in-flight
callbacks; retention-only changes preserve the current epoch. Missing confirmations
are visible and reconciled without silently enabling recording.

The journal bounds retention to 1–90 days and 100–20,000 event frames, with a
16 MiB payload budget and 64 MiB database cap. It buffers at most 1,024 frames or
4 MiB and commits asynchronous batches; a crash can lose uncommitted frames.
Reported queue loss and provider restarts remain visible. Invalid or failed
storage is preserved and stops capture; it does not disable ban enforcement.
SQLite secure deletion is not a guarantee of physical erasure on APFS or backups.
`node native/macos/test-journal.mjs` exercises replay, consent boundaries,
acknowledgment and storage failure using a private fixture, without constructing
or activating a native filter.

Live event pages acknowledge only returned events (or
the requested cursor when empty). Lifetime ring evictions include events already
consumed; a reader identifies missed events from sequence discontinuities.
Journal compilation and fixture tests do not qualify live OS capture. Signed
live TCP/UDP IPv4/IPv6, loopback, PID reuse,
byte-count and crash/coexistence behavior has not yet been qualified. Do not
activate this unqualified filter on a daily machine with Little Snitch.
