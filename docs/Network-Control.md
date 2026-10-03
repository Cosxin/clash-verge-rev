# Network control workspace

The **Network** page provides draft policies, explicit per-application Mihomo routing, native ban controls and source-specific connection history. Draft policy previews remain observe-only. Native controls are unavailable without an installed, authenticated adapter; the source implementation is not yet a qualified replacement for an installed firewall or VPN kill switch.

## Application routing

App routing offers observed applications and a file/application picker, a named server or proxy group for each executable, and a default route. On macOS, selecting an `.app` resolves its main executable; helper processes have separate executable identities and may need separate assignments. Options come from the active profile and running core. Assignments use exact canonical executable paths and engine-inferred identity, not code-signing identity.

Save persists the desired assignments only. Apply requires explicit confirmation of the saved generation and current profile, validates and reloads the core, then commits the active policy. A newer profile/generation cannot silently reuse an old confirmation. Enabled assignments prepend `PROCESS-PATH` rules and a default `MATCH` rule, overriding the profile's lower-priority rules. Rule mode is required, but this screen never changes mode, TUN, system proxy or DNS. Disabling requires Apply to remove the previously applied rules.

The applied badge requires the live core's rule prefix, process lookup, mode, generation and profile to match. Missing targets compile to `REJECT`, never a silent direct fallback, and are not advertised as the chosen route. Routing applies to **new connections entering Mihomo**; bypass traffic and existing connections are not guaranteed to move. A loopback-only test with the pinned Mihomo core verified two executable assignments, default selection and live reassignment; this does not qualify encrypted VPN/TUN behavior.

## Native application bans

Overview offers a separate Ban control, not a draft preview. Its controller uses generation-checked, authenticated native IPC and reports a ban only after the adapter acknowledges the same instance, generation and exact path set. Native policies are persisted separately from proxy profiles. The developer build deliberately disables native writes.

macOS uses a LuLu-derived audit-token identity path and NetworkExtension data provider. It requires a configured Developer ID publisher, signed hardened controller/provider, system-extension entitlement and explicit installation/consent; this checkout has no activation helper. Windows uses a dedicated owner-authenticated service and persistent WFP application filters for IPv4/IPv6 connect/receive-accept. These adapters affect new flows; existing-flow teardown is not guaranteed. Windows native monitoring is not implemented, and no Portmaster driver is claimed active.

Linux uses an explicitly installed root NFQUEUE daemon with a dedicated nftables table, private socket and peer credentials. It rechecks bidirectional TCP/UDP packets, including established traffic, and infers executable ownership through procfs with process-start/fd checks. Ambiguous/unknown identity is blocked. Other firewall providers/tables are not flushed. Performance, kernel coverage and deployment remain unqualified.

Native macOS source builds against the local SDK, Windows source passes target-specific compile checks, and Linux builds for amd64/arm64. None of the providers has been installed or activated on this host. Signed macOS consent/coexistence, Windows linking/service/WFP behavior, and Linux kernel/nft behavior need disposable OS testing. Keep existing protections in place.

## Draft policies

Use Policies to create firewall and route rules with the existing editor or advanced JSON. Conditions include executable path, unknown identity, hostname/domain suffix, IP/CIDR, port and TCP/UDP. Firewall decisions and route choices are separate. Rules use descending priority, then their saved order. Save validates the complete document and advances its generation; a stale editor cannot overwrite a newer policy.

Preview evaluates the saved draft for a supplied connection. `allow`, `block`, `ask` and route results are previews, not native verdicts or actual network paths. An executable path inferred by the core is not verified application identity. Imported or edited rules are not applied to the running core or OS.

Background refreshes adopt a newer generation only when the editor is clean. Unsaved edits and open rule/import dialogs keep their original save generation; a visible warning indicates a newer saved policy. Saving a stale draft fails without discarding it. Explicitly confirm Discard to reload the latest policy. Successful saves adopt the backend-acknowledged document before refreshing other views.

## Little Snitch rule interoperability

Import a user-selected `.lsrules` file to review translated firewall rules and rejection diagnostics. Accepting the review replaces the editor's firewall draft only and preserves its route rules; an explicit Save is still required. Unsupported `via`, signing-code identities, owner scopes, inbound/special remote classes, malformed/null constraints and unsupported fields are rejected, not broadened to unrestricted permissions.

The converter reuses the open-source `ls_rules` 0.4.1 format model (MIT OR Apache-2.0). Little Snitch's specificity precedence differs from this draft's ordering: an entire transfer with potentially overlapping, opposing equal-priority rules is rejected. This deliberately limits compatibility until equivalent resolution can be established.

Export includes only representable outgoing firewall rules, with a review of omissions. Routes are not exported as allow rules. Policy defaults, generation and observe-only state are not part of the `.lsrules` format. Rule exports can contain executable paths and destinations; review the file before sharing it. Nothing invokes or modifies an installed Little Snitch instance.

## Connection history

Recording is opt-in and off by default. When enabled, the backend samples Mihomo connections and polls authenticated monitoring adapters every two seconds, persisting bounded local history. Mihomo observations are **core-only and sampled**: bypass traffic and connections shorter than the interval may be absent. Disappearance is marked `ended_incomplete`, not a confirmed socket close. Native events retain source/destination, process evidence, sequence, verdict and policy generation; OS close reports are distinguished from inferred disappearance.

Counters use source-specific semantics: core cumulative snapshots, macOS OS reports, or Linux observed IP packet bytes. Replay/reset handling avoids adding unchanged counters twice. Native and core records can overlap; the UI separates their counters and never publishes a combined system total. Missing samples and reported dropped events/records are visible. Core disk saves are coalesced, so abrupt exit can lose the latest approximately ten seconds of samples. Native event queues are bounded and volatile. Independent durable 24/7 monitoring, Windows event collection and complete final-byte guarantees are unfinished.

Overview configures retention (1–90 days) and maximum records (100–20,000); byte budgets also bound persistence. History supports search, pagination, clear confirmation and redacted export. Redacted exports omit executable paths, hosts, destination addresses and detailed rule payloads; local history still contains sensitive connection metadata. Existing corrupt/unreadable storage is preserved rather than overwritten, with a visible read-only/error state.

## Storage and native rollout

The workspace lives in `network-workspace/workspace.json` under the application's platform data directory, separate from proxy profiles. Unix files/directories are private to the current user. Recording, rules and deletion do not change proxy, DNS, routes or firewall settings.

Native source reuses LuLu/NetworkExtension and OpenSnitch components with provenance recorded under `native/`; shared Portmaster event decoding is groundwork, not an active driver integration. Inherited TUN support is separate from qualified whole-system per-application routing and kill-switch guarantees. Keep your existing firewall/VPN protections in place until those guarantees are verified on each target OS.

Tracking issue: [Cosxin/clash-verge-rev#1](https://github.com/Cosxin/clash-verge-rev/issues/1).
