# Agent control without a configuration reload

`node scripts/network-agent.mjs` exposes bounded JSON diagnostics and leased changes to **existing Mihomo Selector groups**. It has no account, daemon installation or permission to change system proxy, DNS, TUN, profiles, native bans or connection lifetimes. It uses an explicitly supplied loopback controller and secret file; it never discovers or prints an active profile's credentials.

This is a narrow source-level integration, not a disconnect-proof firewall or an automatic best-route service. Read-only diagnostics work across Node-supported desktop platforms. Mutating trials are currently limited to macOS/Linux: Windows private-ACL and watchdog behavior must be qualified before enabling them.

## Read and plan

Use an existing owner-private file containing the controller bearer secret. Do not place the secret in arguments, environment variables, logs or prompts. On Unix the file must belong to the current user with no group/other permissions. The controller must be numeric loopback HTTP (`127.0.0.1` or `[::1]`).

```sh
node scripts/network-agent.mjs status \
  --controller http://127.0.0.1:9097 --secret-file /private/path/controller-secret
node scripts/network-agent.mjs plan \
  --controller http://127.0.0.1:9097 --secret-file /private/path/controller-secret \
  --input /private/path/route-trial.json
```

`status` reports current Selector choices and bounded connection diagnostics. Connection metadata includes local executable paths and destinations; keep its output private. `plan` is read-only and returns the previous choice, protected chain names and connection counts for supplied control executables.

The plan/trial input is:

```json
{
  "controlProcessPaths": ["/canonical/path/to/agent-executable"],
  "group": "existing Selector name",
  "select": "existing member name",
  "ttlSeconds": 30,
  "exclusive": true
}
```

Supply **every executable that carries the agent's control connection**, including separate helpers. Every supplied path must have live core connection evidence. The tool protects the union of all those connections' chain names, including nested groups, and refuses to change any of them. Both the candidate and rollback target must also have visible dependency graphs disjoint from those names. Group traversal includes all possible members, not just its current choice; broad groups that include a control-route member are refused. Missing dependencies and cycles are refused. Hidden `dialer-proxy` dependencies cannot be proved from the API. If the agent bypasses Mihomo or no live flow is observed, it refuses rather than guessing a safe route. It cannot infer omitted control executables.

Use the Apps screen's explicit setup first if an application needs a new managed slot. A trial cannot create groups or rules. To compare candidate routes, keep the agent's control route fixed and probe through a separate application/group; choose based on those real probes. Existing TCP connections retain their original route rather than being rematched.

## Trial, then confirm or restore

```sh
node scripts/network-agent.mjs trial \
  --controller http://127.0.0.1:9097 --secret-file /private/path/controller-secret \
  --input /private/path/route-trial.json
```

The tool rechecks live control chains and the previous selection, arms an independent detached watchdog **before** submitting the change, performs only a Selector PUT and verifies readback. It returns a private `leaseFile`, trial identity, state and deadline. The lease contains an authenticated watchdog endpoint/token, not the core secret. The secret reaches the watchdog through a private pipe, not arguments or environment variables. Treat the lease as a short-lived credential.

After the trial, perform your own fresh real connectivity check through the connection that matters. Confirmation requires caller attestation; it is **not** an internet check performed by this tool:

```json
{"connectivityOk": true, "checkedAt": 1791000000000}
```

Replace the illustrative timestamp with the actual check time in epoch milliseconds. The check must be after the applied change, at most ten seconds old and before the lease deadline.

```sh
node scripts/network-agent.mjs confirm --lease /private/path/lease.json \
  --input /private/path/connectivity-check.json
node scripts/network-agent.mjs status --lease /private/path/lease.json
node scripts/network-agent.mjs rollback --lease /private/path/lease.json
```

If not confirmed within 30–120 seconds, the watchdog attempts to restore the observed previous choice even if the parent agent exited. It refuses a rollback that would now change a live control chain, and skips restoration if another actor visibly changed the selection. Terminal watchdog status remains available briefly, not as durable history. A failed or unconfirmed result is not success.

Confirmation accepts the current **core choice**, not a new saved application policy. The Apps table will show a different live choice until you explicitly save/apply matching desired assignments. A later GUI Apply, profile reload or core restart can override a confirmed trial. The script is supplied in this source repository and requires Node; it is not yet a bundled desktop command.

## Safety boundary

`exclusive: true` means the caller keeps profile reloads, core restarts, GUI and other route writers away for the lease. The core API has no authenticated instance identity; a restarted core or replaced profile with identical names cannot be distinguished reliably. Mihomo also has no atomic compare-and-swap endpoint: checks before writes detect observed conflicts but cannot eliminate the GET/PUT race. Output explicitly reports `checked_before_write_not_atomic`.

Core/watchdog death, restart, OS sleep, an unavailable old server, missing process identity, omitted helpers and external network changes can defeat recovery. There is no cross-restart recovery guarantee. A later connection may follow a different rule. Server-backed macOS tests retained synthetic Hysteria2 and Reality/Vision control streams while separate app/default Selectors changed, including checked trial rollback and fresh-probe confirmation. The same connection continued receiving bytes without a core restart or changed rule definitions. Those tests used separate protocol nodes on one VPS, not the actual Codex connection or the desktop GUI. The server-loopback fixture stall is consistent with the installed Xray version's default private-address block; see [the protocol checks](Network-Control.md#proxy-protocols-and-real-server-checks). That policy was not bypassed, and the successful tests used the server's public address. These results are not a UDP, TUN, multi-server failure-recovery or all-platform availability guarantee. Do not use agent trials to replace an existing firewall, kill switch or independently secured control path.
