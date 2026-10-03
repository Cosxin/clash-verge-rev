# Linux native application bans

This standalone daemon uses real Linux NFQUEUE packet interception and OpenSnitch-derived native process lookup. It is separate from the desktop process, so an explicitly installed systemd service continues enforcing bans when the GUI closes. **It has not been run or qualified against a Linux kernel here. Builds and synthetic fixtures are not deployment or enforcement proof.**

The narrow policy is an exact list of executable paths. Every queued TCP/UDP packet, inbound and outbound, is checked; there is no stale process/verdict cache or connection-level allow cache. A banned executable's established-flow packets are dropped too. The daemon does not implement the draft rule schema, prompts, hostname policies, proxy/VPN routing, UDP attribution outside the host network namespace, ICMP or other protocols. Do not advertise a complete firewall or kill switch.

Native identity is `/proc/net/{tcp,tcp6,udp,udp6}` tuple → socket inode → `/proc/PID/fd` → executable with repeated PID start-time/executable/descriptor checks. It remains **inferred**, not kernel event-time signing identity. Shared sockets, inaccessible or racing processes, non-host namespaces, malformed/fragmented packets and unresolved identities fail closed. This can block legitimate traffic. Exact paths should come from native event `processPath`, not symlink aliases; path replacement, exec races and namespace constraints require Linux qualification. TCP listening sockets are matched only when attribution is unambiguous.

## Build without deployment

Go 1.25 or later is required. The transport is pure Go and needs no C NFQUEUE library:

```sh
go test ./...
go vet ./...
make build
```

The two outputs are Linux amd64 and arm64. Running the daemon needs root, procfs, nftables with the JSON interface, and NFQUEUE support. It will refuse to start without explicit `--serve --owner-uid UID --owner-gid PRIVATE_GID`. Ordinary desktop startup never invokes an installer.

## Explicit administrator installation

Use an isolated Linux VM first. Review `networkcontrol.nft` and `networkcontrol-linux.service`, and use a local console—not a remote shell that could be cut off. Create a dedicated private group containing only the authorized desktop user, then configure its numeric GID and that user's UID in root-owned mode-0600 `/etc/networkcontrol/linux.env` as `NETWORKCONTROL_OWNER_UID=...` and `NETWORKCONTROL_OWNER_GID=...`.

Install the architecture-matching binary as root-owned, non-writable `/usr/libexec/networkcontrol-linux`, the unit in `/etc/systemd/system/`, and an initial reviewed mode-0600 policy `/var/lib/networkcontrol/bans.json` inside root-owned mode-0700 `/var/lib/networkcontrol`. `bans.example.json` initializes an empty exact-path list; **unknown identities still block**. Paths in that file must be absolute canonical Linux paths, unique, at most 512 entries and at most 2048 bytes each (serialized list at most 512 KiB). It must never point to a proxy profile.

Only after reviewing these consequences, start the service and explicitly load the dedicated table:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now networkcontrol-linux.service
sudo nft -f networkcontrol.nft
```

The supplied nftables file adds only `inet networkcontrol`, two local input/output hooks and queues 9100/9101. It does not flush, replace or adopt the host's other tables. If that table already exists, installation must fail; inspect its ownership rather than deleting it blindly. Other firewall base chains still apply. No `queue bypass` or NFQUEUE fail-open flag is used.

**If the daemon crashes, is stopped, or queues are full/unavailable, queued TCP/UDP traffic drops.** Stopping the service alone does not restore networking. For deliberate removal, first verify this exact table is the one you installed; then remove only it:

```sh
sudo nft -j list table inet networkcontrol
sudo nft delete table inet networkcontrol
sudo systemctl disable --now networkcontrol-linux.service
```

Do not run those commands as an automated desktop cleanup action. Persistent nftables restore at boot must be coordinated with this service and reviewed separately; the supplied unit alone does not install or restore tables.

## Authenticated local contract

`/run/networkcontrol` is root-owned mode 0750, with the private desktop group. The socket `/run/networkcontrol/adapter.sock` is root-owned mode 0660. The server uses `SO_PEERCRED` and accepts only the configured desktop UID or UID 0, not arbitrary members of the socket group. The desktop must verify the server's root peer credentials and the socket/directory ownership; the filesystem permissions alone are not authentication.

Send one newline-delimited JSON document per connection; receive one JSON response line. Requests and responses are bounded to 1 MiB. Strict request fields:

```json
{"schemaVersion":1,"command":"status"}
{"schemaVersion":1,"command":"apply-bans","expectedGeneration":0,"expectedInstanceId":"INSTANCE_FROM_STATUS","processPaths":["/usr/bin/example"]}
{"schemaVersion":1,"command":"events","afterSequence":0,"limit":256}
```

`apply-bans` replaces only the exact-path native ban list, validates all entries and checks both generation and the required string `expectedInstanceId` from fresh status under the same policy/verdict lock. Missing or stale daemon instances are refused before persistence, even if a restarted daemon retains the same generation. It persists the root policy before acknowledgement. It fails without verified healthy queues and the exact dedicated table; a queue socket alone is not readiness. The policy and generation restore after daemon restart. Before any policy has been initialized, queued traffic blocks until an explicit successful application. The GUI's arbitrary preview policy is never treated as a native policy.

Status includes `schemaVersion`, `ok`, `platform:linux`, `adapterId`, `instanceId`, `installed`, `ready`, `active`, `enforcementActive`, `authenticated`, `policyInitialized`, `monitoring`, `generation`, `processPaths`, `existingFlowBehavior`, `reason`, and coverage/error counters. Installed means the current dedicated table passed structural verification. Active additionally requires healthy queues; before policy initialization it means the queued traffic is blocked, not that a user ban list has been applied. This readiness permits an explicit first generation-0 policy application while `policyInitialized:false` remains truthful. Readiness is rechecked for status/apply requests and periodically, not inferred from a saved setting. `existingFlowBehavior:drop` refers to matching banned flows after initialization; before initialization every queued flow drops.

Events include sequence/time, stable tuple/PID-start-derived `flowId`, optional PID/socket UID/executable/start ticks, inferred/unknown identity, source/destination IP and ports, network, direction, observed IP-packet bytes, submitted verdict and native policy generation. There are no payloads, process arguments, environment values or synthesized DNS names. Unknown identities and decode/queue failures have separate counters. Netlink send success records a submitted verdict; events do not claim an independent kernel acknowledgement.

The bounded ring holds the latest 2048 packet events, pages up to 256 and increments `droppedEvents` on eviction. It is **not durable history**, and `instanceId`/sequence change on restart; reset a cursor when the instance changes. `observedUpload`/`observedDownload` include IP headers, retransmissions and dropped packet attempts; loopback can appear in both directions. They are not socket payload totals, NIC counters or proof of complete bandwidth attribution. `droppedEvents` counts ring eviction, not kernel queue drops; `queueErrors` counts fatal queue transport errors. Kernel queue-overflow drop totals are not collected. Queue overflow/fatal errors can lose events; no synthetic completeness claim is made. Per-packet procfs scanning has not been performance-qualified and can cause substantial drops under load.

License and donor provenance: see [NOTICE.md](NOTICE.md) and [LICENSE](LICENSE).
