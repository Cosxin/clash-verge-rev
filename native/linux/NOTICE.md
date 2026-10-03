# Linux native adapter provenance

This modified implementation is GPL-3.0-only, dated 2026-10-02. It is not an official OpenSnitch release. Keep this notice, the accompanying GPL license and corresponding source with distributed builds.

The `/proc` socket-to-inode-to-process lookup in `process.go` adapts OpenSnitch's `daemon/netstat/parse.go`, `daemon/netstat/find.go` and `daemon/procmon/find.go` from [OpenSnitch commit a1353848ba1b660320e90cefea782c3fba272c00](https://github.com/evilsocket/opensnitch/tree/a1353848ba1b660320e90cefea782c3fba272c00), by its upstream authors/contributors, licensed under GPL-3.0. Changes remove donor caches, environment/command-line collection and fatal logging; preserve IPv6 address width; reject ambiguous shared sockets; and recheck PID creation time, executable and descriptor identity.

`queue_linux.go` uses OpenSnitch's real Linux NFQUEUE approach but a pure-Go netlink transport. It deliberately does **not** copy the donor's global protocol-family unbind/bind operations or its timeout-to-accept behavior. Only dedicated queue numbers 9100 and 9101 are bound. Both nftables queue bypass and NFQUEUE fail-open flags are disabled. Packet payloads are used to decode IP/transport headers, then discarded; they are not retained in events.

The direct transport dependency `github.com/mdlayher/netlink` is pinned to 1.7.2, also used by the donor, and is MIT-licensed. Its transitive Go dependencies retain their upstream licenses. No donor daemon, driver, nftables table or systemd unit was installed or launched during development on macOS.

This source implements a standalone adapter, not an OS-qualified release, full firewall policy engine, VPN route guarantee or 24/7 durable connection database. The Linux runtime and administrator deployment requirements remain explicit in README.md.
