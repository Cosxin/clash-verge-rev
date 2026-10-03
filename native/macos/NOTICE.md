# LuLu reuse

Audit-token `SecCodeCopyGuestWithAttributes` / `SecCodeCopyPath` identity resolution,
explicit IPv4/IPv6 loopback rules, system-extension entry point and Mach-service
layout are adapted from Objective-See LuLu commit
`7d2669ed32e5b195d5863dc9695441d3301ba7b0`, GPL-3.0:
`LuLu/Extension/Process.m`, `FilterDataProvider.m`, `XPCListener.m`, `main.m`,
and `Info.plist`. Copyright Objective-See and Patrick Wardle.

Modified 2026-10-02 for exact-executable ban policies, public macOS 13 signing
requirements, owner UID checks and bounded OS flow-statistics reports. LuLu's
alerts, allow-list shortcuts, UI, updater, signing identity and private XPC
audit-token access are not used. The repository's `LICENSE` supplies the GPL text.
