# Isolated developer builds

Tracked issue: [network-control foundation #1](https://github.com/Cosxin/clash-verge-rev/issues/1).

These commands build **NetworkControl Dev**, not an upstream production installation. They never launch the app, install a service, register a driver, or change OS networking. The `network-dev` Rust feature is mandatory: it separates application data and IPC, uses direct sidecar mode, and rejects the unavailable alpha core. The Tauri override has identifier `io.github.cosxin.network-control.dev`, an explicit developer product name, no updater endpoints, no updater artifacts, and no deep-link registrations. Use the wrapper, not the upstream `pnpm build`/`pnpm prebuild` commands, for this flavor.

Developer-only runtime guards prevent inherited startup/shutdown proxy/PAC writes and DNS restoration, skip autostart changes, reject privileged service management, and reject GUI system-proxy/TUN/autostart activation. These guards do **not** make the application a general host-network-inert sandbox: the bundled core may listen on local ports or connect to remote servers, and runtime configuration/command paths are not comprehensively qualified. The artifacts below were built and inspected, never launched. Any runtime evaluation still requires a separately approved disposable environment.

## Pinned assets

`scripts/network-assets.json` pins official Mihomo **v1.19.32** and the existing service dependency **v2.7.5**. Every archive must match its committed SHA-256 before staging; cached archives are reverified on every invocation. No `latest` or mutable alpha download is used. The stable binary is not copied into an alpha slot. Existing differing files are preserved and cause an error. Service executables are copied only, never executed. Platform-specific asset manifests record archive and expanded-binary digests.

The engine and service are GPL-3.0 components. Their exact source commits are linked in the pin file and bundled asset manifest; retain the repository's GPL license and upstream notices when redistributing. Releasing derivative binaries requires satisfying the source/notice obligations. No geographic databases are bundled here: mutable upstream geodata and its redistribution terms require a separate pinned licensing review. Configurations using GEOIP/GEOSITE or similar data may therefore fail; this is not a fully qualified end-user package.

## Commands

Use the repository-pinned Node, pnpm and Rust toolchains. Install the exact dependency locks first (`pnpm install --frozen-lockfile --ignore-scripts` and `cargo fetch --locked --target <target>`). `curl` is required for an initial asset download. Downloads use only fixed HTTPS URLs and can be separated from an offline build:

```sh
node scripts/network-prebuild.mjs aarch64-apple-darwin --download --cache /absolute/workspace/asset-cache
node scripts/network-build.mjs aarch64-apple-darwin --cache /absolute/workspace/asset-cache
node scripts/network-build.mjs aarch64-apple-darwin --bundle --cache /absolute/workspace/asset-cache
```

`--debug` selects a faster local native developer build. The default build is release mode. Set `CARGO_TARGET_DIR` to a workspace-local build cache if desired. macOS `--bundle` creates an unsigned `.app` with Tauri and a plain HFS+/UDZO `.dmg` with `hdiutil makehybrid`/`convert`, without attaching an image or automating Finder. It does not submit to the App Store, sign, notarize, install, or open them. The arm64 linker may emit a local ad-hoc executable signature; that is not a Developer ID signature, signed application bundle, or notarization. Developer ID signing/notarization and approved native-extension/service provisioning remain release gates. A compiled app does not prove native firewall, per-app routing, system-wide monitoring, or kill-switch enforcement. Existing disk-image artifacts are preserved; move an earlier image before requesting another build at the same output path.

Run `node --test scripts/network-assets.test.mjs` for the focused pin/configuration/corrupt-cache regression checks. Re-running preparation without `--download` verifies the cached archives and all staged bytes without network access. Use a separate checkout/staging directory for each target architecture; service resource filenames intentionally are not silently overwritten when another architecture is selected.

On native Windows or Linux builders, replace the target in the first two commands with `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`, or `aarch64-unknown-linux-gnu`. Intel macOS uses `x86_64-apple-darwin` (the pinned amd64-v2 core requires a compatible CPU). The wrapper refuses Windows/Linux installer generation until their inherited privileged install hooks and fork identity are qualified. These parameterized mappings are **not evidence of successful native builds or runtime tests**. Install native compiler/system prerequisites before building; cross-compiling from this Mac is not supported by the wrapper.

Before any launch, inspect the built bundle and confirm that the isolated namespace and stable-only core guards are present. Runtime networking tests require a separately approved disposable environment; never test a firewall/service change on the development host.
