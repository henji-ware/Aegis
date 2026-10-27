# Aegis

[![Desktop checks](https://github.com/henji-ware/Aegis/actions/workflows/desktop.yml/badge.svg)](https://github.com/henji-ware/Aegis/actions/workflows/desktop.yml)

Free and open-source desktop security tools, built with **Tauri 2, Rust, React, TypeScript and Three.js**. Local configuration checks, on-demand ClamAV scanning, native firewall controls, WireGuard profiles and a local Tor proxy.

![Aegis interface — illustrative test data](docs/interface.png)

## Download

Installers are published in [GitHub Releases](https://github.com/henji-ware/Aegis/releases). Version 0.4.1 is the first standard release on the stable channel. Windows packages currently have no trusted Authenticode signature; macOS packages have no Developer ID signature or notarization. Operating system application-control policies may prevent execution. GitHub provenance attestations and checksums do not replace platform code signing.

| Platform | Packages | Architecture |
|---|---|---|
| Windows | NSIS `.exe`, `.msi` | x64 |
| Linux | `.deb`, `.rpm`, `.AppImage` | x64 |
| macOS | `.dmg` | Apple silicon |

The `.deb` targets Debian-family systems with WebKitGTK 4.1 and compatible native libraries. An installer build on Ubuntu does not imply that every Debian version or desktop environment has been tested. The 0.4.1 release validates installation and removal on Debian 13. Package dependencies and the exact CI results are documented with each release.

## Features

| Module | Behavior |
|---|---|
| Diagnostics | Read-only checks with passed, attention, review and unknown states. Windows checks include Smart App Control, VBS and memory integrity. |
| Antivirus | Independent ClamAV/FreshClam, quick/full/custom scans, cancellation, retained detections and explicit partial results. No Windows Defender dependency. |
| Connections | TCP sockets, process names, local executable inspection and review signals. A selected executable can be scanned with ClamAV. |
| Firewall | Confirmed native hardening, saved prior settings, restoration and owned inbound TCP block rules on Windows/UFW. |
| WireGuard | Strict profile validation, private keys in the OS credential vault, explicit activation and recoverable tunnel state. No VPN server is supplied. |
| Tor | Bundled Tor client with a loopback-only SOCKS proxy. Applications must opt in to the proxy; it does not route all device traffic. |
| Activity | Local history, comparisons and escaped HTML reports. |

Connection analysis uses local evidence. A listening port or a temporary executable location is a reason to review, not proof of malware. No external IP reputation service receives your connections. No automatic process termination, file deletion, quarantine or real-time antivirus protection is implemented. ClamAV definitions must be downloaded before normal scans; a completed scan is not a guarantee that a file is safe.

## Interface and languages

Black surfaces with restrained dark green details, an orbital point network, local process selection and pointer parallax. The overview separates diagnostic indicators, connections, device state and module access. Decorative stars and lines are abstract; they do not represent geography, measured traffic or detected attacks. Continuous movement stops with reduced motion and pauses while hidden.

Portuguese, English, Spanish, French, German, Russian, Simplified Chinese, Japanese, Arabic and Hindi are bundled. Language changes are available only in Preferences, take effect immediately and are saved. Arabic uses right-to-left layout. App summaries, recommendations and history headings follow the selected language. Original OS/engine output and legacy records remain available under **Original details**. No translation service is contacted.

## Architecture

`src/` contains React/TypeScript and Three.js. `src-tauri/src/` contains the native Rust implementation. The distributed app has **no Electron or Node.js runtime**. Node.js is used only by frontend/build tooling.

The system WebView renders the interface. Rust accepts a fixed set of validated commands from the local main window. No arbitrary shell, filesystem, remote URL or remote WebView capability is granted to the frontend. Administrative firewall/VPN actions require native confirmation and OS authorization. External engines run as child processes with fixed argument arrays.

Windows WebView2, macOS WKWebView and Linux WebKitGTK are platform dependencies. Their licensing and distribution terms remain applicable. Aegis has no ads, payments, premium tiers, telemetry or mandatory account. Aegis source is MIT licensed; component licenses are preserved separately.

## Build

Install Node.js 22+, the Rust stable toolchain and the [Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/). Windows builds need Visual Studio C++ Build Tools and WebView2; Linux builds need WebKitGTK 4.1 development packages and D-Bus libraries.

```sh
npm ci
npm run check
npm run prepare:runtimes
node scripts/stage-runtimes.cjs
npm run test:rust
npm run package
```

`npm run dev` runs Tauri development mode. `npm run dev:web` previews only the frontend; native features require the desktop application. Installers are written under `src-tauri/target/release/bundle/`. Runtime downloads are pinned and checked against `runtimes.json`. Packaging excludes the restricted UnRAR modules.

## Validation and migration

See [validation](docs/VALIDATION.md), [security](docs/SECURITY.md), [dependency review](docs/DEPENDENCY-REVIEW.md), [Windows compatibility](docs/WINDOWS-COMPATIBILITY.md) and [release notes](docs/RELEASE-NOTES.md). The screenshot uses illustrative test fixtures, not a claim about the current device.

Electron data is preserved when migrating. Compatible settings, history and firewall recovery information are copied to the Tauri store. VPN profiles need to be reimported into the new OS credential vault. An existing owned tunnel is retained for explicit recovery/disconnection when its configuration can be copied. Disconnect VPNs using the previous version before switching whenever possible. Invalid local data is preserved and recovered from its last valid backup instead of silently discarded.

See [third-party notices](docs/THIRD-PARTY-NOTICES.txt) and [LICENSE](LICENSE). Corresponding engine source archives accompany releases. Build provenance can be verified using `gh attestation verify <installer> --repo henji-ware/Aegis`; verify SHA-256 values using the release checksum file as well.
