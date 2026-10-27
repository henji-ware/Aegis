# Aegis

[![Desktop checks](https://github.com/henji-ware/Aegis/actions/workflows/desktop.yml/badge.svg)](https://github.com/henji-ware/Aegis/actions/workflows/desktop.yml)

A free, open-source desktop application for local security checks, on-demand
antivirus scans, firewall controls, WireGuard profiles and a local Tor proxy.
Built with Electron, React, TypeScript and Three.js.

![Aegis interface](docs/interface.png)

## Version 0.3.0

- Dark green interface with clearer surfaces, spacing and keyboard focus.
- Layered 3D shield, faceted center, orbital arcs, subtle lighting and pointer parallax.
- Ten interface languages, instant switching, saved preference and system detection.
- Right-to-left layout for Arabic and localized date formatting.
- Localized native confirmation dialogs and HTML report headings.
- Original operating-system evidence, filenames and engine logs remain unchanged.
- Lazy-loaded 3D scene, capped rendering, hidden-page pause and reduced-motion mode.

## Languages

Portuguese, English, Spanish, French, German, Russian, Simplified Chinese,
Japanese, Arabic and Hindi. Choose a language in the header or in Settings.

Translations are included in the application. Changing language requires no
translation service, account, internet connection or subscription. Unsupported
system languages fall back to English. Portuguese is the source language for
message identifiers; other catalogs are in `locales/`. Technical output and
previously recorded system evidence retain their original language.

## Features

| Module | Behavior |
|---|---|
| Diagnostics | Read-only observations with explicit passed, attention, review and unknown states. Windows checks include Smart App Control, VBS and memory integrity. |
| Antivirus | Bundled ClamAV and FreshClam, official definition updates, quick/full/custom scans, cancellation and retained detections. Works independently of Windows Defender. |
| Connections | TCP sockets and processes, search, filters, optional refresh and an abstract 3D view. |
| Firewall | Native firewall hardening, saved previous settings, restoration and owned inbound TCP block rules where supported. |
| WireGuard | Validated profiles, OS-protected private keys and explicit connection controls. |
| Tor | Bundled client, startup progress and a private SOCKS5 listener on loopback. |
| Activity | Local history, diagnostic comparisons and HTML export. |

There are no ads, paid tiers, subscription features or telemetry in Aegis.
Aegis source is MIT licensed. Third-party components keep their own licenses;
OS runtime libraries may be distributed under their vendor's terms.

## Using a Windows build

1. Extract the entire distribution folder.
2. Open `Aegis.exe` on a system whose application-control policy permits it.
3. In Antivirus, prepare definitions before the first scan. FreshClam downloads
   and verifies the official database; the initial download can be large.
4. Select a scan target and review its results and any read errors.
5. Run Diagnostics to review configuration evidence and recommendations.

**Windows builds are currently unsigned.** Smart App Control blocked a previous
build on the development computer. Version 0.3.0 does not remove that trust
restriction. See [Windows compatibility](docs/WINDOWS-COMPATIBILITY.md).
No Windows protections are disabled and no trust certificates are installed.

The antivirus is on demand: there is no real-time protection, automatic deletion,
cloud file submission or guarantee of detecting every threat. RAR contents are
not inspected. Scans respect session permissions and file/extraction size limits;
protected, encrypted or oversized files can produce partial results.

## Privacy connections

WireGuard requires a profile and a server you operate or choose. No VPN account
or server is bundled, and no provider is mandatory. An active interface alone
does not establish a successful handshake, full routing or leak protection.
This version has no kill switch. A managed WireGuard tunnel can remain active
after Aegis closes; disconnect it explicitly when needed.

Tor supplies a local proxy. Applications must be configured to use it and resolve
names through Tor. This does not route every application automatically. Use the
official Tor Browser for its browser-specific protections. Aegis stops its Tor
client when it closes.

## Platform coverage

The previous CI completed on Windows x64, Linux x64 and macOS ARM64, including
native engine checks and packaging. Current results are visible in
[GitHub Actions](https://github.com/henji-ware/Aegis/actions).
Those checks do not constitute complete desktop or administrative-operation
validation on every operating system.

| Platform | Firewall | VPN prerequisites |
|---|---|---|
| Windows | Native profiles and owned TCP rules | Bundled WireGuard client; elevation when activating a service |
| macOS | Application firewall and stealth mode | External `wireguard-tools`; secure keychain |
| Linux | UFW and owned rules | UFW, iproute2, PolicyKit, `wireguard-tools` and a secure Secret Service/KWallet backend |

The Linux `basic_text` key-storage fallback is refused. External LuLu and
Portmaster project links are optional integrations, not bundled services.

## Development

Requirements: Node.js 22.12 or newer, npm and platform extraction tools.

```sh
npm ci
node node_modules/electron/install.js
npm run prepare:runtimes
npm run dev
```

Runtime downloads come from official projects and must match pinned SHA-256
hashes in `runtimes.json`. The Windows preparer extracts the WireGuard MSI as a
container and installs no service. macOS requires `pkgutil`; Linux requires
`dpkg-deb`. Third-party sources and licenses must accompany redistribution
according to their licenses.

```sh
npm test
npm run build
npm run test:locales
npm run package
```

The UI integration test requires a working Electron environment. In the restricted
development AppContainer only, `AEGIS_TEST_NO_SANDBOX=1` is used by test scripts;
distributed applications retain renderer sandboxing. The default build never
adds that test argument. `AEGIS_DATA_DIR` selects isolated development storage.

Packages are written to `release/`. CI also executes the engines from the final
package and checks that runtime symlinks do not escape its resource directory.
`AEGIS_ELECTRON_ZIP_DIR` can point to a cached official Electron ZIP.

## Architecture and security boundaries

```text
React / Three.js — sandboxed renderer, no Node integration
        │ validated IPC methods and sender
Electron main process / platform adapters
        ├── ClamAV / FreshClam
        ├── Native firewall
        ├── WireGuard
        ├── Tor — local SOCKS proxy
        └── Local storage / OS key store
```

The renderer uses context isolation and a fixed preload API. Native operations
use fixed executables and validated arguments; there is no generic shell IPC.
WireGuard executable hooks are rejected. Administrative changes require native
review and the OS elevation flow. The interface itself does not run elevated.

State has schema validation, atomic writes and recovery from a validated backup.
Never commit VPN profiles, private keys, state files, engine databases or real
reports. The default repository excludes those files and downloaded runtimes.

See [security notes](docs/SECURITY.md), [validation](docs/VALIDATION.md),
[Windows compatibility](docs/WINDOWS-COMPATIBILITY.md) and
[portfolio notes](docs/PORTFOLIO.md). Documentation and commit messages are in English.

## License

Original Aegis code: [MIT](LICENSE). Component notices:
[THIRD-PARTY-NOTICES](docs/THIRD-PARTY-NOTICES.txt) and
[UI-LICENSES](docs/UI-LICENSES.txt).
