# Validation

## Automated checks

The test suite covers:

- WireGuard validation, protected metadata, lifecycle races and failure recovery.
- Canonical ownership checks before removing managed configuration files.
- Firewall snapshots, partial failures, duplicate ports and owned UFW rules.
- Antivirus output retention, early detections in long logs, read errors,
  partial scans, cancelled jobs and exclusive task preparation.
- Store validation, atomic persistence, backup recovery and corrupt-file retention.
- Windows DPAPI label validation and read-only application-control state handling.
- Linux `ss` and macOS `lsof` parsing with IPv4, IPv6 and actual socket states.
- Split macOS package payloads and native-library search paths.
- Complete locale catalogs, interpolation tokens, locale validation, preference
  migration/persistence and safe localized HTML reports.

`npm run check` runs the Node test suite and TypeScript/Vite build.
`npm run test:locales` exercises all ten languages across eight screens in the
Electron application, RTL, persistence, layout overflow, parallax, animated 3D,
reduced motion and WebGL fallback. UI checks use isolated local state.

## CI and native packages

[Desktop checks](https://github.com/henji-ware/Aegis/actions) runs on
Windows, Linux and macOS. It installs dependencies, runs tests, builds the UI,
prepares checksum-pinned engines, invokes ClamAV/FreshClam/Tor, packages the app
and verifies the packaged engines and runtime links before uploading artifacts.
The previous 0.2.1 workflow passed on all three runner platforms. See the latest
workflow for the current commit's result.

The initial macOS library payload and Linux Tor-library loading failures were
fixed. The package does not rely on the temporary extraction directory.
The packager was updated to 20.3.0 to remove the vulnerable extraction dependency.

## Prior local native observations

- ClamAV 1.5.4 and FreshClam 1.5.4 executed on Windows.
- Harmless custom scanning completed with one file, no detections or read errors.
- An EICAR detection test was performed during the initial implementation.
- Tor 0.4.9.14 reached complete bootstrap and its local process was stopped.
- Windows DPAPI roundtrip confirmed the tunnel-name description format.

## Limits of this evidence

No host firewall rules or VPN tunnels were changed for these tests.
Administrative operations use controlled adapters in the automated suite;
real UAC/PolicyKit flows, VPN handshake, routes, DNS and rollback still need VMs.
Native engine and package checks do not fully validate GUI behavior on every OS.

The restricted development AppContainer uses the test-only
`AEGIS_TEST_NO_SANDBOX=1` flag when launching the official Electron runtime.
Distributed applications retain renderer sandboxing and never add that flag.

A previous unsigned Windows executable was blocked by Smart App Control under
`VerifiedAndReputableDesktop`; correlated 3077/3089 events showed zero signatures.
No security policy was weakened. Read [Windows compatibility](WINDOWS-COMPATIBILITY.md)
for details. Current builds remain unsigned.

Original logs and evidence retain their source language. Translation changes
presentation, not the underlying security result or recorded data.
