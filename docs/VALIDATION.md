# Release validation

Version 0.4.1 uses the stable release channel. Publication requires successful frontend, Rust dependency-audit and native desktop jobs. Results apply to the exact release commit; consult the release's GitHub Actions run for executed checks.

| Layer | Checks |
| --- | --- |
| Frontend | TypeScript compilation, Vite production build, catalog parity, parameters, constrained Tauri capabilities and shared report messages. |
| UI integration | Ten languages across eight screens, Arabic RTL, original evidence, recommendations, history, errors, language persistence and no horizontal overflow. Constellation motion, pointer parallax, reduced-motion freeze and WebGL fallback. This layer uses mocked native transport. |
| Dependency audit | npm audit fails on high/critical advisories; cargo-audit checks the locked Rust dependencies against RustSec. Warnings and tool output remain visible in CI. This is not an independent security audit. |
| Rust regression | Store validation/recovery, interrupted scans, bounded command output, socket parsing and incomplete snapshots, loopback classification, local review signals, Known Folder scan targets, cancellation, profile validation, ownership reconciliation, shell quoting and HTML escaping. |
| Native engines | Bundled ClamAV and Tor execute on Windows x64, Linux x64 and macOS Apple silicon. A benign fixture and custom local test signature exercise the antivirus process/parser; no malware download is required. TCP inspection and available Windows protection-state queries run read-only. |
| Windows | MSI payload extraction plus native UI Automation. NSIS and MSI installation into isolated CI directories, real installed-app UI/device/ClamAV/diagnostic checks, and uninstall. |
| Linux | DEB metadata/payload, RPM metadata/integrity, libarchive extraction and isolated RPM install/removal with scripts/triggers disabled and dependencies omitted; AppImage extraction; Debian 13 dependency resolution, install and removal. The isolated RPM transaction does not validate Fedora dependency resolution. |
| macOS | DMG mount/copy/removal checks and app bundle ad-hoc signature verification, plus native engine checks. Apple notarization and a full interactive macOS GUI test are not implied. |

Automated release checks do not activate a real VPN, enable Tor, harden the firewall or change endpoint-protection policy. Real provider tunnels, DNS leak protection, definition freshness after installation, every supported desktop environment, trusted Windows publisher signing and Apple Developer ID/notarization remain outside this test matrix.

The absence of known dependency advisories or a completed antivirus scan is not proof that software is free of vulnerabilities or malware. Unknown and incomplete diagnostic evidence is retained as such.
