# Aegis 1.0.0

- Reorganized black overview with dark green details, meaningful process-to-socket 3D relationships, pointer parallax, reduced motion and a readable WebGL fallback.
- Larger, sharper cube icon for the Windows Start menu and application packages. Logo-only sidebar; no storage/version footer, external firewall promotions or components panel.
- Ten bundled interface languages. Language selection remains in Preferences; original operating-system and engine evidence stays available separately.
- Independent ClamAV scans with file inventory, real processed/total percentage, current path, per-file causes and one partial-result explanation. Preparation remains indeterminate until the file list is known.
- Explicit quarantine with detection recheck, SHA-256 verification, recoverable journal state and restoration that refuses an existing destination.
- Daily/weekly schedules, selected weekday, missed-task recovery, opt-in definition checks every four hours, startup and background tray mode. Aegis must be running for these tasks.
- Opt-in connection change history and in-app alerts for new non-loopback listening services. Signals support review and do not establish maliciousness.
- Local VPN interface, route and DNS evidence, optional authorized public-IP lookup, and explicit reversible Linux nftables blocking outside an active owned single-peer WireGuard tunnel.
- Version-bound signed in-app updates on supported Windows installers, AppImage and macOS app builds. DEB/RPM and portable Windows builds use manual updates.
- Windows no-install ZIP, NSIS EXE and MSI; Linux DEB, RPM and AppImage; macOS Apple silicon DMG. Architecture is recorded in each filename.

## Validation

Publication is gated by frontend checks, ten-language UI integration, dependency audits, Rust regression tests, native engine tests, installer checks and updater signature/tamper tests. The Linux VPN test creates a real WireGuard tunnel in disposable disconnected namespaces and exercises IPv4/IPv6 blocking, tunnel loss and owned-rule removal. Consult the exact release workflow and VALIDATION.md for executed evidence and limits.

## Behavior and limits

ClamAV definitions must be downloaded before normal malware scans. Scanning is on demand or scheduled; no continuous file interception or automatic deletion is supplied. Quarantine containers encode file bytes to prevent accidental execution; they are not encrypted storage. Definition downloads may be rate limited by the upstream service, with original errors retained.

VPN servers/profiles are supplied by the user. The Linux blocking control persists after tunnel/app closure until explicitly removed. Route/DNS configuration checks and a public-IP result are not a comprehensive leak test. Tor provides a loopback SOCKS proxy that applications must choose to use. Firewall/VPN changes require native confirmation and OS authorization.

Windows artifacts currently have no trusted Authenticode publisher certificate; macOS has no Apple Developer ID signature/notarization. Updater signatures, SHA-256 checksums and GitHub build attestations cover separate integrity/provenance properties and do not replace OS publisher trust. Keep system protections enabled.

## Upgrade

Existing Tauri settings, history and recovery information are retained. New automation controls default to off. Data remains in the user profile after uninstall. When migrating from Electron, compatible records are preserved and VPN secrets must be reimported into the OS credential vault. Disconnect a tunnel managed by the old version before switching versions.
