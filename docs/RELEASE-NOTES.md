# Aegis 0.4.1

The first standard release on the stable channel uses Tauri 2 and Rust, with a React, TypeScript and Three.js interface. It is published as a normal GitHub release and selected as the latest release after all release checks succeed.

- Redesigned black overview, restrained dark green details, an orbital point network, local process selection, parallax and reduced-motion support.
- Logo-only sidebar branding and language changes available only in Preferences.
- Ten interface languages, including localized update progress and singular diagnostic summaries.
- Read-only device checks, local connection inspection and on-demand ClamAV scans independent of Windows Defender.
- Quick scans resolve the operating system's Downloads and Desktop folders, including redirected or localized locations.
- Incomplete connection snapshots cannot produce a successful no-listeners diagnostic.
- Invalid local state recovers from the last valid backup instead of crashing. Tor cancellation and pending firewall-rule recovery are hardened.
- Native installation/removal tests, multilingual UI integration, Rust regression tests and dependency vulnerability checks gate publication.
- Obsolete interface-enumeration/build dependencies were removed. Remaining upstream informational advisories are recorded in the dependency review; the release does not claim zero dependency warnings.

## Downloads

Windows x64 NSIS `.exe` and `.msi`; Linux x64 `.deb`, `.rpm` and `.AppImage`; macOS Apple silicon `.dmg`. Check the architecture in each filename. The Debian package requires WebKitGTK 4.1 and the listed native dependencies. Compatibility beyond the documented CI matrix is not implied.

## Behavior and limitations

ClamAV requires signature downloads before normal malware scans. Antivirus scanning is on demand; automatic deletion, quarantine and real-time protection are not implemented. Local connection signals support review and cannot establish that a connection is safe or malicious. No external IP reputation service is queried.

Firewall and VPN changes require explicit confirmation and OS authorization. A WireGuard server/profile is supplied by the user. Tor exposes a loopback-only SOCKS proxy that applications must choose to use. No paid Aegis feature, subscription, telemetry or mandatory account is required.

The stable release channel does not supply a publisher certificate: Windows installers currently have no trusted Authenticode signature, and macOS has no Apple Developer ID signature/notarization. SHA-256 checksums and GitHub artifact attestations verify integrity/build provenance, not operating-system publisher trust. Keep system protections enabled.

## Upgrade

Electron user data is preserved. Compatible history, settings and firewall recovery information can be imported; VPN secrets need to be reimported into the system credential vault. Disconnect a VPN tunnel managed by the old version before switching versions. Application data is retained during uninstall; delete it separately only if you intend to discard your history and recovery information.
