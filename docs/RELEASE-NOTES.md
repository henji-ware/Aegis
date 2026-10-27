# Aegis 0.4.0 preview

This preview migrates the desktop runtime from Electron/Node.js to Tauri 2 and Rust. React, TypeScript and Three.js remain responsible for the interface.

- Dark green constellation visualization, with point clouds, local process selection, parallax and reduced-motion support.
- Read-only device checks, local connection inspection and on-demand ClamAV scans.
- Native firewall confirmation, reversible settings, WireGuard profiles in the system credential vault, and a loopback-only Tor SOCKS proxy.
- Ten interface languages and original diagnostic details preserved separately.

Installers: Windows x64 NSIS `.exe` and `.msi`; Linux x64 `.deb`, `.rpm` and `.AppImage`; macOS Apple silicon `.dmg`. Check the architecture in each filename. Debian-family packages require WebKitGTK 4.1 and the listed native dependencies. GUI compatibility beyond the CI platforms is not implied.

This is a development preview. ClamAV requires signature downloads before malware scanning. Local connection signals are evidence for review, not a guarantee that a connection is safe or malicious. No external IP reputation service is queried.

The installers currently have no trusted Windows Authenticode or Apple Developer ID signature/notarization. SHA-256 checksums and GitHub artifact attestations verify release integrity and build provenance; they do not remove operating system trust warnings. Do not disable system protections to run this preview.

Electron user data is preserved. Compatible history, settings and firewall recovery information can be imported; VPN secrets need to be reimported into the new system vault. Disconnect a VPN tunnel managed by the old version before switching versions.
