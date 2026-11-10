# Aegis 1.0.2

- Refined black and dark-green interface with clearer typography, spacing, selected states, review/unknown indicators, sticky connection-table headers and responsive overview cards.
- Connection searches now include both local and remote ports, formatted IPv6 endpoints and trimmed input. Application counts no longer count worker PIDs as separate named applications. Unknown TCP states remain unknown; absent executable-path evidence cannot produce a no-local-signals result. Existing review signals take precedence over conflicting verdicts.
- Release downloads are reduced to eight platform packages, the signed updater manifest and one sources-and-notices archive. Standalone signatures, checksums, build metadata, documentation and corresponding third-party sources are included in that archive. Updater signatures remain embedded in latest.json. GitHub also provides its automatic source archives.

## Packages and trust

Windows x64 EXE/MSI/portable ZIP, Linux x64 DEB/RPM/AppImage and macOS Apple silicon DMG/app updater archive. All release gates must pass before publication. Updates are version-bound and signed; Windows Authenticode and Apple Developer ID/notarization are not supplied. Connection analysis uses local evidence, without external IP reputation or an automatic malware verdict. ClamAV remains an explicit on-demand or scheduled scan, with engine limits.
