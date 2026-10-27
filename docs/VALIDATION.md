# Validation

The 0.4.0 migration is validated in layers. Results refer to the tested commit; check the linked GitHub Actions run before using a development preview.

- Frontend TypeScript compilation and Vite production build.
- Catalog parity and interpolation checks for ten locales.
- Browser UI integration: ten languages across eight screens, Arabic RTL, diagnostic recommendations, legacy history localization, connection details, generic errors with preserved originals, language persistence and no horizontal page overflow.
- Constellation animation, pointer parallax, reduced-motion freeze and WebGL fallback. UI integration uses mocked native transport; it is not a native WebView integration test.
- Rust unit tests: strict preferences, atomic store recovery, interrupted scans, TCP parsers, loopback classification, local review signals, profile validation, shell quoting, port validation, retained antivirus detections, partial scans and HTML escaping.
- CI native smoke checks run bundled ClamAV and Tor, enumerate local TCP sockets and query Windows protection states where applicable. A benign custom test fixture and local test signature exercise the ClamAV process/parser without downloading malware or changing firewall/VPN state.
- Installer construction on Windows, Ubuntu and macOS runners. Building a package is not an interactive install/uninstall test or proof of compatibility with every target OS release.

No real firewall hardening, VPN activation, protection-policy change or external reputation lookup is required by the automated checks. ClamAV definition freshness, real provider tunnels, DNS leak protection, Apple notarization and trusted Windows publisher signing are not claimed as validated by these tests.
