# Security model and review points

## Trust boundaries

The renderer has sandboxing and context isolation enabled, with Node integration
disabled. The preload exposes fixed methods. Main-process handlers validate the
sender, operation, payload size and values. Unexpected navigation and windows are
blocked. Official links use an allowlist and open in the external browser.

The main process runs with user permissions. Administrative operations use fixed
commands, a native review dialog and OS elevation. The whole app does not run as
administrator. Imported WireGuard profiles cannot contain executable hooks.

## Local data and engines

ClamAV and FreshClam run as separate processes with argument arrays. Detections
are retained, with no automatic deletion or file submission. Definition files
are verified by FreshClam. UnRAR modules are excluded because of their restrictive
license; RAR content scanning is not offered.

Tor runs as a client, not a relay, with an exclusive SOCKS listener on loopback.
Its configuration and data are separate from the user's other Tor installations.
Reaching 100% bootstrap does not anonymize the entire computer.

Persisted VPN keys use the OS key store. Linux `basic_text` is rejected. Public
profile metadata excludes keys. Windows service configuration uses DPAPI
LocalMachine within the private user-data directory. Unix `wg-quick` requires a
private configuration file while connected. Keep that directory private.

Language choice is validated against a fixed list and saved with the other local
preferences. Translations are bundled, never remotely requested. Original system
output is not rewritten. HTML reports escape untrusted content and use a
restrictive Content Security Policy.

## Validation still needed in isolated VMs

- Hardening and restoration with UAC/PolicyKit cancellation, failures and GPO.
- A real WireGuard test server: handshake, reconnect, reboot, DNS and IPv6.
- macOS utun observation during native connection lifecycle.
- Complete desktop startup and GUI flows across OS versions and hardware.
- Recovery during interrupted writes and power loss.
- Independent review of IPC, key handling, engine distribution and updates.

This is a personal development and security project. It has not received an
independent security audit or certification. CI results are not a guarantee of
complete endpoint protection.
