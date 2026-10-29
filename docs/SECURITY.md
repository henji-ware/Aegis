# Security model

The Tauri system WebView renders local frontend assets. Rust owns native operations and accepts a fixed method allowlist from the main local window only. Production remote origins are rejected. Capabilities grant event delivery only; the renderer has no generic filesystem, shell, opener or HTTP API. Content Security Policy blocks remote scripts, frames and objects.

Administrative operations require localized native confirmation and OS authorization. PowerShell commands use encoded, fixed templates and validated quoted values. Unix programs receive argument arrays; the macOS administrator bridge quotes every argument. No profile can supply commands or hooks. Normal app operation does not require continuous administrator privileges.

WireGuard configurations permit a small directive allowlist and validated keys, IP routes, ports and endpoints. Imported secrets are stored through the OS credential vault, with no plaintext fallback. A vault failure blocks import. On Windows, the temporary service configuration is machine-DPAPI protected with the tunnel name as its description. Unix configuration files use a private directory and mode 0600 while needed by wg-quick. The app retains uncertain tunnel state until removal can be confirmed. Closing Aegis stops its Tor child but leaves an explicitly activated VPN running.

Native firewall configuration and rule intent are persisted before elevation. Only owned Aegis rules can be removed. Existing UFW rules are not adopted. Restoration keeps the saved prior settings; effective organization policies can still override local policy. A partial or denied operation remains visible and recoverable.

The local store is versioned, written through a synced temporary file and replaced atomically. A valid prior copy is retained. Corruption is preserved before recovery. Interrupted scans never become completed scans; prior detections are retained. Storage and application errors are not treated as successful protection.

ClamAV is an on-demand child process. Its exit status, summary, errors, limits and individual findings determine the result. Detections survive output truncation. The app never executes the inspected executable, automatically deletes files, kills observed processes or uploads file contents. A connection-executable scan rechecks the PID identity, canonical executable path and file metadata shortly before scanning. It is a point-in-time check; the process/file can still change later.

Local connection analysis is heuristic evidence, not threat intelligence. Missing process access yields unknown coverage. A port, IP address, signature absence or file location alone is not a malicious verdict. The connection visualization uses observed process/socket relationships; it does not measure packet traffic, geography or remote trust.

HTML reports escape original values and forbid scripts through CSP. Original diagnostic output is preserved separately from localized summaries. Release checksums and attestations cover artifact integrity/provenance only. Trusted Authenticode, Developer ID signing/notarization and an independent security review remain separate work.

Quarantine is explicit and bounded to regular files no larger than 512 MiB. Links, protected application/system paths and changed detections are rejected. Same-volume staging retains recoverable data if sealing fails. The private non-executable container encodes bytes; it is not encryption or an independent integrity authority. SHA-256 is checked before restoration, and an atomic no-overwrite publication preserves an existing destination. Filesystem limitations or permission failures retain the source for recovery.

The Linux VPN control installs a uniquely owned inet nftables table after explicit authorization. It permits loopback, the owned tunnel and its resolved UDP endpoint, and rejects other output. It never flushes global rules. Removal verifies table ownership; confirmed absence permits recovery from a failed apply. It persists until removed, including after tunnel loss. Configuration evidence does not prove absence of DNS/IPv6/application leaks.

Updates are downloaded only from the repository release path, verified by the Tauri updater against an embedded Minisign public key and bound to a signed version. Downgrades are disabled. The private signing key belongs in the repository Actions secret, never in source, artifacts or logs. Pull-request builds use ephemeral test keys and cannot be published by the release job. Compromise of the signing key/release authority can authorize malicious updates; signatures do not replace code review or OS publisher trust.

Report reproducible issues privately to the repository owner before publishing sensitive details. Do not include private keys, tokens, personal logs or unrelated device data in public reports.
