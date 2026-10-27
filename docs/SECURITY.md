# Security model

The Tauri system WebView renders local frontend assets. Rust owns native operations and accepts a fixed method allowlist from the main local window only. Production remote origins are rejected. Capabilities grant event delivery only; the renderer has no generic filesystem, shell, opener or HTTP API. Content Security Policy blocks remote scripts, frames and objects.

Administrative operations require localized native confirmation and OS authorization. PowerShell commands use encoded, fixed templates and validated quoted values. Unix programs receive argument arrays; the macOS administrator bridge quotes every argument. No profile can supply commands or hooks. Normal app operation does not require continuous administrator privileges.

WireGuard configurations permit a small directive allowlist and validated keys, IP routes, ports and endpoints. Imported secrets are stored through the OS credential vault, with no plaintext fallback. A vault failure blocks import. On Windows, the temporary service configuration is machine-DPAPI protected with the tunnel name as its description. Unix configuration files use a private directory and mode 0600 while needed by wg-quick. The app retains uncertain tunnel state until removal can be confirmed. Closing Aegis stops its Tor child but leaves an explicitly activated VPN running.

Native firewall configuration and rule intent are persisted before elevation. Only owned Aegis rules can be removed. Existing UFW rules are not adopted. Restoration keeps the saved prior settings; effective organization policies can still override local policy. A partial or denied operation remains visible and recoverable.

The local store is versioned, written through a synced temporary file and replaced atomically. A valid prior copy is retained. Corruption is preserved before recovery. Interrupted scans never become completed scans; prior detections are retained. Storage and application errors are not treated as successful protection.

ClamAV is an on-demand child process. Its exit status, summary, errors, limits and individual findings determine the result. Detections survive output truncation. The app never executes the inspected executable, automatically deletes files, kills observed processes or uploads file contents. A connection-executable scan rechecks the PID identity, canonical executable path and file metadata shortly before scanning. It is a point-in-time check; the process/file can still change later.

Local connection analysis is heuristic evidence, not threat intelligence. Missing process access yields unknown coverage. A port, IP address, signature absence or file location alone is not a malicious verdict. The decorative constellation is not a packet capture or topology measurement.

HTML reports escape original values and forbid scripts through CSP. Original diagnostic output is preserved separately from localized summaries. Release checksums and attestations cover artifact integrity/provenance only. Trusted Authenticode, Developer ID signing/notarization and an independent security review remain separate work.

Report reproducible issues privately to the repository owner before publishing sensitive details. Do not include private keys, tokens, personal logs or unrelated device data in public reports.
