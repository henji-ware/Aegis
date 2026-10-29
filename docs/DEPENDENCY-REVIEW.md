# Dependency review — 1.0.0

Review date: 2026-10-28. The locked dependency graph is checked with cargo-audit against RustSec, and the frontend lockfile is checked with npm audit. CI output is retained; these tools do not replace an independent security review.

The obsolete `get_if_addrs` dependency and its unmaintained `gcc` build dependency were removed. Interface addresses now use the existing sysinfo dependency, avoiding a second native interface-enumeration library.

## Informational RustSec warnings

The upstream desktop/credential stack retains informational advisories. They remain visible in CI; no advisory is hidden with `--ignore`.

| Advisory | Dependency | Review |
| --- | --- | --- |
| RUSTSEC-2024-0370 | proc-macro-error 1.0.4 | Maintenance warning in the upstream macro/GTK stack. |
| RUSTSEC-2026-0371 | zbus_names 3.0.0 and 4.3.5 | Maintenance warnings in the upstream D-Bus dependencies. |
| RUSTSEC-2026-0370 | zvariant 4.2.0 and 5.15.1 | Maintenance warnings in the upstream D-Bus dependencies. |
| RUSTSEC-2026-0372 | zvariant_derive 4.2.0 and 5.15.1 | Maintenance warnings in the upstream D-Bus macros. |
| [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429) | glib 0.18.5 | Informational unsoundness advisory affecting VariantStrIter. See the scoped code-path review below. |

## GLib code-path review

Tauri 2's Linux GTK3/WebKitGTK dependency graph selects glib 0.18.5. The upstream correction is in glib 0.20 or later, outside the compatible version range required by this GTK3 stack. Forcing that version is not a compatible lockfile update.

Aegis does not call GLib variant-string iteration. Searching the downloaded sources of the locked dependency graph for `VariantStrIter` and `array_iter_str` found references only in glib's own implementation, examples and tests; no Aegis or other dependency production call site was found. This reduces the identified exposure but is a source review, not a formal whole-program reachability proof. The dependency version and advisory remain reported by the audit.

The release does not claim zero dependency warnings or universal absence of vulnerabilities. Reassess these advisories when updating the GTK, Tauri, D-Bus or credential-storage stack. New security advisories can appear after the review date.
