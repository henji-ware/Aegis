# Aegis 1.0.1

- Replaced small unlabeled graph targets with searchable application cards and readable socket buttons. Selecting an application focuses its observed destinations; click a destination to open native connection details. All observed applications remain available in scrollable lists, with arrow/Home/End keyboard navigation, visible focus, large click targets and usable controls when WebGL is unavailable. The network explorer now uses the panel width.

- Connection analysis now displays a dated result panel with counts, review reasons, coverage, filters, loading and error states. The completed snapshot stays visible when live monitoring refreshes. Switching between the snapshot and live sockets is explicit; unknown process access is shown as not verified.
- The report explicitly describes its scope: listening-port and executable-path signals. It does not query IP reputation or automatically scan executable contents. The selected executable can be scanned separately with ClamAV from its connection details.
- Files of 2 GiB or larger are excluded before launching ClamAV and reported as not scanned because of the engine's size limit. This avoids the known Windows fstat/file-status error. Size exclusions are separate from read errors and detections; the result remains partial, never a clean verdict for an unscanned file. Other configured engine limits can also restrict smaller files.
- An all-oversized selection produces an explicit partial result with zero files scanned, rather than a generic engine failure. Observed file errors are counted before the engine emits its final summary.
- Added multilingual UI regressions for preserved results after live updates, review/unknown/empty/failure states, and oversized-file notices, plus native sparse-file inventory regression coverage.

## Packages and trust

Windows x64 EXE/MSI and no-install ZIP; Linux x64 DEB/RPM/AppImage; macOS Apple silicon DMG/app archive. All release gates must pass before stable publication. Updater artifacts are version-bound and signed. Windows Authenticode and Apple Developer ID/notarization are still not supplied; updater signatures do not establish OS publisher trust.

Existing settings, profiles and history are retained. Close an older running instance before opening the new portable build. Keep the complete portable folder together. ClamAV scanning remains on demand or scheduled and requires current definitions; a lack of local connection signals or detections is not proof of safety.
