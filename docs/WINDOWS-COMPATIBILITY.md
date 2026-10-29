# Windows compatibility

Aegis 1.0.0 uses Tauri 2, Rust and the system WebView2 runtime. Installer builds target Windows x64 with NSIS and WiX/MSI. A no-install ZIP contains the same executable and engines: extract the entire folder and open aegis-desktop.exe. The build machine needs Visual Studio C++ tools; end users do not need Rust or Node.js.

The distributed application currently has no trusted Authenticode publisher signature. Smart App Control, SmartScreen or another application-control policy may prevent execution. An installer extension or a self-signed certificate does not resolve publisher trust by itself. Do not disable device protections to run Aegis.

On the development device, earlier CodeIntegrity events 3077/3089 identified an unsigned Aegis executable blocked under VerifiedAndReputableDesktop, with Smart App Control enabled. This is evidence about that earlier executable/device state, not proof that every installation is organization-managed. The Rust migration does not automatically change those trust decisions.

Aegis reads Smart App Control registry state and Win32_DeviceGuard for VBS, running security services and user-mode code integrity. Unknown, unsupported or denied queries remain unknown. No Device Guard, Core Isolation, Smart App Control or code-integrity policy is changed by diagnostics.

The system credential vault protects VPN profiles. Owned Windows tunnel configurations are DPAPI-protected for WireGuard and use the required tunnel description. Firewall and tunnel activation require OS elevation after in-app confirmation. Existing native policy and application rules can affect the observed result.

Trusted Windows code signing requires an eligible publisher certificate/service or a separately reviewed distribution route. GitHub artifact attestations are useful supply-chain evidence but are not Authenticode signatures and do not remove application-control warnings.
