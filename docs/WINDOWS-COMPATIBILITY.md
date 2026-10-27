# Windows application-control compatibility

## Confirmed observation

A previous unsigned `Aegis.exe` was blocked on the development computer.
Read-only CodeIntegrity investigation found:

- Event 3077: a block under `VerifiedAndReputableDesktop`.
- Correlated event 3089: `TotalSignatureCount = 0`.
- Smart App Control registry state 1, indicating enforcement.
- Authenticode status `NotSigned`.

The policy name identifies Smart App Control. A generic Device Guard error alone
does not prove the computer is managed by an organization. VBS, HVCI and
application control are distinct features.

Current Windows distributions remain unsigned. The interface changes and
multilingual diagnostics do not resolve a trust block before application startup.
No security policy was disabled and no trust certificate was installed.

## Read-only diagnostics

Aegis reads `VerifiedAndReputablePolicyState` and queries `Win32_DeviceGuard` for
VBS, running security services and user-mode code-integrity enforcement.
Denied or unavailable queries stay unknown. Configured VBS is distinguished from
running VBS; evaluation is distinguished from enforcement.

These queries request no elevation and change no policy. A positive observation
does not certify a particular executable or guarantee it will be allowed.

## Future distribution

Releases need verifiable provenance, a controlled build process and compatibility
testing under the intended policies. Trusted signing can help establish
provenance but is not a guarantee of acceptance by every policy. Signing keys
must never be placed in this repository.

## References

- [Microsoft: testing Smart App Control](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control)
- [Microsoft: application-control troubleshooting](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting)
- [Microsoft: VBS and memory integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
