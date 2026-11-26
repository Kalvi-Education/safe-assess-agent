# SafeAgent threat model

Public document. No incident details, student data or tool-specific evasion notes belong
here; record incidents in the private Kalvium incident store and link only the technique
class below.

## Assumption

The student owns the device and may have administrator rights. Anything on the device
(binary, files, memory, local keys) can be read or modified. Security therefore comes from
the **server verifying signed, bound results**, not from hiding the local channel.

## Technique classes

| Class | Examples | SafeAgent signal | Status |
|---|---|---|---|
| Remote control | AnyDesk, TeamViewer, RDP | Process name/signer, remote session flags, installed services | 0.2.1 name; 0.2.2 signer, session, services |
| Renamed binary | Signed remote tool renamed to a benign name | Authenticode signer, version-info company/original filename | 0.2.2 (Windows); macOS Team ID planned |
| Self-built / unsigned tool | Script or packed executable | Unsigned and user-writable-path counts (build flag, default off) | 0.2.2, needs HIBu category |
| Automation runtime | Python/Node-driven screen reading and input injection | Runtime process catalog; signer match | 0.2.2 |
| Local AI model | Ollama, LM Studio | Catalog name + signer | 0.2.1 name; 0.2.2 signer where listed |
| Hidden overlay | Capture-excluded or non-activating topmost windows | Window affinity and extended styles | 0.2.1 |
| Synthetic input | Injected mouse/keyboard | Injected-input flag counting | Proposed; consent text needed |
| Screen capture by another app | DXGI / Graphics Capture | None reliable in user mode | Research |
| Hardware input emulation | USB HID device | None locally | Server-side behavioural signals only |
| Agent tampering | Patched or replaced SafeAgent | Signed results, build self-report, server build allowlist | Proposed (protocol-v3-proposal.md) |
| Fake page result | Page posts "ready" without SafeAgent | Server verifies agent signature | Proposed |
| Launch outside Chrome | Terminal invokes host with an approved origin | Parent-process signer in signed result | Proposed |

## Residual risk

A patched agent on the student's own machine can still use that install's key to sign false
results. Remaining controls: periodic in-attempt checks, server-side consistency with Layer
1/2 signals, build allowlists, per-install revocation and human review. Findings are review
signals, never automatic penalties.
