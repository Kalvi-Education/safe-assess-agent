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
| Self-built / unsigned tool | Script or packed executable | Unsigned and user-writable-path counts | 0.2.2, needs HIBu category |
| Automation runtime | Python/Node-driven screen reading and input injection | Runtime process catalog; signer match | 0.2.2 |
| Local AI model | Ollama, LM Studio | Catalog name + signer | 0.2.1 name; 0.2.2 signer where listed |
| Hidden overlay | Capture-excluded or non-activating topmost windows | Window affinity and extended styles | 0.2.1 |
| Synthetic input | Injected mouse/keyboard | Injected-input flag counting | Proposed; consent text needed |
| Screen capture by another app | DXGI / Graphics Capture | None reliable in user mode | Research |
| Hardware input emulation | USB HID device | None locally | Server-side behavioural signals only |
| Agent tampering | Patched or replaced SafeAgent | Signed results, self-reported hash, server build allowlist | 0.2.5 agent side; server verification pending |
| Fake page result | Page posts "ready" without SafeAgent | Server verifies agent signature | 0.2.5 agent side; server verification pending |
| Launch outside Chrome | Terminal or wrapper invokes the host | Parent check: signed Chrome required (`UNTRUSTED_PARENT`) | 0.2.5 |

## What a valid signature does and does not prove

- It proves the result came from the process holding that install's device key, unmodified in
  transit, bound to this preflight/session, challenge and connection.
- It does **not** prove the agent is untampered. `selfHash` and `parent` are self-reported by the
  same process; a patched agent can report the expected values and still sign.
- Non-exportable keys stop copying the key off the device. They do not stop another process
  running as the same user from asking the OS to sign with it.
- Unsigned macOS builds have no key at all: every macOS pilot result is unsigned.

## Residual risk

A patched agent on the student's own machine can still use that install's key to sign false
results. Remaining controls: periodic in-attempt checks, server-side consistency with Layer
1/2 signals, build allowlists, per-install revocation and human review. Findings are review
signals, never automatic penalties.
