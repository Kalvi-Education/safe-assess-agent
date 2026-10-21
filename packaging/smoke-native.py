"""Exercise the actual binary without installing or printing local findings."""
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import sys
import uuid


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def frame(value):
    payload = json.dumps(value).encode("utf-8")
    return struct.pack("=I", len(payload)) + payload


def decode_frames(data):
    replies = []
    while data:
        require(len(data) >= 4, "Truncated response header")
        size = struct.unpack("=I", data[:4])[0]
        require(0 < size <= 1048576, "Invalid response size")
        require(len(data) >= size + 4, "Truncated response payload")
        replies.append(json.loads(data[4:4 + size]))
        data = data[4 + size:]
    return replies


def main():
    binary = Path(sys.argv[1]).resolve()
    if os.name == "nt" and binary.suffix != ".exe":
        binary = binary.with_suffix(".exe")
    ids = os.environ.get("SAFEAGENT_ALLOWED_EXTENSION_IDS", "").split(",")
    require(all(re.fullmatch(r"[a-p]{32}", value) for value in ids), "Explicit extension IDs required")
    version = subprocess.run([str(binary), "--version"], capture_output=True, check=True, timeout=10).stdout.decode().strip().split()[-1]
    requests = [dict(protocolVersion=2, requestId=str(uuid.uuid4()), command=command,
                     challenge=secrets.token_hex(16)) for command in ("hello", "check")]
    for launch in ([f"chrome-extension://{ids[0]}/"], ["messaging", f"chrome-extension://{ids[0]}/"]):
        result = subprocess.run([str(binary), *launch], input=b"".join(map(frame, requests)), capture_output=True, timeout=30)
        require(result.returncode == 0, "Native messaging exited unsuccessfully")
        replies = decode_frames(result.stdout)
        require(len(replies) == 2, "Expected hello and check replies")
        for request, reply in zip(requests, replies):
            for field in ("protocolVersion", "requestId", "challenge"):
                require(reply.get(field) == request[field], f"Mismatched {field}")
            require(reply.get("agentVersion") == version, "Version mismatch")
            require(type(reply.get("ok")) is bool, "Invalid ok field")
            require(type(reply.get("observedAt")) is int and reply["observedAt"] > 0, "Invalid observation timestamp")
            require(isinstance(reply.get("findings"), list), "Invalid findings")
            capabilities = reply.get("capabilities", {})
            require(set(capabilities) == {"processes", "displays", "overlays"}, "Invalid capability set")
            for capability in capabilities.values():
                require(capability.get("status") in {"available", "unsupported", "error", "notChecked"}, "Invalid capability status")
                require(isinstance(capability.get("limitation"), str) and capability["limitation"], "Missing capability limitation")
            if request["command"] == "hello":
                require(reply["ok"] and not reply["findings"], "Hello must not scan")
                require(reply.get("preflightSupport") == {"contractVersion": 1, "grantVersion": 3},
                        "Expected signed v3 preflight support on wire v2")
                expected = "ready" if os.environ.get("SAFEAGENT_AUTH_PUBLIC_KEYS") else "AUTH_CONFIG_INVALID"
                require(reply.get("authReadiness") == expected, "Unexpected embedded authorization readiness")
            else:
                require(not reply["ok"] and reply.get("error", {}).get("code") == "UNAUTHORIZED", "Unauthenticated check accepted")
                require(not reply["findings"], "Unauthenticated findings returned")
                require(all(value["status"] in {"notChecked", "unsupported"} for value in capabilities.values()), "Unauthenticated probe ran")
    diagnostic = subprocess.run([str(binary), "check"], capture_output=True, timeout=10)
    require(diagnostic.returncode != 0, "CLI check bypassed authorization")
    require(json.loads(diagnostic.stdout).get("error", {}).get("code") == "UNAUTHORIZED", "CLI must be metadata-only")
    denied = next(char * 32 for char in "abcdefghijklmnop" if char * 32 not in ids)
    for launch in ([f"chrome-extension://{denied}/"], ["messaging"], ["messaging", f"chrome-extension://{denied}/"]):
        result = subprocess.run([str(binary), *launch], input=frame(requests[0]), capture_output=True, timeout=10)
        require(result.returncode != 0, "Unauthorized messaging origin accepted")
        require(not result.stdout, "Denied origin emitted protocol output")
    print("Native launch, framed hello/check, correlation and origin rejection passed; no findings logged.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        # Never dump stdout/stderr or local observations in CI failures.
        print(f"Native smoke failed: {type(error).__name__}", file=sys.stderr)
        sys.exit(1)
