"""Generate Chrome registration from the same explicit IDs compiled into SafeAgent."""
import json
import re
import sys
from pathlib import Path

ids = sys.argv[1].split(",")
if not ids or len(set(ids)) != len(ids) or any(not re.fullmatch(r"[a-p]{32}", value) for value in ids):
    raise SystemExit("Supply unique, exact Chrome extension IDs")
binary = sys.argv[2]
if not Path(binary).is_absolute():
    raise SystemExit("Native messaging binary path must be absolute")
Path(sys.argv[3]).write_text(json.dumps({
    "name": "com.kalvium.safeagent",
    "description": "Kalvium SafeAgent (local observations, not attestation)",
    "path": binary,
    "type": "stdio",
    "allowed_origins": [f"chrome-extension://{value}/" for value in ids],
}, indent=2) + "\n", encoding="utf-8")
