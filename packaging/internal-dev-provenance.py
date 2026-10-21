"""Actions-only distribution manifest; never an approval or signed attestation."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

DEV_ID = "khafofcbffjkkeeldejiplkfpdfckeol"
TARGETS = {
    "x86_64-pc-windows-msvc": "windows-x64-UNSIGNED-DEV.exe",
    "aarch64-apple-darwin": "macos-arm64-UNSIGNED-DEV.pkg",
    "x86_64-apple-darwin": "macos-x64-UNSIGNED-DEV.pkg",
}


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def main():
    sha = os.environ["SOURCE_SHA"]
    target = os.environ["TARGET"]
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or command("git", "rev-parse", "HEAD") != sha:
        raise ValueError("Source must match the full immutable SHA")
    if command("git", "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Source tree must remain clean")
    subprocess.run(["git", "merge-base", "--is-ancestor", sha, "refs/remotes/origin/main"], check=True)
    subprocess.run(["cargo", "run", "--locked", "--example", "validate-auth-config", "--", "--internal-dev"], check=True)
    metadata = json.loads(command("cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"))
    version = next(p["version"] for p in metadata["packages"] if p["name"] == "safeagent")
    if version != "0.2.0":
        raise ValueError("Internal Dev pilot requires agent version 0.2.0")
    dist = Path("dist")
    installer = dist / f"safeagent-{version}-{TARGETS[target]}"
    if not installer.is_file():
        raise ValueError("Expected unsigned installer missing")
    installers = list(dist.glob("*.exe")) + list(dist.glob("*.pkg"))
    if installers != [installer]:
        raise ValueError("Unexpected installers in distribution directory")
    digest = hashlib.sha256(installer.read_bytes()).hexdigest()
    provenance = {
        "schemaVersion": 1,
        "channel": "internal-dev",
        "agentVersion": version,
        "sourceCommit": sha,
        "target": target,
        "extensionIds": [DEV_ID],
        "publicKeyIds": sorted(entry.split(":", 1)[0] for entry in os.environ["SAFEAGENT_AUTH_PUBLIC_KEYS"].split(",")),
        "publicKeyRingSha256": hashlib.sha256(os.environ["SAFEAGENT_AUTH_PUBLIC_KEYS"].encode()).hexdigest(),
        "wireProtocolVersion": 2,
        "preflightGrantVersion": 3,
        "supportsPreflight": True,
        "developmentOnly": True,
        "signatureStatus": "unsigned",
        "notarized": False,
        "installer": installer.name,
        "installerSha256": digest,
        "installerSize": installer.stat().st_size,
        "workflowCommit": os.environ["GITHUB_SHA"],
        "runId": os.environ["GITHUB_RUN_ID"],
        "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
    }
    manifest = dist / "provenance.json"
    manifest.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8", newline="\n")
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    (dist / "SHA256SUMS").write_text(
        f"{digest}  {installer.name}\n{manifest_digest}  {manifest.name}\n", encoding="utf-8", newline="\n"
    )


if __name__ == "__main__":
    main()
