"""Validate the entire pilot bundle before writing a catalog or creating GCS objects.

No cloud imports/credentials are needed for local validation. Publication is create-only;
an existing object stops the run (including retries after partial publication).
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

DEV_ID = "khafofcbffjkkeeldejiplkfpdfckeol"
VERSION = "0.2.0"
TARGETS = {
    "x86_64-pc-windows-msvc": ("windows", "x64", "exe"),
    "aarch64-apple-darwin": ("macos", "arm64", "pkg"),
    "x86_64-apple-darwin": ("macos", "x64", "pkg"),
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(data):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_pairs)


def validate(root, source, workflow, run_id, attempt, key_ring):
    for value in (source, workflow):
        require(re.fullmatch(r"[0-9a-f]{40}", value), "Expected full lowercase commit SHA")
    for value in (run_id, attempt):
        require(re.fullmatch(r"[1-9][0-9]*", value), "Invalid run identity")
    entries = key_ring.split(",")
    require(all(re.fullmatch(r"[A-Za-z0-9_-]+:[A-Za-z0-9_-]{43}", e) for e in entries),
            "Approved public key ring required; runtime parser must also validate it")
    key_ids = sorted(e.split(":", 1)[0] for e in entries)
    require(len(key_ids) == len(set(key_ids)), "Duplicate key IDs")
    expected_dirs = {f"safeagent-UNSIGNED-DEV-{source}-{t}" for t in TARGETS}
    require(root.is_dir() and not root.is_symlink(), "Invalid artifact root")
    require({p.name for p in root.iterdir()} == expected_dirs, "Require exactly all three artifacts")
    prefix = f"internal-dev/{VERSION}/{source}"
    packages = []
    uploads = []
    for target, (platform, arch, extension) in TARGETS.items():
        directory = root / f"safeagent-UNSIGNED-DEV-{source}-{target}"
        require(directory.is_dir() and not directory.is_symlink(), "Invalid artifact directory")
        filename = f"safeagent-{VERSION}-{platform}-{arch}-UNSIGNED-DEV.{extension}"
        names = {filename, "provenance.json", "SHA256SUMS"}
        require({p.name for p in directory.iterdir()} == names, "Unexpected or missing artifact files")
        files = {}
        for name in names:
            path = directory / name
            require(path.is_file() and not path.is_symlink(), "Artifact must be a regular file")
            files[name] = path.read_bytes()
        installer_hash = digest(files[filename])
        provenance_hash = digest(files["provenance.json"])
        require(files["SHA256SUMS"] == (
            f"{installer_hash}  {filename}\n{provenance_hash}  provenance.json\n"
        ).encode(), "Checksum mismatch or unexpected checksum entries")
        require(len(files[filename]) > 0, "Empty installer")
        expected = {
            "schemaVersion": 1,
            "channel": "internal-dev",
            "agentVersion": VERSION,
            "sourceCommit": source,
            "target": target,
            "extensionIds": [DEV_ID],
            "publicKeyIds": key_ids,
            "publicKeyRingSha256": digest(key_ring.encode()),
            "wireProtocolVersion": 2,
            "preflightGrantVersion": 3,
            "supportsPreflight": True,
            "developmentOnly": True,
            "signatureStatus": "unsigned",
            "notarized": False,
            "installer": filename,
            "installerSha256": installer_hash,
            "installerSize": len(files[filename]),
            "workflowCommit": workflow,
            "runId": run_id,
            "runAttempt": attempt,
        }
        record = strict_json(files["provenance.json"])
        # Exact fields/types prevent extra URLs, secrets or misleading metadata reaching GCS.
        require(record == expected and all(type(record[k]) is type(v) for k, v in expected.items()),
                f"Provenance mismatch for {target}")
        target_prefix = f"{prefix}/{target}"
        packages.append({
            "target": target,
            "platform": platform,
            "arch": arch,
            "filename": filename,
            "objectPath": f"{target_prefix}/{filename}",
            "sha256": installer_hash,
            "size": len(files[filename]),
            "provenanceObjectPath": f"{target_prefix}/provenance.json",
            "provenanceSha256": provenance_hash,
            "checksumsObjectPath": f"{target_prefix}/SHA256SUMS",
            "checksumsSha256": digest(files["SHA256SUMS"]),
        })
        for name in (filename, "provenance.json", "SHA256SUMS"):
            uploads.append((f"{target_prefix}/{name}", files[name]))
    catalog = {
        "schemaVersion": 1,
        "channel": "internal-dev",
        "agentVersion": VERSION,
        "sourceCommit": source,
        "workflowCommit": workflow,
        "runId": run_id,
        "runAttempt": attempt,
        "wireProtocolVersion": 2,
        "preflightGrantVersion": 3,
        "supportsPreflight": True,
        "developmentOnly": True,
        "signatureStatus": "unsigned",
        "notarized": False,
        "extensionId": DEV_ID,
        "publicKeyIds": key_ids,
        "publicKeyRingSha256": digest(key_ring.encode()),
        "packages": packages,
    }
    uploads.append((f"{prefix}/catalog.json", (json.dumps(catalog, indent=2) + "\n").encode()))
    return uploads


def publish(bucket, uploads):
    for name, data in uploads:
        content_type = "application/json" if name.endswith(".json") else (
            "text/plain" if name.endswith("SHA256SUMS") else "application/octet-stream"
        )
        blob = bucket.blob(name)
        blob.cache_control = "private, no-store"
        blob.upload_from_string(data, content_type=content_type, if_generation_match=0, retry=None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    import os
    uploads = validate(args.artifacts, os.environ["SOURCE_SHA"], os.environ["GITHUB_SHA"],
                       os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"],
                       os.environ["SAFEAGENT_AUTH_PUBLIC_KEYS"])
    args.catalog.write_bytes(uploads[-1][1])
    if args.publish:
        bucket = os.environ["SAFEAGENT_DEV_GCS_BUCKET"]
        require(re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,61}[a-z0-9]", bucket), "Invalid bucket name")
        from google.cloud import storage
        publish(storage.Client().bucket(bucket), uploads)


if __name__ == "__main__":
    main()
