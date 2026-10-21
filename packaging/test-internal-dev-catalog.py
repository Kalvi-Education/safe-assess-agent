import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


catalog = load("internal-dev-catalog")
provenance = load("internal-dev-provenance")
SOURCE = "a" * 40
WORKFLOW = "b" * 40
# Fixture only: public-key crypto validation is separately tested by the Rust runtime parser.
RING = "test-only:" + "A" * 43


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "artifacts"
        self.root.mkdir()
        self.env = {
            "SOURCE_SHA": SOURCE, "GITHUB_SHA": WORKFLOW, "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1", "SAFEAGENT_AUTH_PUBLIC_KEYS": RING,
        }
        metadata = json.dumps({"packages": [{"name": "safeagent", "version": "0.2.0"}]})
        for target, suffix in provenance.TARGETS.items():
            folder = self.root / f"safeagent-UNSIGNED-DEV-{SOURCE}-{target}"
            folder.mkdir()
            dist = folder / "dist"
            dist.mkdir()
            (dist / f"safeagent-0.2.0-{suffix}").write_bytes(target.encode())
            previous = Path.cwd()
            try:
                os.chdir(folder)
                with patch.dict(os.environ, {**self.env, "TARGET": target}), patch.object(
                    provenance, "command", side_effect=[SOURCE, "", metadata]
                ), patch.object(provenance.subprocess, "run"):
                    provenance.main()
            finally:
                os.chdir(previous)
            for path in dist.iterdir():
                path.rename(folder / path.name)
            dist.rmdir()
        self.folder = next(self.root.iterdir())

    def validate(self, **overrides):
        values = dict(root=self.root, source=SOURCE, workflow=WORKFLOW,
                      run_id="123", attempt="1", key_ring=RING)
        return catalog.validate(**(values | overrides))

    def rewrite_provenance(self, mutate):
        path = self.folder / "provenance.json"
        record = json.loads(path.read_bytes())
        mutate(record)
        path.write_text(json.dumps(record) + "\n", encoding="utf-8")
        installer = self.folder / record["installer"]
        (self.folder / "SHA256SUMS").write_text(
            f"{catalog.digest(installer.read_bytes())}  {installer.name}\n"
            f"{catalog.digest(path.read_bytes())}  provenance.json\n", encoding="utf-8", newline="\n"
        )

    def test_complete_catalog_and_local_cli(self):
        uploads = self.validate()
        self.assertEqual(len(uploads), 10)
        name, data = uploads[-1]
        self.assertEqual(name, f"internal-dev/0.2.0/{SOURCE}/catalog.json")
        record = json.loads(data)
        self.assertEqual(record["extensionId"], catalog.DEV_ID)
        self.assertEqual(record["wireProtocolVersion"], 2)
        self.assertEqual(record["preflightGrantVersion"], 3)
        self.assertTrue(record["supportsPreflight"])
        self.assertTrue(record["developmentOnly"])
        self.assertEqual(record["signatureStatus"], "unsigned")
        self.assertEqual(len(record["packages"]), 3)
        self.assertNotIn(b"https://", data)
        self.assertNotIn(RING.encode(), data)
        for package in record["packages"]:
            payload = dict(uploads)[package["objectPath"]]
            self.assertEqual(package["size"], len(payload))
            self.assertEqual(package["sha256"], hashlib.sha256(payload).hexdigest())
        output = Path(self.temp.name) / "catalog.json"
        subprocess.run([sys.executable, "-B", catalog.__file__, "--artifacts", str(self.root),
                        "--catalog", str(output)], env=os.environ | self.env, check=True)
        self.assertEqual(output.read_bytes(), data)

    def test_invalid_bundle_stops_publish_cli_before_cloud_import(self):
        (self.root / "unexpected").mkdir()
        output = Path(self.temp.name) / "catalog.json"
        result = subprocess.run(
            [sys.executable, "-B", catalog.__file__, "--artifacts", str(self.root),
             "--catalog", str(output), "--publish"], env=os.environ | self.env,
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Require exactly all three artifacts", result.stderr)
        self.assertFalse(output.exists())

    def test_missing_target_or_extra_artifact_rejected(self):
        folder = next(self.root.iterdir())
        moved = Path(self.temp.name) / "moved"
        folder.rename(moved)
        with self.assertRaises(ValueError):
            self.validate()
        moved.rename(folder)
        (self.root / "extra").mkdir()
        with self.assertRaises(ValueError):
            self.validate()

    def test_extra_file_and_missing_checksum_rejected(self):
        extra = self.folder / "private-key.txt"
        extra.write_text("must never publish")
        with self.assertRaises(ValueError):
            self.validate()
        extra.unlink()
        (self.folder / "SHA256SUMS").unlink()
        with self.assertRaises(ValueError):
            self.validate()

    def test_modified_installer_and_checksums_rejected(self):
        installer = next(p for p in self.folder.iterdir() if p.suffix in (".pkg", ".exe"))
        original = installer.read_bytes()
        installer.write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            self.validate()
        installer.write_bytes(original)
        sums = self.folder / "SHA256SUMS"
        sums.write_bytes(sums.read_bytes() + b"extra checksum entry\n")
        with self.assertRaises(ValueError):
            self.validate()

    def test_metadata_mismatches_rejected_even_with_recomputed_checksums(self):
        original = {p.name: p.read_bytes() for p in self.folder.iterdir()}
        changes = {
            "sourceCommit": "c" * 40, "workflowCommit": "c" * 40,
            "runId": "124", "runAttempt": "2", "agentVersion": "0.3.0",
            "target": "unsupported", "extensionIds": ["a" * 32],
            "publicKeyIds": ["unapproved"], "publicKeyRingSha256": "c" * 64,
            "signatureStatus": "signed", "developmentOnly": False, "notarized": True,
            "wireProtocolVersion": 1, "preflightGrantVersion": 2, "supportsPreflight": False,
            "installerSize": 999, "installerSha256": "c" * 64, "schemaVersion": True,
            "signedUrl": "https://must-not-persist.invalid", "privateKey": "never",
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                for name, data in original.items():
                    (self.folder / name).write_bytes(data)
                self.rewrite_provenance(lambda record: record.update({key: value}))
                with self.assertRaises(ValueError):
                    self.validate()

    def test_expected_full_sha_and_approved_ring_required(self):
        for values in ({"source": "main"}, {"source": "a" * 7}, {"workflow": "b" * 7},
                       {"attempt": "2"}, {"key_ring": ""}, {"key_ring": RING + "," + RING},
                       {"key_ring": "other:" + "B" * 43}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.validate(**values)

    def test_symlink_rejected(self):
        if os.name == "nt":
            self.skipTest("Creating symlinks requires Windows developer privileges")
        installer = next(p for p in self.folder.iterdir() if p.suffix in (".pkg", ".exe"))
        real = Path(self.temp.name) / "real"
        installer.rename(real)
        installer.symlink_to(real)
        with self.assertRaises(ValueError):
            self.validate()

    def test_duplicate_json_fields_rejected(self):
        with self.assertRaises(ValueError):
            catalog.strict_json('{"sourceCommit":"a","sourceCommit":"b"}')

    def test_create_only_catalog_last_no_reads_or_acl(self):
        uploads = self.validate()
        bucket = Mock(spec=["blob"])
        blob = Mock(spec=["upload_from_string", "cache_control"])
        bucket.blob.return_value = blob
        catalog.publish(bucket, uploads)
        self.assertEqual([call.args[0] for call in bucket.blob.call_args_list],
                         [name for name, _ in uploads])
        for call in blob.upload_from_string.call_args_list:
            self.assertEqual(call.kwargs["if_generation_match"], 0)
            self.assertIsNone(call.kwargs["retry"])
        self.assertEqual(blob.cache_control, "private, no-store")

    def test_conflict_or_interruption_stops_before_catalog(self):
        uploads = self.validate()
        for failure_at in (0, 4, 8):
            with self.subTest(failure_at=failure_at):
                bucket = Mock(spec=["blob"])
                bucket.blob.return_value.upload_from_string.side_effect = (
                    [None] * failure_at + [RuntimeError("412 conflict or connection loss")]
                )
                with self.assertRaises(RuntimeError):
                    catalog.publish(bucket, uploads)
                self.assertEqual(bucket.blob.call_count, failure_at + 1)
                self.assertNotIn(uploads[-1][0], [c.args[0] for c in bucket.blob.call_args_list])


if __name__ == "__main__":
    unittest.main()
