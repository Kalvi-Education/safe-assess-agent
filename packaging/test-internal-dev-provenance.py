import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("provenance", Path(__file__).with_name("internal-dev-provenance.py"))
provenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provenance)


class ProvenanceTests(unittest.TestCase):
    def test_target_records_and_hashes_without_key_values(self):
        for target, suffix in provenance.TARGETS.items():
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                old = os.getcwd()
                try:
                    os.chdir(directory)
                    Path("dist").mkdir()
                    artifact = Path("dist") / f"safeagent-0.2.0-{suffix}"
                    artifact.write_bytes(b"installer-test-placeholder")
                    env = {"SOURCE_SHA": "a" * 40, "TARGET": target,
                           "SAFEAGENT_AUTH_PUBLIC_KEYS": "approved-id:PUBLIC_VALUE",
                           "GITHUB_SHA": "b" * 40, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
                    metadata = json.dumps({"packages": [{"name": "safeagent", "version": "0.2.0"}]})
                    with patch.dict(os.environ, env), patch.object(provenance, "command", side_effect=["a" * 40, "", metadata]), patch.object(provenance.subprocess, "run") as run:
                        provenance.main()
                        self.assertIn("--internal-dev", run.call_args_list[1].args[0])
                    text = Path("dist/provenance.json").read_text()
                    record = json.loads(text)
                    self.assertNotIn("PUBLIC_VALUE", text)
                    self.assertEqual(record["signatureStatus"], "unsigned")
                    self.assertEqual(record["extensionIds"], [provenance.DEV_ID])
                    self.assertEqual(record["target"], target)
                    self.assertEqual(record["publicKeyIds"], ["approved-id"])
                    self.assertNotIn(b"\r", Path("dist/SHA256SUMS").read_bytes())
                    self.assertNotIn(b"\r", Path("dist/provenance.json").read_bytes())
                    for line in Path("dist/SHA256SUMS").read_text().splitlines():
                        digest, name = line.split("  ")
                        self.assertEqual(digest, hashlib.sha256((Path("dist") / name).read_bytes()).hexdigest())
                finally:
                    os.chdir(old)

    def test_pilot_rejects_other_versions(self):
        env = {"SOURCE_SHA": "a" * 40, "TARGET": "aarch64-apple-darwin"}
        metadata = json.dumps({"packages": [{"name": "safeagent", "version": "0.3.0"}]})
        with patch.dict(os.environ, env), patch.object(
            provenance, "command", side_effect=["a" * 40, "", metadata]
        ), patch.object(provenance.subprocess, "run"), self.assertRaises(ValueError):
            provenance.main()

    def test_ref_mismatch_and_dirty_source_fail(self):
        for sha, outputs in [("main", []), ("a" * 40, ["b" * 40]), ("a" * 40, ["a" * 40, " M Cargo.toml"])]:
            with self.subTest(sha=sha, outputs=outputs), patch.dict(os.environ, {"SOURCE_SHA": sha, "TARGET": "aarch64-apple-darwin"}), patch.object(provenance, "command", side_effect=outputs):
                with self.assertRaises(ValueError):
                    provenance.main()


if __name__ == "__main__":
    unittest.main()
