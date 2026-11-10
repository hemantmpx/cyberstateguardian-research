from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from experiments.datasets.windows_apt_2025.audit import audit_archive


class WindowsAptArchiveAuditTests(unittest.TestCase):
    def test_manifest_file_hash_is_distinct_from_recorded_archive_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            archive_path = root / "fixture.zip"
            manifest_path = root / "manifest.json"
            combined = (
                b"_source.agent.id,_source.agent.name,_id,_index\n"
                b"001,fixture,evt-1,index-1\n"
            )
            publisher_checksums = (
                f"{hashlib.sha256(combined).hexdigest()}  combined.csv\n".encode()
            )
            members = {
                "dataset/combined.csv": combined,
                "dataset/checksums.sha256": publisher_checksums,
                "dataset/scenario_manifest.csv": b"scenario\nfixture\n",
                "dataset/validation_summary.csv": b"validation\nfixture\n",
            }
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, contents in members.items():
                    archive.writestr(name, contents)

            with zipfile.ZipFile(archive_path) as archive:
                infos = [info for info in archive.infolist() if not info.is_dir()]
                uncompressed_bytes = sum(info.file_size for info in infos)

            archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
            manifest = {
                "dataset": "fixture",
                "dataset_id": "fixture-id",
                "revision": 1,
                "source_url": "https://example.invalid/fixture",
                "downloaded_at": "2026-10-16",
                "sha256": archive_hash,
                "archive_file_count": len(infos),
                "uncompressed_bytes": uncompressed_bytes,
                "independent_state_scope": False,
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            result = audit_archive(archive_path, manifest_path)

            self.assertEqual(result["schema_version"], "csg-windows-apt-archive-audit-v2")
            self.assertEqual(result["status"], "PASS")
            acquisition = result["acquisition"]
            self.assertEqual(acquisition["archive_sha256"], archive_hash)
            self.assertEqual(acquisition["manifest_recorded_archive_sha256"], archive_hash)
            self.assertEqual(
                acquisition["manifest_sha256"],
                hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            )
            self.assertNotEqual(acquisition["manifest_sha256"], archive_hash)


if __name__ == "__main__":
    unittest.main()
