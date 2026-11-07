"""Release metadata integrity checks; no network or installer is executed."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "packaging" / "build_update_manifest.py"
SPEC = importlib.util.spec_from_file_location("labguard_build_update_manifest", SOURCE)
manifest_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manifest_tool)


class UpdateManifestTests(unittest.TestCase):
    def packages(self, root):
        data = {"LabGuard-Setup.exe": b"trusted-windows-build", "LabGuard-Linux-x86_64.tar.gz": b"trusted-linux-build"}
        for name, value in data.items():
            (root / name).write_bytes(value)
        return data

    def test_hashes_and_sizes_describe_exact_packages_without_urls_or_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve();data = self.packages(root)
            result = manifest_tool.build_manifest(root, "2.2.0")
            self.assertEqual(result["app_id"], "br.perabru.labguard.desktop")
            self.assertEqual(result["schema"], 1)
            self.assertEqual(result["version"], "2.2.0")
            self.assertEqual(result["channel"], "stable")
            self.assertEqual(set(result["artifacts"]), {"windows-x86_64", "linux-x86_64"})
            for artifact in result["artifacts"].values():
                value = data[artifact["name"]]
                self.assertEqual(artifact["size"], len(value))
                self.assertEqual(artifact["sha256"], hashlib.sha256(value).hexdigest())
                self.assertEqual(set(artifact), {"name", "size", "sha256"})
            self.assertNotIn(str(root), json.dumps(result))

    def test_stable_version_rejects_prereleases_leading_zero_and_path_content(self):
        for version in ("v2.2.0", "02.2.0", "2.02.0", "2.2.00", "2.2", "2.2.0-beta", "2.2.0+build", "2.2.0/../", "65536.0.0", 22, None):
            with self.subTest(version=version), self.assertRaises(manifest_tool.ManifestError):
                manifest_tool.validate_version(version)
        for version in ("0.0.0", "2.2.0", "65535.65535.65535"):
            self.assertEqual(manifest_tool.validate_version(version), version)

    def test_missing_empty_or_oversized_package_prevents_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve();self.packages(root)
            installer = root / "LabGuard-Setup.exe"
            installer.unlink()
            with self.assertRaises(manifest_tool.ManifestError):manifest_tool.build_manifest(root, "2.2.0")
            installer.write_bytes(b"")
            with self.assertRaises(manifest_tool.ManifestError):manifest_tool.write_manifest(root, "2.2.0")
            installer.write_bytes(b"12345")
            with patch.object(manifest_tool, "MAX_ARTIFACT_SIZE", 4), self.assertRaises(manifest_tool.ManifestError):
                manifest_tool.build_manifest(root, "2.2.0")
            self.assertFalse((root / manifest_tool.MANIFEST_NAME).exists())

    def test_output_is_deterministic_and_replacing_manifest_does_not_change_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve();data = self.packages(root)
            result = manifest_tool.write_manifest(root, "2.2.0")
            first = result.read_bytes()
            self.assertEqual(result.name, "labguard-update.json")
            manifest_tool.write_manifest(root, "2.2.0")
            self.assertEqual(first, result.read_bytes())
            self.assertTrue(first.endswith(b"\n"))
            self.assertFalse(list(root.glob(".labguard-update-*.tmp")))
            for name, value in data.items():self.assertEqual((root/name).read_bytes(), value)

    def test_package_and_output_links_are_rejected_without_writing_the_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve();self.packages(root)
            target = root / "outside.txt";target.write_bytes(b"keep")
            try:
                (root / manifest_tool.MANIFEST_NAME).symlink_to(target)
            except OSError:
                self.skipTest("Creating symbolic links is unavailable for this account.")
            with self.assertRaises(manifest_tool.ManifestError):manifest_tool.write_manifest(root, "2.2.0")
            self.assertEqual(target.read_bytes(), b"keep")
            (root / manifest_tool.MANIFEST_NAME).unlink()
            (root / "LabGuard-Setup.exe").unlink()
            (root / "LabGuard-Setup.exe").symlink_to(target)
            with self.assertRaises(manifest_tool.ManifestError):manifest_tool.build_manifest(root, "2.2.0")


if __name__ == "__main__":
    unittest.main()
