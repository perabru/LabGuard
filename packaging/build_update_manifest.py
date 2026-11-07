"""Build deterministic metadata for the two supported desktop update packages.

The release job hashes this file in SHA256SUMS.txt after generation. This is
integrity metadata for the same trusted GitHub publisher, not a signature.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

APP_ID = "br.perabru.labguard.desktop"
MANIFEST_NAME = "labguard-update.json"
MAX_ARTIFACT_SIZE = 150 * 1024 * 1024
ARTIFACTS = {"windows-x86_64": "LabGuard-Setup.exe", "linux-x86_64": "LabGuard-Linux-x86_64.tar.gz"}
VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\.(0|[1-9][0-9]{0,4})\Z")


class ManifestError(ValueError):
    pass


def validate_version(version):
    match = VERSION_RE.fullmatch(version) if isinstance(version, str) else None
    if not match or any(int(part) > 65535 for part in match.groups()):
        raise ManifestError("Use a stable numeric version such as 2.2.0.")
    return version


def _is_reparse(info):
    return bool(getattr(info, "st_file_attributes", 0) & 0x400)


def _directory(directory):
    root = Path(directory).absolute()
    for item in (root, *root.parents):
        try:
            info = item.lstat()
        except OSError:
            raise ManifestError("Release directory is unavailable.") from None
        if stat.S_ISLNK(info.st_mode) or _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ManifestError("Release directory must not contain links or reparse points.")
    return root


def _file_digest(path):
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode) or _is_reparse(before) or not stat.S_ISREG(before.st_mode):
            raise ManifestError("Update packages must be regular files without links.")
        if not 0 < before.st_size <= MAX_ARTIFACT_SIZE:
            raise ManifestError("Update package size is outside the supported limit.")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (before.st_dev, before.st_ino, before.st_size) != (opened.st_dev, opened.st_ino, opened.st_size):
                raise ManifestError("Update package changed while opening.")
            digest, total = hashlib.sha256(), 0
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_ARTIFACT_SIZE:
                    raise ManifestError("Update package exceeds the supported limit.")
                digest.update(block)
            after = os.fstat(stream.fileno())
        if total != before.st_size or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ManifestError("Update package changed while hashing.")
        return {"name": path.name, "sha256": digest.hexdigest(), "size": total}
    except ManifestError:
        raise
    except OSError:
        raise ManifestError("A required desktop update package is unavailable.") from None


def build_manifest(directory, version):
    version = validate_version(version)
    root = _directory(directory)
    artifacts = {platform: _file_digest(root / filename) for platform, filename in ARTIFACTS.items()}
    return {"schema": 1, "app_id": APP_ID, "version": version, "channel": "stable", "artifacts": artifacts}


def write_manifest(directory, version):
    manifest = build_manifest(directory, version)
    root = _directory(directory)
    destination = root / MANIFEST_NAME
    try:
        if destination.exists() or destination.is_symlink():
            current = destination.lstat()
            if stat.S_ISLNK(current.st_mode) or _is_reparse(current) or not stat.S_ISREG(current.st_mode):
                raise ManifestError("Manifest destination must be a regular file without links.")
        payload = (json.dumps(manifest, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("ascii")
        descriptor, temporary = tempfile.mkstemp(prefix=".labguard-update-", suffix=".tmp", dir=root)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
        finally:
            try:
                Path(temporary).unlink()
            except FileNotFoundError:
                pass
        return destination
    except ManifestError:
        raise
    except OSError:
        raise ManifestError("Update manifest could not be written.") from None


def main():
    parser = argparse.ArgumentParser(description="Build LabGuard desktop update metadata.")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        write_manifest(args.directory, args.version)
    except ManifestError as error:
        parser.exit(1, "Update manifest not generated: " + str(error) + "\n")
    print("Created labguard-update.json for stable version " + args.version + ".")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
