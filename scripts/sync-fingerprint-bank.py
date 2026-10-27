#!/usr/bin/env python3
"""Sync the immutable lm-detector fingerprint artifact and matching metadata.

Use --write to fetch the pinned upstream revision; --check needs no network.
Never take a moving branch HEAD when changing an isolation reference library.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "internal" / "fingerprint" / "data"
UPSTREAM_REPO = "Ikaleio/lm-detector"
UPSTREAM_COMMIT = "a4ef212df06817e8071acd05f00219f4c9eb2f9a"
DETECTOR_SHA256 = "9ac93e5e580f5bac887f97a20bfae15d0a3ad08c6372e4b3552fce6708078a80"
BANK_SHA256 = "7117831989ca8e1793cd954899ec5f614541a37ea65a4174b711f80e6036fb1b"
METADATA_SHA256 = "42a2856119bb663917afd9ac7c56c22b0db831cd06b873a17418df615b675dc5"
EXPECTED_MODEL_COUNT = 64
METADATA_FIELDS = ("id", "display_name", "family", "family_name", "response_count")


def verify_digest(contents: bytes, expected: str, label: str) -> None:
    actual = hashlib.sha256(contents).hexdigest()
    if actual != expected:
        raise ValueError(f"{label} SHA-256 mismatch: expected {expected}, got {actual}")


def decode_header(data: bytes) -> dict:
    if len(data) < 8:
        raise ValueError("upstream detector is too small")
    length = struct.unpack_from("<I", data)[0]
    if length < 5 or length + 4 > len(data):
        raise ValueError("invalid detector header length")
    return json.loads(data[4 : 4 + length])


def metadata_from_bank(bank_bytes: bytes, detector_bytes: bytes) -> bytes:
    bank = json.loads(bank_bytes)
    detector = decode_header(detector_bytes)
    models = bank["models"]
    assert detector["schema"] == "shared-detector-v2", "unexpected detector schema"
    assert detector["bank_built_at"] == bank["built_at"], "bank build time differs"
    assert detector["source_reference_sha256"] == bank["reference_sha256"], "different source reference"
    assert len(models) == len(detector["model_ids"]) == EXPECTED_MODEL_COUNT, "model count mismatch"
    assert detector["response_counts"]["n"] == EXPECTED_MODEL_COUNT, "response counts mismatch"
    assert all(model["id"] == detector["model_ids"][i] for i, model in enumerate(models)), "model order differs"
    metadata = {
        "schema": bank["schema"],
        "built_at": bank["built_at"],
        "source_reference_sha256": bank["reference_sha256"],
        "models": [{field: model[field] for field in METADATA_FIELDS} for model in models],
    }
    result = (json.dumps(metadata, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    verify_digest(result, METADATA_SHA256, "generated metadata")
    return result


def fetch(relative_path: str) -> bytes:
    url = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{UPSTREAM_COMMIT}/data/{relative_path}"
    with urlopen(Request(url, headers={"User-Agent": "magpie-codex-guard-fingerprint-sync"}), timeout=75) as response:
        return response.read()


def atomic_replace(path: Path, payload: bytes) -> None:
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as tmp:
            tmp.write(payload)
            tmp_name = tmp.name
        os.chmod(tmp_name, path.stat().st_mode & 0o777)
        os.replace(tmp_name, path)
    finally:
        if tmp_name is not None and os.path.exists(tmp_name):
            os.unlink(tmp_name)


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="verify pinned local files, no network")
    group.add_argument("--write", action="store_true", help="download pinned upstream files and replace locally")
    args = parser.parse_args()

    detector_path = DATA / "shared_detector.bin"
    metadata_path = DATA / "model_metadata.json"
    if args.write:
        binary = fetch("shared_detector.bin")
        bank = fetch("unified_bank.json")
        verify_digest(binary, DETECTOR_SHA256, "upstream detector")
        verify_digest(bank, BANK_SHA256, "upstream bank")
        meta = metadata_from_bank(bank, binary)
        atomic_replace(detector_path, binary)
        atomic_replace(metadata_path, meta)

    binary = detector_path.read_bytes()
    metadata = metadata_path.read_bytes()
    verify_digest(binary, DETECTOR_SHA256, "pinned local detector")
    verify_digest(metadata, METADATA_SHA256, "pinned local metadata")
    parsed = json.loads(metadata)
    header = decode_header(binary)
    assert parsed["built_at"] == header["bank_built_at"]
    assert len(parsed["models"]) == len(header["model_ids"]) == EXPECTED_MODEL_COUNT
    assert [m["id"] for m in parsed["models"]] == header["model_ids"]
    print(f"verified {UPSTREAM_REPO}@{UPSTREAM_COMMIT}: {EXPECTED_MODEL_COUNT} models; build {header['bank_built_at']}")


if __name__ == "__main__":
    main()
