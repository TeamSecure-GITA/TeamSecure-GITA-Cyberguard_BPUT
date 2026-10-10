"""Apply a locally supplied, Ed25519-signed YARA rules bundle."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import tempfile
import zipfile

from malware_scanner import RULES_PATH, _load_yara

MAX_BUNDLE_BYTES = 5_250_000
MAX_RULE_BYTES = 5_000_000
RULE_FILENAME = "cyberguard_malware.yar"
MANIFEST_FILENAME = "manifest.json"
SIGNED_FIELDS = ("schema_version", "version", "file", "sha256")


def _canonical_manifest(manifest: dict) -> bytes:
    signed = {field: manifest[field] for field in SIGNED_FIELDS}
    return json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")


def apply_signed_bundle(bundle_path: str | Path, public_key_path: str | Path, rules_path: str | Path = RULES_PATH) -> dict:
    """Verify, compile, then atomically replace the bundled rules file."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    bundle_path = Path(bundle_path)
    key_bytes = Path(public_key_path).read_bytes()
    public_key = serialization.load_pem_public_key(key_bytes)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("The trusted YARA update key must be Ed25519.")

    if bundle_path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("The signed YARA bundle exceeds the size limit.")
    with zipfile.ZipFile(bundle_path) as bundle:
        infos = bundle.infolist()
        names = [item.filename for item in infos]
        if len(names) != 2 or set(names) != {MANIFEST_FILENAME, RULE_FILENAME}:
            raise ValueError("The bundle must contain exactly manifest.json and cyberguard_malware.yar.")
        if any(item.file_size > MAX_RULE_BYTES for item in infos):
            raise ValueError("A signed YARA bundle member exceeds the size limit.")
        if next(item.file_size for item in infos if item.filename == MANIFEST_FILENAME) > 16_384:
            raise ValueError("The signed YARA manifest exceeds the size limit.")
        if bundle.testzip() is not None:
            raise ValueError("The signed YARA bundle failed its ZIP integrity check.")
        manifest = json.loads(bundle.read(MANIFEST_FILENAME))
        rule_bytes = bundle.read(RULE_FILENAME)

    if not isinstance(manifest, dict) or set(manifest) != {*SIGNED_FIELDS, "signature"}:
        raise ValueError("The signed YARA manifest has an unsupported schema.")
    if manifest["schema_version"] != 1 or manifest["file"] != RULE_FILENAME:
        raise ValueError("The signed YARA manifest has an unsupported schema or file name.")
    if not isinstance(manifest["version"], str) or not manifest["version"].strip() or len(manifest["version"]) > 80:
        raise ValueError("The signed YARA manifest version is invalid.")
    digest = hashlib.sha256(rule_bytes).hexdigest()
    if not isinstance(manifest["sha256"], str) or not hmac.compare_digest(digest, manifest["sha256"].lower()):
        raise ValueError("The YARA rules checksum does not match the signed manifest.")
    try:
        signature = base64.b64decode(manifest["signature"], validate=True)
        public_key.verify(signature, _canonical_manifest(manifest))
    except Exception as error:
        raise ValueError("The YARA rules signature is invalid.") from error

    source = rule_bytes.decode("utf-8")
    _load_yara().compile(source=source)

    destination = Path(rules_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile("wb", dir=destination.parent, prefix=f".{destination.name}.", delete=False) as stream:
            temp_path = Path(stream.name)
            stream.write(rule_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, destination)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()
    return {"status": "updated", "version": manifest["version"], "sha256": digest, "path": str(destination)}


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply an Ed25519-signed CyberGuard YARA rule bundle")
    parser.add_argument("bundle", help="ZIP containing a signed manifest.json and cyberguard_malware.yar")
    parser.add_argument("--public-key", default=os.getenv("CYBERGUARD_YARA_RULES_PUBLIC_KEY"), help="Trusted Ed25519 PEM public key path (or CYBERGUARD_YARA_RULES_PUBLIC_KEY)")
    args = parser.parse_args()
    if not args.public_key:
        parser.error("provide --public-key or set CYBERGUARD_YARA_RULES_PUBLIC_KEY")
    print(json.dumps(apply_signed_bundle(args.bundle, args.public_key), sort_keys=True))


if __name__ == "__main__":
    main()
