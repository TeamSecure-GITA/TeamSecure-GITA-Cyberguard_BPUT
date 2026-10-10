import base64
import hashlib
import json
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import update_yara_rules


RULES = 'rule Update_Test { strings: $s = "signed test" condition: $s }\n'


def _make_bundle(tmp_path, *, tamper_signature=False):
    private_key = Ed25519PrivateKey.generate()
    public_key_path = tmp_path / "trusted-yara-key.pem"
    public_key_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    rule_bytes = RULES.encode()
    manifest = {
        "schema_version": 1,
        "version": "2026.10.10-test1",
        "file": update_yara_rules.RULE_FILENAME,
        "sha256": hashlib.sha256(rule_bytes).hexdigest(),
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(canonical)
    if tamper_signature:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    manifest["signature"] = base64.b64encode(signature).decode()
    bundle_path = tmp_path / "signed-rules.zip"
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(update_yara_rules.MANIFEST_FILENAME, json.dumps(manifest))
        bundle.writestr(update_yara_rules.RULE_FILENAME, rule_bytes)
    return bundle_path, public_key_path


def test_signed_yara_update_verifies_compiles_and_atomically_replaces(tmp_path, monkeypatch):
    class FakeYara:
        @staticmethod
        def compile(source):
            assert source == RULES
            return object()

    monkeypatch.setattr(update_yara_rules, "_load_yara", lambda: FakeYara())
    bundle_path, public_key_path = _make_bundle(tmp_path)
    active_rules = tmp_path / "active.yar"
    active_rules.write_text("old rules", encoding="utf-8")

    result = update_yara_rules.apply_signed_bundle(bundle_path, public_key_path, active_rules)

    assert result["status"] == "updated"
    assert result["version"] == "2026.10.10-test1"
    assert active_rules.read_text(encoding="utf-8") == RULES


def test_signed_yara_update_rejects_invalid_signature_without_replacing_rules(tmp_path, monkeypatch):
    class FakeYara:
        @staticmethod
        def compile(source):
            return object()

    monkeypatch.setattr(update_yara_rules, "_load_yara", lambda: FakeYara())
    bundle_path, public_key_path = _make_bundle(tmp_path, tamper_signature=True)
    active_rules = tmp_path / "active.yar"
    active_rules.write_text("trusted old rules", encoding="utf-8")

    with pytest.raises(ValueError, match="signature is invalid"):
        update_yara_rules.apply_signed_bundle(bundle_path, public_key_path, active_rules)

    assert active_rules.read_text(encoding="utf-8") == "trusted old rules"


def test_signed_yara_update_rejects_compile_failure_without_replacing_rules(tmp_path, monkeypatch):
    class FakeYara:
        @staticmethod
        def compile(source):
            raise RuntimeError("invalid YARA syntax")

    monkeypatch.setattr(update_yara_rules, "_load_yara", lambda: FakeYara())
    bundle_path, public_key_path = _make_bundle(tmp_path)
    active_rules = tmp_path / "active.yar"
    active_rules.write_text("trusted old rules", encoding="utf-8")

    with pytest.raises(RuntimeError, match="invalid YARA syntax"):
        update_yara_rules.apply_signed_bundle(bundle_path, public_key_path, active_rules)

    assert active_rules.read_text(encoding="utf-8") == "trusted old rules"
