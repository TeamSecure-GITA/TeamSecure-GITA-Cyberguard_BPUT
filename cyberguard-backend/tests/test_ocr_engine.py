import asyncio
from io import BytesIO
import sys
from types import SimpleNamespace

from PIL import Image
from fastapi import UploadFile

import main
import ocr_engine


def image_bytes():
    output = BytesIO()
    Image.new("RGB", (16, 16), "white").save(output, format="PNG")
    return output.getvalue()


def test_ocr_extracts_text_when_tesseract_is_available(monkeypatch):
    monkeypatch.setattr(ocr_engine.shutil, "which", lambda _: "tesseract")
    monkeypatch.setitem(sys.modules, "pytesseract", SimpleNamespace(image_to_string=lambda image, timeout: "Verify your account"))

    result = ocr_engine.extract_image_text(image_bytes())

    assert result["status"] == "text_detected"
    assert result["character_count"] == len("Verify your account")
    assert "text" in result


def test_ocr_reports_missing_tesseract_without_failing(monkeypatch):
    monkeypatch.setattr(ocr_engine.shutil, "which", lambda _: None)

    result = ocr_engine.extract_image_text(image_bytes())

    assert result["status"] == "unavailable"
    assert "Tesseract" in result["reason"]


def test_image_upload_scores_ocr_text_without_returning_raw_text(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "ocr-upload.db")
    monkeypatch.setattr(main, "extract_image_text", lambda content: {
        "status": "text_detected",
        "text": "Urgent: verify your password at https://credential-reset.example immediately",
        "character_count": 75,
        "truncated": False,
    })
    monkeypatch.setattr(main, "analyze_media", lambda *args: {"score": 5, "indicators": [], "reasons": [], "method": "image-test"})
    main.initialize_database()

    result = asyncio.run(main.analyze_file(
        category="image",
        file=UploadFile(file=BytesIO(b"image bytes"), filename="notice.png", headers={"content-type": "image/png"}),
        metadata="{}",
        user={"username": "analyst", "role": "analyst"},
    ))

    ocr_result = result["assessment"]["ocr_analysis"]
    assert ocr_result["status"] == "text_detected"
    assert ocr_result["risk_score"] > 0
    assert any(indicator["name"].startswith("OCR:") for indicator in result["assessment"]["indicators"])
    assert "verify your password" not in str(result)


def test_uploaded_login_screenshot_detects_visible_brand_domain_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "login-screenshot.db")
    monkeypatch.setattr(main, "extract_image_text", lambda content: {
        "status": "text_detected",
        "text": "Microsoft sign in. Enter your password at https://microsoft-login.example",
        "character_count": 74,
        "truncated": False,
    })
    monkeypatch.setattr(main, "analyze_media", lambda *args: {"score": 5, "indicators": [], "reasons": [], "method": "image-test"})
    main.initialize_database()

    result = asyncio.run(main.analyze_file(
        category="image",
        file=UploadFile(file=BytesIO(b"image bytes"), filename="login.png", headers={"content-type": "image/png"}),
        metadata="{}",
        user={"username": "analyst", "role": "analyst"},
    ))

    assessment = result["assessment"]
    assert assessment["ocr_analysis"]["brand_domain_mismatches"] == [{
        "brand": "microsoft",
        "observed_domain": "microsoft-login.example",
        "expected_domain": "microsoft.com",
    }]
    assert any(item["name"] == "OCR Login Brand-Domain Mismatch" for item in assessment["indicators"])
    assert "Microsoft" not in str(assessment["ocr_analysis"])