"""Optional OCR extraction for uploaded images."""

from io import BytesIO
import shutil
from typing import Any

MAX_OCR_CHARACTERS = 20_000
OCR_TIMEOUT_SECONDS = 15


def extract_image_text(content: bytes) -> dict[str, Any]:
    if not shutil.which("tesseract"):
        return {"status": "unavailable", "reason": "Tesseract OCR executable is not installed."}
    try:
        import pytesseract
    except ImportError:
        return {"status": "unavailable", "reason": "The pytesseract Python package is not installed."}

    try:
        from PIL import Image

        with Image.open(BytesIO(content)) as image:
            text = pytesseract.image_to_string(image.convert("RGB"), timeout=OCR_TIMEOUT_SECONDS)
    except Exception:
        return {"status": "failed", "reason": "OCR could not decode or process this image."}

    normalized_text = (text or "").strip()[:MAX_OCR_CHARACTERS]
    return {
        "status": "text_detected" if normalized_text else "no_text_detected",
        "text": normalized_text,
        "character_count": len(normalized_text),
        "truncated": len(text or "") > MAX_OCR_CHARACTERS,
    }