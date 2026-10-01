from io import BytesIO

import numpy as np
from PIL import Image
import soundfile as sf

from deepfake_models import analyze_pretrained, model_status


def main():
    image_buffer = BytesIO()
    Image.new("RGB", (224, 224), "white").save(image_buffer, format="JPEG")
    audio_buffer = BytesIO()
    waveform = np.sin(2 * np.pi * 440 * np.arange(16_000) / 16_000).astype("float32")
    sf.write(audio_buffer, waveform, 16_000, format="WAV")

    for kind, content in (("image", image_buffer.getvalue()), ("audio", audio_buffer.getvalue())):
        result = analyze_pretrained(content, kind)
        if result is None:
            raise RuntimeError(f"{kind} detector did not load: {model_status()['load_errors']}")
        score = result.get("score")
        if not isinstance(score, (int, float)) or not 0 <= score <= 99:
            raise RuntimeError(f"{kind} detector returned an invalid score: {score!r}")
        print(f"PASS  {kind} model inference ({score}/99)")

    loaded = model_status()["loaded"]
    if set(loaded) != {"image", "audio"}:
        raise RuntimeError(f"Expected both models loaded, got {loaded}")


if __name__ == "__main__":
    main()