"""Download configured public model weights into a local cache.

This command requires the model licences to be reviewed before use. It does
not download or claim a model is production-calibrated.
"""
import argparse
import os
from pathlib import Path

MODELS = {
    "image": os.getenv("CYBERGUARD_IMAGE_MODEL", "dima806/deepfake_vs_real_image_detection"),
    "audio": os.getenv("CYBERGUARD_AUDIO_MODEL", "Hemgg/Deepfake-audio-detection"),
}


def download(output: Path):
    try:
        from huggingface_hub import snapshot_download
    except ImportError as error:
        raise SystemExit("Install requirements-ai.txt first: " + str(error))
    output.mkdir(parents=True, exist_ok=True)
    results = {}
    for kind, model_id in MODELS.items():
        results[kind] = snapshot_download(repo_id=model_id, local_dir=output / kind, local_dir_use_symlinks=False)
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "models" / "pretrained")
    args = parser.parse_args()
    print(download(args.output))
