"""Download configured public model weights into a local cache.

This command requires the model licences to be reviewed before use. It does
not download or claim a model is production-calibrated.
"""
import argparse
import hashlib
import json
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
        model_dir = output / kind
        results[kind] = snapshot_download(repo_id=model_id, local_dir=model_dir, local_dir_use_symlinks=False)
        weight_files = [path for path in model_dir.rglob("*") if path.is_file() and path.suffix in {".bin", ".safetensors", ".pt", ".pth"}]
        if not weight_files or max(path.stat().st_size for path in weight_files) < 1_000_000:
            raise RuntimeError(f"{kind} model download did not contain a usable weight artifact")
        manifest = {
            "model_id": model_id,
            "kind": kind,
            "files": [
                {"path": str(path.relative_to(model_dir)), "bytes": path.stat().st_size, "sha256": _sha256(path)}
                for path in sorted(model_dir.rglob("*")) if path.is_file() and not path.name.endswith(".metadata")
            ],
        }
        (model_dir / "cyberguard-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return results


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "models" / "pretrained")
    args = parser.parse_args()
    print(download(args.output))
