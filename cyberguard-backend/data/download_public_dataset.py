"""Download and normalize the authorised UCI SMS Spam Collection."""
import argparse
import csv
import io
import zipfile
from pathlib import Path
from urllib.request import urlopen

SOURCE = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"


def download(output: Path) -> int:
    with urlopen(SOURCE, timeout=30) as response:
        archive = zipfile.ZipFile(io.BytesIO(response.read()))
    member = next(name for name in archive.namelist() if name.endswith("SMSSpamCollection"))
    rows = []
    for line in archive.read(member).decode("utf-8", errors="replace").splitlines():
        label, text = line.split("\t", 1)
        rows.append({"text": text.strip(), "label": "1" if label == "spam" else "0"})
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["text", "label"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download the UCI SMS Spam Collection")
    parser.add_argument("--output", type=Path, default=Path(__file__).with_name("uci_sms_spam.csv"))
    args = parser.parse_args()
    print(f"Downloaded {download(args.output)} rows to {args.output}")
