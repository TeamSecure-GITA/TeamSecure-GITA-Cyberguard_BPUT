from __future__ import annotations

import logging
import os
import time

from dotenv import load_dotenv

from operations import backup_database
from provider_integrations import sync_cve_feed

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
logging.basicConfig(level=os.getenv("CYBERGUARD_LOG_LEVEL", "INFO"))
LOGGER = logging.getLogger("cyberguard.worker")


def run_once() -> dict[str, object]:
    result: dict[str, object] = {"cve_sync": sync_cve_feed()}
    if os.getenv("CYBERGUARD_BACKUP_PATH"):
        result["backup"] = backup_database()
    return result


def run_forever() -> None:
    interval = max(60, int(os.getenv("CYBERGUARD_WORKER_INTERVAL_SECONDS", "900")))
    while True:
        try:
            LOGGER.info("worker cycle: %s", run_once())
        except Exception:
            LOGGER.exception("worker cycle failed")
        time.sleep(interval)


if __name__ == "__main__":
    run_forever()
