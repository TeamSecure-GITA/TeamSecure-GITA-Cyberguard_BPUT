from __future__ import annotations

import argparse

from operations import backup_database, restore_database


parser = argparse.ArgumentParser(description="CyberGuard SQLite backup and restore utility")
parser.add_argument("command", choices=("backup", "restore"))
parser.add_argument("path", help="Backup file path")
args = parser.parse_args()

result = backup_database(args.path) if args.command == "backup" else restore_database(args.path)
print(result)
