"""Restore the AEGISINTEL database from a verified backup (terminal only).

Usage:
  .venv\\Scripts\\python.exe scripts\\restore_db.py PATH_TO_BACKUP.db

STOP THE APPLICATION FIRST (Ctrl+C in its terminal). The current database is saved as a
"pre-restore" backup before it is replaced, so this operation can be undone. You will be asked
to type RESTORE to confirm.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from threatlens.config import get_settings
from threatlens.maintenance import BackupError, restore_database, verify_backup


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("backup", type=Path)
    parser.add_argument("--yes", action="store_true", help="skip the interactive confirmation")
    args = parser.parse_args()
    db_path = get_settings().db_path
    try:
        info = verify_backup(args.backup)
    except BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(
        f"Backup OK: {info.path.name} (schema {list(info.schema_versions)}, "
        f"sha256 {info.sha256[:16]}…)"
    )
    print(f"This will REPLACE: {db_path}")
    if not args.yes and input("Make sure the app is stopped, then type RESTORE: ") != "RESTORE":
        print("Cancelled. Nothing was changed.")
        return 1
    try:
        _, safety = restore_database(args.backup, db_path)
    except BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if safety:
        print(f"Previous database saved as: {safety.path}")
    print("Restore complete. Start the app again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
