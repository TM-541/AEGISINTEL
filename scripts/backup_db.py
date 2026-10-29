"""Create, list or verify AEGISINTEL database backups (terminal only).

Usage:
  .venv\\Scripts\\python.exe scripts\\backup_db.py            # create a verified backup
  .venv\\Scripts\\python.exe scripts\\backup_db.py --list     # list existing backups
  .venv\\Scripts\\python.exe scripts\\backup_db.py --verify PATH

Backups are written to <data dir>\\backups\\ with a .sha256 fingerprint file. Safe to run while
the application is running.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from threatlens.config import get_settings
from threatlens.maintenance import BackupError, backup_database, list_backups, verify_backup


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--list", action="store_true", help="list existing backups")
    group.add_argument("--verify", type=Path, metavar="PATH", help="verify a backup file")
    parser.add_argument("--label", default="manual", help="short label added to the filename")
    args = parser.parse_args()
    db_path = get_settings().db_path
    try:
        if args.list:
            backups = list_backups(db_path)
            print("\n".join(str(p) for p in backups) or "No backups found.")
            return 0
        info = (
            verify_backup(args.verify)
            if args.verify
            else backup_database(db_path, label=args.label)
        )
    except BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(f"{'Verified' if args.verify else 'Backup created'}: {info.path}")
    print(f"  size: {info.size_bytes:,} bytes · schema versions: {list(info.schema_versions)}")
    print(f"  sha256: {info.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
