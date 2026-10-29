"""Break-glass recovery for a locked-out AEGISINTEL administrator (terminal only).

Usage:
  .venv\\Scripts\\python.exe scripts\\recover_admin.py USERNAME

Resets the password of an existing administrator account, re-enables it, clears login
throttling for it and signs out all of its sessions. The new password is typed at a hidden
prompt, so it never appears on screen, in shell history or in logs. The action is audited.
Access to this command is equivalent to access to the database file itself.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from threatlens.config import get_settings
from threatlens.errors import ValidationFailedError
from threatlens.maintenance import BackupError, recover_admin


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("username")
    args = parser.parse_args()
    db_path = get_settings().db_path
    if not db_path.is_file():
        print("Error: database not found. Run scripts\\init_db.py first.", file=sys.stderr)
        return 1
    pw1 = getpass.getpass("New password (min 12 characters, hidden): ")
    pw2 = getpass.getpass("Repeat new password: ")
    if pw1 != pw2:
        print("Error: passwords do not match. Nothing was changed.", file=sys.stderr)
        return 1
    try:
        recover_admin(db_path, args.username, pw1)
    except (BackupError, ValidationFailedError) as exc:
        message = exc.public_message if isinstance(exc, ValidationFailedError) else str(exc)
        print(f"Error: {message} Nothing was changed.", file=sys.stderr)
        return 1
    print(f"Administrator '{args.username}' recovered. All their sessions were signed out.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
