"""Initialise the AEGISINTEL database and issue a one-time administrator setup code.

Usage:  .venv\\Scripts\\python.exe scripts\\init_db.py

The setup code is printed once to this terminal (not to any log file). Only its SHA-256
hash is stored. It expires after 30 minutes and stops working once the first admin exists.
"""

from __future__ import annotations

import sys

from threatlens.errors import ThreatLensError
from threatlens.services.auth_service import SETUP_CODE_TTL_MINUTES
from threatlens.services.container import build_services


def main() -> int:
    services = build_services()
    print(f"Database ready at: {services.settings.db_path}")
    if not services.auth.setup_required():
        print("An administrator already exists. Initial setup is closed.")
        return 0
    try:
        code = services.auth.issue_setup_code()
    except ThreatLensError as exc:
        print(f"Could not issue setup code: {exc.public_message}", file=sys.stderr)
        return 1
    print(f"\nOne-time setup code (valid for {SETUP_CODE_TTL_MINUTES} minutes):\n")
    print(f"    {code}\n")
    print("Open the app, choose 'Initial setup' and enter this code to create the administrator.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
