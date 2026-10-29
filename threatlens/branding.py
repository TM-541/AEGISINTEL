"""Product identity: the single source of truth for user-facing branding.

Internal identifiers (the ``threatlens`` package, ``THREATLENS_*`` environment variables and the
``threatlens.db`` filename) are deliberately unchanged, so existing installations, databases and
configuration keep working after the rebrand.
"""

from __future__ import annotations

from pathlib import Path

PRODUCT_NAME = "AEGISINTEL"
TAGLINE = "Evidence-first threat intelligence. Every verdict, provable."
ASSETS = Path(__file__).resolve().parent.parent / "assets"
LOGO_PATH = ASSETS / "aegisintel_logo.png"
ICON_PATH = ASSETS / "aegisintel_icon.png"
# Shield + name, shown at the top of the sidebar (st.logo accepts only an image there).
WORDMARK_PATH = ASSETS / "aegisintel_wordmark.png"
