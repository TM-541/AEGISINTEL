"""Registry of navigation pages so pages can link to each other via st.switch_page."""

from __future__ import annotations

from typing import Any

import streamlit as st

PAGES: dict[str, Any] = {}


def go(url_path: str) -> None:
    page = PAGES.get(url_path)
    if page is not None:
        st.switch_page(page)
