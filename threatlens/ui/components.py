"""Reusable UI helpers. Any untrusted text placed into HTML is escaped here."""

from __future__ import annotations

import html
import io
import logging
import secrets
from collections.abc import Callable
from typing import Any, TypeVar

import pandas as pd
import streamlit as st

from threatlens.errors import SessionExpiredError, ThreatLensError
from threatlens.ui.theme import (
    CONFIDENCE_COLORS,
    DETECTION_COLORS,
    DETECTION_LABELS,
    DISPOSITION_COLORS,
    SEVERITY_COLORS,
    STATUS_COLORS,
)

log = logging.getLogger(__name__)
T = TypeVar("T")
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _luminance(hex_color: str) -> float:
    rgb = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def text_color_for(bg: str) -> str:
    """Navy or white, whichever gives the higher contrast on this background."""
    lum = _luminance(bg)
    navy, white = _luminance("#0B1220"), 1.0
    return "#0B1220" if (lum + 0.05) / (navy + 0.05) >= (white + 0.05) / (lum + 0.05) else "#FFFFFF"


def badge(
    value: str, palette: dict[str, str] | None = None, *, label: str | None = None, prefix: str = ""
) -> str:
    palette = palette or SEVERITY_COLORS
    color = palette.get(str(value).lower(), "#7D8BA1")
    text = html.escape((label or str(value)).replace("_", " "))
    pre = (
        f'<span style="opacity:.75;font-weight:600">{html.escape(prefix)}:</span> '
        if prefix
        else ""
    )
    return (
        f'<span class="tl-badge" style="background:{color};color:{text_color_for(color)}">'
        f"{pre}{text}</span>"
    )


def severity_badge(value: str, *, prefix: str = "") -> str:
    return badge(value, SEVERITY_COLORS, prefix=prefix)


def status_badge(value: str, *, prefix: str = "") -> str:
    return badge(value, STATUS_COLORS, prefix=prefix)


def confidence_badge(value: str) -> str:
    return badge(value, CONFIDENCE_COLORS, prefix="Confidence")


def detection_badge(value: str) -> str:
    return badge(value, DETECTION_COLORS, label=DETECTION_LABELS.get(value, value))


def disposition_badge(value: str) -> str:
    return badge(value, DISPOSITION_COLORS, prefix="Verdict")


def assessment_line(inc: dict[str, Any]) -> None:
    """The four independent assessment dimensions of an incident, each labelled."""
    html_line(
        severity_badge(inc["severity"], prefix="Severity"),
        confidence_badge(inc.get("confidence", "medium")),
        detection_badge(inc.get("detection_status", "known_detection")),
        disposition_badge(inc.get("disposition", "undetermined")),
        status_badge(inc["status"], prefix="Status"),
    )


def html_line(*parts: str) -> None:
    """Render pre-escaped HTML fragments (badges) separated by spaces."""
    st.markdown(" ".join(parts), unsafe_allow_html=True)


def esc(text: Any) -> str:
    return html.escape("" if text is None else str(text))


def metric_card(label: str, value: Any, help_text: str = "") -> None:
    st.markdown(
        f'<div class="tl-card" title="{esc(help_text)}"><div class="label">{esc(label)}</div>'
        f'<div class="value">{esc(value)}</div></div>',
        unsafe_allow_html=True,
    )


def safe_csv(df: pd.DataFrame) -> bytes:
    """CSV export with spreadsheet formula injection neutralised."""

    def neutralise(v: Any) -> Any:
        return "'" + v if isinstance(v, str) and v.startswith(FORMULA_PREFIXES) else v

    buf = io.StringIO()
    df.map(neutralise).to_csv(buf, index=False)
    return buf.getvalue().encode("utf-8")


def empty_state(title: str, hint: str) -> None:
    st.info(f"**{title}**  \n{hint}")


def guarded(fn: Callable[..., T], *args: Any, **kwargs: Any) -> T | None:
    """Run a service call; show safe messages; never leak stack traces to the browser."""
    try:
        return fn(*args, **kwargs)
    except SessionExpiredError as exc:
        st.session_state.pop("token", None)
        st.session_state["flash"] = exc.public_message
        st.rerun()
    except ThreatLensError as exc:
        st.error(exc.public_message)
    except Exception:
        ref = secrets.token_hex(4)
        log.exception("unhandled UI error", extra={"ref": ref})
        st.error(f"Something went wrong. Reference: {ref}. Details are in the server log.")
    return None


def require_incident() -> int | None:
    iid = st.session_state.get("incident_id")
    if iid is None:
        empty_state(
            "No incident selected",
            "Open the **Incident Queue** and choose an incident to investigate.",
        )
    return iid
