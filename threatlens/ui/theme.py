"""Visual theme: dark navy / slate, high-contrast text, restrained severity colours."""

from __future__ import annotations

import math
import random
from urllib.parse import quote

import streamlit as st

PALETTE = {
    "bg": "#0B1220",
    "panel": "#131C2E",
    "panel_2": "#1A2438",
    "border": "#2A3650",
    "text": "#E6EDF6",
    "muted": "#9AA8BD",
    "accent": "#38D6C4",  # matches the AEGISINTEL shield
    # Form fields: a recessed well darker than the panel, outlined at >= 3:1 (WCAG 1.4.11)
    # against both the panel and the well, so empty inputs are visible before focus.
    "field": "#0A1120",
    "field_border": "#5A6C8A",
    "field_border_hover": "#7487A6",
}
SEVERITY_COLORS = {
    "critical": "#E5484D",
    "high": "#F5A524",
    "medium": "#C9A227",
    "low": "#5B8DB8",
    "informational": "#7D8BA1",
}
CONFIDENCE_COLORS = {"high": "#3FA796", "medium": "#C9A227", "low": "#7D8BA1"}
DETECTION_COLORS = {
    "known_detection": "#4F8CC9",
    "anomalous_behavior": "#8A7CD8",
    "suspicious_unmatched": "#F5A524",
}
DISPOSITION_COLORS = {
    "undetermined": "#5E6B80",
    "true_positive": "#E5484D",
    "benign_confirmed": "#3FA796",
    "false_positive": "#3FA796",
    "inconclusive": "#C9A227",
    "insufficient_telemetry": "#C9A227",
}
DETECTION_LABELS = {
    "known_detection": "Known detection",
    "anomalous_behavior": "Anomalous behaviour",
    "suspicious_unmatched": "Suspicious - no rule match",
}
STATUS_COLORS = {
    "new": "#4F8CC9",
    "triage": "#8A7CD8",
    "investigating": "#F5A524",
    "contained": "#3FA796",
    "resolved": "#5E6B80",
    "false_positive": "#5E6B80",
    "pending": "#F5A524",
    "approved": "#3FA796",
    "rejected": "#5E6B80",
    "executed": "#4F8CC9",
    "failed": "#E5484D",
    "validated": "#3FA796",
    "fallback": "#F5A524",
}


def network_background_svg(width: int = 1600, height: int = 1000, nodes: int = 78) -> str:
    """Decorative node-network graphic (static, seeded, so it's identical on every load).

    Purely visual: it represents no data. Node density drops toward the centre so the
    content area stays calm and readable.
    """
    rng = random.Random(7)  # noqa: S311 # nosec B311 - decorative layout, not security
    cx, cy = width / 2, height / 2
    points: list[tuple[float, float]] = []
    while len(points) < nodes:
        x, y = rng.uniform(0, width), rng.uniform(0, height)
        # Distance from centre normalised to 0..1; keep few points near the middle.
        d = math.hypot((x - cx) / cx, (y - cy) / cy) / math.sqrt(2)
        if rng.random() < 0.15 + 0.85 * d:
            points.append((x, y))
    edges = []
    for i, (x1, y1) in enumerate(points):
        near = sorted(
            ((math.hypot(x1 - x2, y1 - y2), j) for j, (x2, y2) in enumerate(points) if j != i)
        )[:3]
        for dist, j in near:
            if dist < 210 and i < j:
                x2, y2 = points[j]
                edges.append(
                    f'<line x1="{x1:.0f}" y1="{y1:.0f}" x2="{x2:.0f}" y2="{y2:.0f}"'
                    f' stroke-opacity="{max(0.08, 0.32 - dist / 900):.2f}"/>'
                )
    dots = []
    for k, (x, y) in enumerate(points):
        if k % 9 == 0:  # occasional "hub" with a soft halo
            dots.append(
                f'<circle cx="{x:.0f}" cy="{y:.0f}" r="14" fill="#3FA796" fill-opacity=".07"/>'
                f'<circle cx="{x:.0f}" cy="{y:.0f}" r="3.2" fill="#5FC4B0" fill-opacity=".32"/>'
            )
        else:
            dots.append(
                f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{rng.uniform(1.4, 2.4):.1f}"'
                f' fill="#6FA8DC" fill-opacity=".34"/>'
            )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}"'
        f' preserveAspectRatio="xMidYMid slice">'
        f'<g stroke="#4F8CC9" stroke-width="1">{"".join(edges)}</g>{"".join(dots)}</svg>'
    )


_BG_URI = "data:image/svg+xml;utf8," + quote(network_background_svg())

CSS = f"""
<style>
  html, body, [class*="css"] {{ font-size: 16px; }}
  /* Layered backdrop: node network + two soft glows over the navy base. Decorative only. */
  .stApp {{
      background-color: {PALETTE["bg"]};
      background-image:
          url("{_BG_URI}"),
          radial-gradient(1100px 620px at 8% -6%, rgba(79,140,201,.20), transparent 62%),
          radial-gradient(900px 560px at 104% 108%, rgba(63,167,150,.16), transparent 60%),
          linear-gradient(180deg, #0B1220 0%, #0D1526 55%, #0A101C 100%);
      background-size: cover, auto, auto, auto;
      background-position: center, 0 0, 0 0, 0 0;
      background-attachment: fixed;
  }}
  header[data-testid="stHeader"] {{ background: transparent; }}
  /* Content surfaces stay near-opaque so text never sits directly on the pattern. */
  div[data-testid="stVerticalBlockBorderWrapper"] {{
      background: rgba(19,28,46,.88); border-radius: 10px; }}
  div[data-testid="stDataFrame"], div[data-testid="stExpander"], div[data-testid="stForm"],
  div[data-testid="stAlert"], div[data-testid="stCode"] {{
      background: rgba(19,28,46,.92); border-radius: 8px; }}
  .tl-card {{ backdrop-filter: blur(3px); }}
  section[data-testid="stSidebar"] {{
      background: linear-gradient(180deg, rgba(19,28,46,.97), rgba(13,21,38,.97));
      border-right: 1px solid {PALETTE["border"]}; }}
  h1, h2, h3 {{ letter-spacing: .2px; color: {PALETTE["text"]}; }}
  .tl-brand {{ font-weight: 800; font-size: 1.35rem; letter-spacing: 3px;
      color: {PALETTE["text"]}; text-shadow: 0 0 18px rgba(56,214,196,.35); }}
  .tl-tagline {{ color: {PALETTE["muted"]}; font-size: .85rem; margin-top: -4px; }}
  .tl-card {{ background: {PALETTE["panel"]}; border: 1px solid {PALETTE["border"]};
      border-radius: 10px; padding: 14px 16px; height: 100%; }}
  .tl-card .label {{ color: {PALETTE["muted"]}; font-size: .8rem; text-transform: uppercase;
      letter-spacing: .8px; }}
  .tl-card .value {{ color: {PALETTE["text"]}; font-size: 1.9rem; font-weight: 700; }}
  .tl-badge {{ display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: .78rem;
      font-weight: 700; letter-spacing: .4px; color: #0B1220; text-transform: uppercase; }}
  .tl-sim {{ border: 1px dashed #F5A524; color: #F5A524; padding: 2px 8px; border-radius: 6px;
      font-weight: 700; font-size: .78rem; }}
  .tl-ai {{ border: 1px solid #8A7CD8; color: #C7BFF5; padding: 2px 8px; border-radius: 6px;
      font-size: .78rem; font-weight: 600; }}
  .tl-muted {{ color: {PALETTE["muted"]}; }}
  div[data-testid="stMetricValue"] {{ font-size: 1.8rem; }}
  /* Form fields: visible outline at rest, brighter on hover, accent ring on focus. */
  div[data-baseweb="input"], div[data-baseweb="textarea"], div[data-baseweb="select"] > div,
  div[data-testid="stDateInputField"], div[data-testid="stNumberInputContainer"] {{
      background-color: {PALETTE["field"]} !important;
      border: 1px solid {PALETTE["field_border"]} !important;
      border-radius: 8px !important;
      transition: border-color .15s ease, box-shadow .15s ease; }}
  div[data-baseweb="input"]:hover, div[data-baseweb="textarea"]:hover,
  div[data-baseweb="select"] > div:hover {{
      border-color: {PALETTE["field_border_hover"]} !important; }}
  div[data-baseweb="input"]:focus-within, div[data-baseweb="textarea"]:focus-within,
  div[data-baseweb="select"] > div:focus-within {{
      border-color: {PALETTE["accent"]} !important;
      box-shadow: 0 0 0 3px rgba(56,214,196,.18) !important; }}
  div[data-baseweb="input"] > div, div[data-baseweb="base-input"],
  div[data-baseweb="input"] input, div[data-baseweb="textarea"] textarea,
  div[data-testid="stNumberInputContainer"] div[data-baseweb="input"] {{
      background-color: transparent !important; }}
  div[data-testid="stNumberInputContainer"] div[data-baseweb="input"] {{
      border: none !important; box-shadow: none !important; }}
  input::placeholder, textarea::placeholder {{ color: {PALETTE["muted"]} !important;
      opacity: 1; }}
  section[data-testid="stFileUploaderDropzone"] {{
      background-color: {PALETTE["field"]}; border: 1px dashed {PALETTE["field_border"]};
      border-radius: 8px; }}
</style>
"""


def apply_theme() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
