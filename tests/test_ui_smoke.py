"""Headless UI smoke tests using Streamlit's AppTest.

Every page is rendered against a seeded database. Pages must raise no exceptions and show
no error banners for an administrator. Admin-only pages must be refused by the *backend*
for a viewer even when the page itself is reached.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from tests.conftest import ADMIN_PW
from tests.test_investigation import seed
from threatlens.models.domain import Role

APP = str(Path(__file__).resolve().parent.parent / "app.py")
PAGES = [
    "overview",
    "events",
    "incidents",
    "workspace",
    "timeline",
    "ai_report",
    "rules",
    "responses",
    "audit",
    "users",
    "health",
]


def page_script(module: str, data_dir: str, token: str, incident_id: int) -> None:
    import importlib

    import httpx
    import streamlit as st

    from threatlens.config import Settings
    from threatlens.integrations.ollama import OllamaClient
    from threatlens.services.container import build_services

    def offline(request):
        raise httpx.ConnectError("offline in tests")

    settings = Settings(
        data_dir=data_dir, enable_vector_search=False, log_level="ERROR", _env_file=None
    )
    client = OllamaClient(settings.ollama_host, timeout=1, transport=httpx.MockTransport(offline))
    services = build_services(settings, ollama_client=client)
    st.session_state["incident_id"] = incident_id
    importlib.import_module(f"threatlens.ui.pages.{module}").render(services, token)


@pytest.fixture()
def seeded(services, settings):
    token, iid, _, _ = seed(services)
    services.users.create_user(
        token, username="viewer1", password="Viewer-Strong-Pass-77", role=Role.VIEWER
    )
    viewer = services.auth.login("viewer1", "Viewer-Strong-Pass-77")
    return {"data_dir": str(settings.data_dir), "admin": token, "viewer": viewer, "iid": iid}


def run_page(module, seeded, token):
    at = AppTest.from_function(
        page_script, args=(module, seeded["data_dir"], token, seeded["iid"]), default_timeout=60
    )
    return at.run()


@pytest.mark.parametrize("module", PAGES)
def test_every_page_renders_for_admin(seeded, module):
    at = run_page(module, seeded, seeded["admin"])
    assert not at.exception, [e.value for e in at.exception]
    assert not at.error, [e.value for e in at.error]


@pytest.mark.parametrize("module", ["audit", "users"])
def test_admin_pages_refused_by_backend_for_viewer(seeded, module):
    at = run_page(module, seeded, seeded["viewer"])
    assert not at.exception
    assert any("do not have permission" in e.value for e in at.error)


def test_overview_numbers_come_from_database(seeded, services):
    at = run_page("overview", seeded, seeded["admin"])
    stats = services.incidents.dashboard_stats(seeded["admin"])
    html = " ".join(m.body for m in at.markdown)
    assert f">{stats['incidents_open']}<" in html
    assert f">{stats['events']:,}<" in html


def test_full_app_setup_then_login(settings, monkeypatch):
    monkeypatch.setenv("THREATLENS_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("THREATLENS_ENABLE_VECTOR_SEARCH", "false")
    from threatlens.config import get_settings
    from threatlens.services.container import build_services

    get_settings.cache_clear()
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()
    assert [s.value for s in at.subheader] == ["Initial administrator setup"]
    services = build_services(get_settings())
    code = services.auth.issue_setup_code()
    services.auth.create_initial_admin(setup_code=code, username="admin", password=ADMIN_PW)
    at.run()
    assert [s.value for s in at.subheader] == ["Sign in"]
    at.text_input[0].input("admin")
    at.text_input[1].input("wrong-password-123")
    at.button[0].click()
    at.run()
    assert any("Invalid username or password" in e.value for e in at.error)
    at.text_input[0].input("admin")
    at.text_input[1].input(ADMIN_PW)
    at.button[0].click()
    at.run()
    assert not at.exception
    assert [t.value for t in at.title] == ["Security Operations Overview"]
    get_settings.cache_clear()


# --- decorative background must not hurt readability -------------------------------------


def _lum(hex_color: str) -> float:
    rgb = [int(hex_color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def _blend(fg: str, bg: str, alpha: float) -> str:
    f = [int(fg[i : i + 2], 16) for i in (1, 3, 5)]
    b = [int(bg[i : i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(
        f"{round(alpha * x + (1 - alpha) * y):02x}" for x, y in zip(f, b, strict=True)
    )


def test_background_is_static_valid_svg_and_text_stays_readable():
    import xml.etree.ElementTree as ET

    from threatlens.ui.theme import PALETTE, network_background_svg

    svg = network_background_svg()
    assert svg == network_background_svg()  # deterministic, no fake "live" data
    root = ET.fromstring(svg)  # noqa: S314 - our own generated markup
    assert "animate" not in svg and root.tag.endswith("svg")
    # Worst case: brightest hub node over the strongest glow, behind body text.
    base = _blend("#4F8CC9", PALETTE["bg"], 0.20)
    for color, alpha in (("#5FC4B0", 0.32), ("#6FA8DC", 0.34)):  # must match theme.py
        assert f'fill="{color}" fill-opacity="{str(alpha)[1:]}"' in svg
        worst = _blend(color, base, alpha)
        l1, l2 = _lum(PALETTE["text"]), _lum(worst)
        contrast = (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)
        assert contrast >= 4.5, (color, contrast)  # WCAG AA even at the brightest pixel


def test_form_fields_are_visible_before_focus():
    from threatlens.ui.theme import CSS, PALETTE

    def ratio(a, b):
        l1, l2 = _lum(a), _lum(b)
        return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)

    # WCAG 1.4.11: a field's boundary needs 3:1 against what surrounds it and its own fill.
    for surround in (PALETTE["panel"], PALETTE["field"]):
        assert ratio(PALETTE["field_border"], surround) >= 3.0, surround
    assert ratio(PALETTE["text"], PALETTE["field"]) >= 4.5  # typed text
    assert ratio(PALETTE["muted"], PALETTE["field"]) >= 4.5  # placeholders
    assert PALETTE["field"] != PALETTE["panel"]  # the well differs from the card
    for selector in ('div[data-testid="stTextInputRootElement"]', ":focus-within"):
        assert selector in CSS


def test_field_selectors_exist_in_installed_streamlit_frontend():
    """Regression: v1.0.0 styled BaseWeb selectors that Streamlit 1.66 no longer renders, so
    fields stayed invisible while the colour test passed. Every field test id the theme targets
    must exist in the installed frontend bundle, so a Streamlit upgrade that renames them fails here.
    """
    import re

    import streamlit

    from threatlens.ui.theme import CSS

    bundle = "".join(
        p.read_text(encoding="utf-8", errors="ignore")
        for p in (Path(streamlit.__file__).parent / "static").rglob("*.js")
    )
    targeted = set(re.findall(r'data-testid="(st\w+)"', CSS))
    fields = {t for t in targeted if any(k in t for k in ("Input", "TextArea", "Select", "Date"))}
    assert {"stTextInputRootElement", "stTextAreaRootElement", "stSelectbox"} <= fields
    missing = sorted(t for t in fields if t not in bundle)
    assert not missing, f"theme targets test ids this Streamlit does not render: {missing}"


# --- phase 2: every incident type and populated report/approval states render cleanly ------


def _incident_ids(services, token):
    return {i["detection_status"]: i["id"] for i in services.incidents.list_incidents(token)}


def run_page_for(module, seeded, token, incident_id):
    at = AppTest.from_function(
        page_script, args=(module, seeded["data_dir"], token, incident_id), default_timeout=60
    )
    return at.run()


def test_workspace_renders_for_every_detection_status(seeded, services):
    from threatlens.models.domain import Severity

    token = seeded["admin"]
    ev = services.incidents.detail(token, seeded["iid"])["events"][0]["id"]
    services.incidents.flag_events(
        token,
        [ev],
        title="Analyst flagged item",
        reason="Looks wrong to me per HR report.",
        severity=Severity.LOW,
    )
    ids = _incident_ids(services, token)
    assert set(ids) == {"known_detection", "anomalous_behavior", "suspicious_unmatched"}
    for status, iid in ids.items():
        for module in ("workspace", "timeline"):
            at = run_page_for(module, seeded, token, iid)
            assert not at.exception, (status, module, [e.value for e in at.exception])
            assert not at.error, (status, module, [e.value for e in at.error])


def test_ai_report_and_approvals_render_with_data(seeded, services):
    from threatlens.models.report import SimulatedAction

    token = seeded["admin"]
    # A fallback report is stored when the model is unreachable (offline in this fixture).
    services.investigation.client = __import__(
        "threatlens.integrations.ollama", fromlist=["OllamaClient"]
    ).OllamaClient(
        services.settings.ollama_host,
        timeout=1,
        transport=__import__("httpx").MockTransport(
            lambda r: (_ for _ in ()).throw(__import__("httpx").ConnectError("x"))
        ),
    )
    services.investigation.investigate(token, seeded["iid"])
    services.response.propose(
        token, seeded["iid"], SimulatedAction.ESCALATE_INCIDENT, "ws-fin-07", "Needs tier-2 review"
    )
    for module in ("ai_report", "responses"):
        at = run_page_for(module, seeded, token, seeded["iid"])
        assert not at.exception, [e.value for e in at.exception]
        errors = [e.value for e in at.error]
        if module == "ai_report":  # the injection warning is an intentional red banner
            assert any("prompt-injection" in e for e in errors)
            errors = [e for e in errors if "prompt-injection" not in e]
        assert errors == []
    report_text = " ".join(
        m.value for m in run_page_for("ai_report", seeded, token, seeded["iid"]).warning
    )
    assert "deterministic summary" in report_text.lower()
