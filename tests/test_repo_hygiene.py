"""Repository hygiene checks that guard against supply-chain style mistakes."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIRS = ["threatlens", "tests", "scripts", "rules"]
BIDI_AND_INVISIBLE = {*range(0x200B, 0x2010), *range(0x202A, 0x202F), *range(0x2066, 0x206A)}


def _files():
    yield ROOT / "app.py"
    for d in SOURCE_DIRS:
        for p in (ROOT / d).rglob("*"):
            if p.suffix in {".py", ".yml", ".yaml", ".sql", ".toml"} and p.is_file():
                yield p


def test_no_trojan_source_characters():
    offenders = []
    for p in _files():
        text = p.read_text(encoding="utf-8")
        for n, line in enumerate(text.splitlines(), 1):
            if any(ord(c) in BIDI_AND_INVISIBLE for c in line):
                offenders.append(f"{p.relative_to(ROOT)}:{n}")
    assert offenders == []


def test_no_runtime_data_or_env_tracked_by_gitignore():
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in [".env", "data/*", "*.db", "chroma/", ".venv/", "*.log"]:
        assert pattern in ignore


def test_control_regex_still_strips_bidi():
    from threatlens.ingest.normalize import clean_text

    hostile = "a" + chr(0x202E) + "b" + chr(0x2066) + "c" + chr(0x200B) + "d" + chr(0x1B)
    assert clean_text(hostile, 100) == "abcd"
