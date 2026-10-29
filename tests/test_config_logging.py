from __future__ import annotations

import json
import logging

import pytest
from pydantic import ValidationError

from threatlens.config import Settings
from threatlens.errors import AuthenticationError, ThreatLensError
from threatlens.logging_setup import REDACTED, JsonFormatter, redact


def test_defaults_are_loopback_and_safe(settings):
    assert settings.ollama_host == "http://127.0.0.1:11434"
    assert settings.allow_remote_ollama is False
    assert settings.max_upload_bytes == 10 * 1024 * 1024


@pytest.mark.parametrize("host", ["http://10.0.0.5:11434", "http://example.com:11434"])
def test_remote_ollama_rejected_without_opt_in(host):
    with pytest.raises(ValidationError):
        Settings(ollama_host=host, _env_file=None)


def test_remote_ollama_allowed_with_explicit_opt_in():
    s = Settings(ollama_host="http://10.0.0.5:11434", allow_remote_ollama=True, _env_file=None)
    assert s.ollama_host.endswith(":11434")


@pytest.mark.parametrize(
    "host", ["file:///etc/passwd", "ftp://127.0.0.1", "http://user:pw@127.0.0.1:11434", "nonsense"]
)
def test_invalid_ollama_urls_rejected(host):
    with pytest.raises(ValidationError):
        Settings(ollama_host=host, _env_file=None)


@pytest.mark.parametrize(
    "field,value", [("max_upload_mb", 0), ("session_idle_minutes", 0), ("ai_max_events", 10_000)]
)
def test_out_of_range_values_fail_fast(field, value):
    with pytest.raises(ValidationError):
        Settings(**{field: value}, _env_file=None)


def test_env_var_override(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("THREATLENS_OLLAMA_MODEL", "llama3.2:3b")
    assert Settings(_env_file=None).ollama_model == "llama3.2:3b"


def test_redact_nested_sensitive_keys():
    data = {"user": "alice", "password": "x", "nested": {"api_key": "k", "list": [{"token": "t"}]}}
    out = redact(data)
    assert out["user"] == "alice"
    assert out["password"] == REDACTED
    assert out["nested"]["api_key"] == REDACTED
    assert out["nested"]["list"][0]["token"] == REDACTED


def test_json_formatter_redacts_extras():
    record = logging.LogRecord("t", logging.INFO, __file__, 1, "login", None, None)
    record.password = "hunter2"  # type: ignore[attr-defined]
    record.username = "alice"  # type: ignore[attr-defined]
    line = JsonFormatter().format(record)
    parsed = json.loads(line)
    assert "hunter2" not in line
    assert parsed["ctx"]["username"] == "alice"


def test_errors_keep_detail_out_of_public_message():
    err = AuthenticationError(detail="user bob not found in table users")
    assert "bob" not in err.public_message
    assert ThreatLensError().public_message
