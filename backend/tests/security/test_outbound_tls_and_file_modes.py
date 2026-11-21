"""Outbound TLS floor, evidence file permissions and config-error logging (CodeQL triage, 1.3.2)."""
from __future__ import annotations

import logging
import ssl
import stat
from pathlib import Path

from app.core import tls
from app.core.ip_trust import is_ip_in_trusted_proxies
from app.services import evidence

APP_DIR = Path(__file__).resolve().parents[2] / "app"


def test_client_context_verifies_and_requires_tls12():
    ctx = tls.client_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_unverified_context_still_requires_tls12():
    ctx = tls.unverified_client_context()
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_every_outbound_tls_context_comes_from_the_shared_helper():
    """A new ssl.create_default_context() elsewhere would skip the TLS 1.2 floor."""
    offenders = []
    for path in APP_DIR.rglob("*.py"):
        if path == APP_DIR / "core" / "tls.py":
            continue
        text = path.read_text()
        for needle in ("ssl.create_default_context(", "ssl._create_unverified_context(", "ssl.SSLContext("):
            if needle in text:
                offenders.append(f"{path.relative_to(APP_DIR)}: {needle}")
    assert offenders == []


def test_evidence_files_are_not_readable_by_other_users(tmp_path):
    path = evidence.WriteOnceDirectory(tmp_path).put("checkpoint-test.json", b"[]")
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode & 0o222 == 0, "evidence files must be read-only"
    assert mode & 0o077 == 0, "only the owner may read evidence"
    assert mode & 0o400


def test_invalid_trusted_proxy_is_reported_by_position_not_value(caplog):
    with caplog.at_level(logging.WARNING, logger="app.core.ip_trust"):
        assert is_ip_in_trusted_proxies("10.0.0.5", ["not-an-ip-xyz", "10.0.0.5"]) is True
    assert "TRUSTED_PROXIES entry 1" in caplog.text
    assert "not-an-ip-xyz" not in caplog.text
