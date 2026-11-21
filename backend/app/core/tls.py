"""TLS settings for every connection HoneyShield makes to another server.

Webhooks, syslog/SIEM, SMTP, S3 and WORM storage, OIDC sign-in and the watchdog's probe all get
their client context from here, so they share one rule: TLS 1.2 or newer. Python's default context
already refuses older versions on current OpenSSL builds, but that depends on the system's OpenSSL
configuration; setting the floor here makes it hold everywhere the image runs.
"""
from __future__ import annotations

import ssl

MINIMUM_VERSION = ssl.TLSVersion.TLSv1_2


def client_context(cafile: str | None = None) -> ssl.SSLContext:
    """A verifying client context (system CAs, or only `cafile` when given) that requires TLS 1.2+."""
    ctx = ssl.create_default_context(cafile=cafile or None)
    ctx.minimum_version = MINIMUM_VERSION
    return ctx


def unverified_client_context() -> ssl.SSLContext:
    """A context that does not check the certificate, still TLS 1.2+.

    Only for the watchdog's probe of a first install with a self-signed certificate
    (WATCHDOG_PROBE_VERIFY_TLS=false); the watchdog reports the untrusted certificate separately.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = MINIMUM_VERSION
    return ctx
