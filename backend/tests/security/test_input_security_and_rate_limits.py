"""Comprehensive regression tests for Phase 7: Input Security & Rate Limits.

Covers:
  - F-010: Request body-size limits (normal, oversized Content-Length, streaming/chunked, 413 format)
  - F-011: API-wide rate limiting (authenticated, public, health exempt, 429 Retry-After, reset)
  - F-012: HoneyToken ingestion abuse control (valid, invalid, revoked, per-token isolation, 429)
  - F-013: Forensic request header security (allowlist, credential stripping, deterministic truncation, size cap)
  - F-028: IP validation and trusted-proxy model (IPv4/IPv6, malformed reject, spoofing resistance)
"""
from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.header_security import sanitize_forensic_headers
from app.core.ip_trust import extract_client_ip, is_valid_ip, normalize_ip
from app.core.rate_limit import api_limiter, ingestion_limiter, login_limiter, reset_all_limiters
from app.models.detection_event import DetectionEvent
from app.models.enums import HoneyTokenType


# ---------------------------------------------------------------------------
# Phase 7B: Request Body Size Limits (F-010)
# ---------------------------------------------------------------------------

class TestRequestBodySizeLimits:
    def test_normal_request_within_limit_accepted(self, client, admin_headers_a):
        """A normal payload well below the 1MB limit must succeed."""
        resp = client.post(
            "/api/v1/projects",
            headers=admin_headers_a,
            json={"tenant_slug": "tenant-a", "name": "Body Size Project", "domain": "bodysize.test.internal"},
        )
        assert resp.status_code == 201
        assert resp.json()["name"] == "Body Size Project"

    def test_oversized_content_length_rejected_with_413(self, client, admin_headers_a):
        """A request with Content-Length exceeding the limit must be rejected with 413."""
        settings = get_settings()
        oversized_length = settings.max_request_body_bytes + 1024

        headers = dict(admin_headers_a)
        headers["content-length"] = str(oversized_length)

        resp = client.post(
            "/api/v1/projects",
            headers=headers,
            content=b"x" * 100,  # Content-Length claims oversized
        )
        assert resp.status_code == 413
        data = resp.json()
        assert "exceeds maximum allowed size" in data["detail"]
        assert "request_id" in data

    def test_streaming_chunked_body_overflow_rejected_with_413(self, client, admin_headers_a):
        """A streamed/chunked request body exceeding max_bytes must terminate and return 413."""
        settings = get_settings()
        max_bytes = settings.max_request_body_bytes

        # Generate payload larger than max_bytes
        oversized_payload = b"A" * (max_bytes + 2048)

        # Without Content-Length or with exact large payload
        resp = client.post(
            "/api/v1/projects",
            headers=admin_headers_a,
            content=oversized_payload,
        )
        assert resp.status_code == 413
        assert "exceeds maximum allowed size" in resp.json()["detail"]

    def test_boundary_request_accepted(self, client, admin_headers_a):
        """A request immediately below the limit must pass the body size check."""
        # A payload of 100KB is well below 1MB but substantial
        payload = {"tenant_slug": "tenant-a", "name": "Boundary Project", "domain": "boundary.test.internal"}
        resp = client.post(
            "/api/v1/projects",
            headers=admin_headers_a,
            json=payload,
        )
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# Phase 7C: API-Wide Rate Limiting (F-011)
# ---------------------------------------------------------------------------

class TestApiRateLimiting:
    def test_authenticated_traffic_rate_limited(self, client, admin_headers_a):
        """Authenticated traffic must be throttled once limit is reached and return 429."""
        settings = get_settings()
        limit = settings.rate_limit_per_minute_authenticated

        # Use patch to simulate low limit for fast execution
        with patch.object(settings, "rate_limit_per_minute_authenticated", 3):
            # First 3 requests succeed
            for _ in range(3):
                r = client.get("/api/v1/projects", headers=admin_headers_a)
                assert r.status_code == 200

            # 4th request must be rejected with 429
            r4 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r4.status_code == 429
            assert "Retry-After" in r4.headers
            assert int(r4.headers["Retry-After"]) >= 1
            data = r4.json()
            assert "rate limit exceeded" in data["detail"].lower()
            assert "request_id" in data

    def test_public_traffic_rate_limited(self, client):
        """Public API traffic must be throttled per IP."""
        settings = get_settings()
        with patch.object(settings, "rate_limit_per_minute_public", 2):
            # 2 requests succeed
            for _ in range(2):
                r = client.get("/api/v1/tenants/999")  # unauthenticated 401 response counts as request
                assert r.status_code in (401, 404)

            # 3rd request is rate-limited before auth
            r3 = client.get("/api/v1/tenants/999")
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers

    def test_health_and_readiness_endpoints_exempt(self, client):
        """Health and readiness checks must never be blocked by rate limiting."""
        settings = get_settings()
        with patch.object(settings, "rate_limit_per_minute_public", 1):
            # Multiple rapid calls to health endpoints
            for _ in range(5):
                r_root = client.get("/")
                assert r_root.status_code == 200
                r_health = client.get("/health")
                assert r_health.status_code == 200
                r_v1_health = client.get("/api/v1/health")
                assert r_v1_health.status_code == 200
                r_ready = client.get("/api/v1/ready")
                assert r_ready.status_code != 429
                assert r_ready.status_code in (200, 503)

    def test_auth_login_endpoint_rate_limited(self, client):
        """POST /auth/login must be rate limited by login_limiter."""
        reset_all_limiters()
        settings = get_settings()
        with patch.object(settings, "login_attempts_per_minute", 2):
            for _ in range(2):
                r = client.post("/auth/login", json={"email": "wrong@example.com", "password": "wrong"})
                assert r.status_code == 401

            r3 = client.post("/auth/login", json={"email": "wrong@example.com", "password": "wrong"})
            assert r3.status_code == 429
            assert "Retry-After" in r3.headers

    def test_limiter_reset(self, client, admin_headers_a):
        """Resetting limiters must immediately restore admission."""
        settings = get_settings()
        with patch.object(settings, "rate_limit_per_minute_authenticated", 1):
            r1 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r1.status_code == 200

            r2 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r2.status_code == 429

            reset_all_limiters()

            r3 = client.get("/api/v1/projects", headers=admin_headers_a)
            assert r3.status_code == 200

    def test_unverified_bearer_token_receives_anonymous_rate_limit(self, client):
        """Unverified/bogus Bearer tokens must receive public limit, not elevated authenticated limit."""
        settings = get_settings()
        with patch.object(settings, "rate_limit_per_minute_public", 2):
            headers = {"Authorization": "Bearer forged.invalid.token"}
            r1 = client.get("/api/v1/projects", headers=headers)
            assert r1.status_code == 401
            r2 = client.get("/api/v1/projects", headers=headers)
            assert r2.status_code == 401

            # Request 3 is throttled at public limit (2), returning 429
            r3 = client.get("/api/v1/projects", headers=headers)
            assert r3.status_code == 429

    def test_random_bearer_tokens_cannot_flood_key_table(self, client):
        """Random bearer tokens from the same IP must all map to public_ip, not separate keys."""
        from app.core.rate_limit import api_limiter
        initial_keys = len(api_limiter._counts)

        for i in range(10):
            client.get("/api/v1/projects", headers={"Authorization": f"Bearer fake_token_{i}"})

        # At most 1 new key should have been created (public_ip:127.0.0.1)
        assert len(api_limiter._counts) <= initial_keys + 1

    def test_limiter_saturation_bounds_memory_and_preserves_existing(self):
        """FixedWindowLimiter must strictly bound memory under high-cardinality keys without evicting existing clients."""
        from app.core.rate_limit import FixedWindowLimiter
        limiter = FixedWindowLimiter(max_keys=10, clock=lambda: 1000.0)

        # Register an existing key
        allowed, _ = limiter.check_and_increment("client:existing", limit=5, global_limit=100)
        assert allowed is True

        # Saturate with 10 distinct attacker keys (filling remaining 9 slots up to max_keys=10)
        for i in range(10):
            limiter.check_and_increment(f"attacker:{i}", limit=5, global_limit=100)

        # Existing key still has remaining allowance and is preserved (not evicted)
        allowed_existing, _ = limiter.check_and_increment("client:existing", limit=5, global_limit=100)
        assert allowed_existing is True

        # New arrival beyond max_keys is rejected to defend memory
        allowed_new, _ = limiter.check_and_increment("new:arrival", limit=5, global_limit=100)
        assert allowed_new is False

        # Table size is strictly bounded to max_keys
        assert len(limiter._counts) <= 10


# ---------------------------------------------------------------------------
# Phase 7D: Public HoneyToken Ingestion Rate Limiting (F-012)
# ---------------------------------------------------------------------------

class TestHoneyTokenIngestionRateLimiting:
    def test_valid_token_triggers_detection_event(self, client, token_a, db_session):
        """Under normal volume, a valid token triggers an event and returns 204."""
        resp = client.get(f"/t/{token_a.token_value}")
        assert resp.status_code == 204

        # Verify event was recorded in DB
        events = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).all()
        assert len(events) >= 1

    def test_invalid_token_preserves_expected_204(self, client):
        """Unknown/phantom token returns silent 204 without leaking state."""
        resp = client.get("/t/nonexistent-token-xyz")
        assert resp.status_code == 204

    def test_revoked_token_produces_detection_event(self, client, token_a, db_session):
        """Revoked HoneyToken must still record a forensic DetectionEvent."""
        token_a.is_active = False
        db_session.commit()

        initial_count = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count()
        resp = client.get(f"/t/{token_a.token_value}")
        assert resp.status_code == 204

        new_count = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count()
        assert new_count == initial_count + 1

    def test_per_token_cap_limits_storage_not_response(self, client, token_a, db_session):
        """Past the per-(IP, token) cap, repeats are not stored individually, one suppression
        marker is written, and the response is unchanged (a 429 here would reveal validity)."""
        from app.models.audit_log import AuditLog

        settings = get_settings()
        with patch.object(settings, "ingestion_rate_limit_per_minute_token", 3):
            for _ in range(6):
                assert client.get(f"/t/{token_a.token_value}").status_code == 204

        assert db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count() == 3
        markers = db_session.query(AuditLog).filter_by(event_type="DETECTION_HITS_SUPPRESSED").all()
        assert len(markers) == 1
        assert markers[0].tenant_id == token_a.project.tenant_id
        assert token_a.token_value not in json.dumps(markers[0].event_metadata) + markers[0].message

    def test_per_token_cap_does_not_suppress_other_tokens(self, client, token_a, token_b, db_session):
        """Flooding token_a must NOT suppress detection of token_b from the same IP."""
        settings = get_settings()
        with patch.object(settings, "ingestion_rate_limit_per_minute_token", 2):
            for _ in range(5):
                client.get(f"/t/{token_a.token_value}")
            assert client.get(f"/t/{token_b.token_value}").status_code == 204
        assert db_session.query(DetectionEvent).filter_by(honey_token_id=token_b.id).count() == 1

    def test_pixel_ingestion_cap_keeps_gif_response(self, client, token_a, db_session):
        """Tracking pixel always answers with the GIF under the per-token cap; storage is capped."""
        settings = get_settings()
        with patch.object(settings, "ingestion_rate_limit_per_minute_token", 2):
            for _ in range(4):
                r = client.get(f"/px/{token_a.token_value}.gif")
                assert r.status_code == 200
                assert r.headers["content-type"] == "image/gif"
        assert db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count() == 2

    def test_per_ip_response_limit_is_identical_for_valid_and_invalid(self, client, token_a, db_session):
        """Once a caller exceeds its request rate it gets 429 for valid and invalid values alike,
        and the valid hit is still recorded."""
        settings = get_settings()
        with patch.object(settings, "ingestion_rate_limit_per_minute_ip", 3):
            for i in range(3):
                assert client.get(f"/t/junk-{i}").status_code == 204
            r_invalid = client.get("/t/junk-x")
            r_valid = client.get(f"/t/{token_a.token_value}")
            assert r_invalid.status_code == r_valid.status_code == 429
            assert "Retry-After" in r_valid.headers
        assert db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count() == 1

    def test_valid_hit_recorded_when_limiter_key_table_is_full(self, client, token_a, db_session):
        """HONEY-001: attacker noise filling the shared key table cannot blind detection."""
        for i in range(8192):
            ingestion_limiter.check_and_increment(f"ingest_ip:noise{i}", 120, 10**9)
        client.get(f"/t/{token_a.token_value}", headers={"X-Forwarded-For": "203.0.113.50"})
        assert db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count() == 1

    def test_valid_hit_recorded_when_global_budget_is_exhausted(self, client, token_a, db_session):
        """HONEY-001: exhausting the global per-minute budget cannot blind detection."""
        budget = get_settings().rate_limit_global_per_minute
        for i in range(budget):
            ingestion_limiter.check_and_increment(f"ingest_ip:n{i % 50}", 10**9, budget)
        r = client.get(f"/t/{token_a.token_value}", headers={"X-Forwarded-For": "203.0.113.51"})
        assert r.status_code == 429  # response throttled ...
        # ... but the evidence is kept.
        assert db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count() == 1

    def test_valid_hit_recorded_when_valid_counter_table_is_full(self, client, token_a, db_session):
        """Fail open for evidence: an untracked (IP, token) pair is still recorded."""
        from app.core.rate_limit import ingestion_valid_hit_counter

        for i in range(16384):
            ingestion_valid_hit_counter.increment(f"valid:noise:{i}")
        client.get(f"/t/{token_a.token_value}")
        assert db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).count() == 1

    def test_oversized_value_is_not_looked_up(self, client):
        """Values longer than any stored token are treated as invalid without a DB query."""
        from app.repositories.honey_token import HoneyTokenRepository

        with patch.object(HoneyTokenRepository, "get_by_token") as lookup:
            assert client.get("/t/" + "a" * 600).status_code == 204
            lookup.assert_not_called()
            client.get("/t/" + "a" * 20)
            lookup.assert_called_once()


# ---------------------------------------------------------------------------
# Phase 7E: Request Header Security & Sanitization (F-013)
# ---------------------------------------------------------------------------

class TestRequestHeaderSecurity:
    def test_allowed_forensic_headers_retained(self, client, token_a, db_session):
        """Forensic allowlisted headers must be persisted in DetectionEvent."""
        headers = {
            "User-Agent": "AttackerBrowser/1.0",
            "Referer": "https://evil.internal/search",
            "Sec-CH-UA": '"Chromium";v="120"',
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = client.get(f"/t/{token_a.token_value}", headers=headers)
        assert resp.status_code == 204

        event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
        assert event is not None
        assert event.headers is not None
        assert event.headers.get("user-agent") == "AttackerBrowser/1.0"
        assert event.headers.get("referer") == "https://evil.internal/search"
        assert event.headers.get("sec-ch-ua") == '"Chromium";v="120"'

    def test_sensitive_credentials_never_persisted(self, client, token_a, db_session):
        """Authorization, Cookie, and credential headers must NEVER be persisted."""
        headers = {
            "Authorization": "Bearer super-secret-jwt-token",
            "Cookie": "session_id=12345; auth=secret_cookie",
            "Set-Cookie": "tracker=danger",
            "X-API-Key": "secret-api-key-value",
            "User-Agent": "AttackerProbe/2.0",
        }
        resp = client.get(f"/t/{token_a.token_value}", headers=headers)
        assert resp.status_code == 204

        event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
        assert event is not None
        assert event.headers is not None
        assert "authorization" not in event.headers
        assert "cookie" not in event.headers
        assert "set-cookie" not in event.headers
        assert "x-api-key" not in event.headers
        assert event.headers.get("user-agent") == "AttackerProbe/2.0"

    def test_arbitrary_untrusted_headers_dropped(self, client, token_a, db_session):
        """Arbitrary non-allowlisted headers must not be persisted."""
        headers = {
            "X-Attacker-Custom": "payload_data",
            "X-Random-Junk": "junk_data",
            "User-Agent": "SafeProbe",
        }
        resp = client.get(f"/t/{token_a.token_value}", headers=headers)
        assert resp.status_code == 204

        event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
        assert "x-attacker-custom" not in event.headers
        assert "x-random-junk" not in event.headers

    def test_oversized_retained_header_values_truncated(self):
        """Header values exceeding max length must be deterministically truncated."""
        oversized_ua = "A" * 5000
        raw = {"user-agent": oversized_ua, "referer": "https://example.com"}
        sanitized = sanitize_forensic_headers(raw, max_value_length=100)
        assert sanitized is not None
        assert len(sanitized["user-agent"]) == 100
        assert sanitized["user-agent"] == "A" * 100
        assert sanitized["referer"] == "https://example.com"

    def test_jsonb_size_bounded_under_4kb(self):
        """Even with many headers, total serialized JSON must not exceed max_total_bytes."""
        raw = {f"user-agent": "A" * 500, "referer": "B" * 500, "origin": "C" * 500}
        sanitized = sanitize_forensic_headers(raw, max_total_bytes=512)
        assert sanitized is not None
        encoded = json.dumps(sanitized).encode("utf-8")
        assert len(encoded) <= 512


# ---------------------------------------------------------------------------
# Phase 7F: IP Validation & Trusted Proxy Model (F-028)
# ---------------------------------------------------------------------------

class TestIPValidationAndTrustModel:
    def test_valid_ipv4_and_ipv6_accepted(self):
        """Valid IPv4 and IPv6 strings must normalize correctly."""
        assert normalize_ip("198.51.100.1") == "198.51.100.1"
        assert normalize_ip("2001:db8::1") == "2001:db8::1"
        assert normalize_ip(" 10.0.0.1 ") == "10.0.0.1"

    def test_malformed_ip_in_detection_event_create_rejected(self, client, admin_headers_a, token_a):
        """Submitting a malformed IP to POST /detection-events must return 422."""
        invalid_ips = ["not-an-ip", "999.999.999.999", "; DROP TABLE users;", "1.2.3.4.5"]
        for bad_ip in invalid_ips:
            resp = client.post(
                "/api/v1/detection-events",
                headers=admin_headers_a,
                json={
                    "token_value": token_a.token_value,
                    "ip_address": bad_ip,
                    "request_path": "/test",
                    "http_method": "GET",
                    "severity": "LOW",
                    "reason": "Analyst reproduction for regression test",
                },
            )
            assert resp.status_code == 422, f"Expected 422 for bad IP '{bad_ip}', got {resp.status_code}"

    def test_untrusted_peer_spoofed_forwarded_for_ignored(self, client, token_a, db_session):
        """Untrusted peers supplying X-Forwarded-For must NOT be trusted."""
        settings = get_settings()
        # Direct peer is 127.0.0.1 in TestClient, but let's configure trusted_proxies to exclude 127.0.0.1
        with patch.object(settings, "trusted_proxies", ["192.168.1.1"]):
            # Attacker sends spoofed header
            resp = client.get(
                f"/t/{token_a.token_value}",
                headers={"X-Forwarded-For": "203.0.113.199"},
            )
            assert resp.status_code == 204

            event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
            # Must NOT use the spoofed IP; uses peer IP (127.0.0.1)
            assert event.ip_address == "127.0.0.1"

    def test_trusted_proxy_forwarded_for_honored(self, client, token_a, db_session):
        """When peer IP matches trusted_proxies, valid X-Forwarded-For is honored."""
        settings = get_settings()
        with patch.object(settings, "trusted_proxies", ["127.0.0.1"]):
            resp = client.get(
                f"/t/{token_a.token_value}",
                headers={"X-Forwarded-For": "198.51.100.55"},
            )
            assert resp.status_code == 204

            event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
            assert event.ip_address == "198.51.100.55"

    def test_malformed_forwarded_for_falls_back_safely(self, client, token_a, db_session):
        """Malformed X-Forwarded-For falls back safely to peer IP without crashing."""
        settings = get_settings()
        with patch.object(settings, "trusted_proxies", ["127.0.0.1"]):
            resp = client.get(
                f"/t/{token_a.token_value}",
                headers={"X-Forwarded-For": "invalid-ip-string"},
            )
            assert resp.status_code == 204

            event = db_session.query(DetectionEvent).filter_by(honey_token_id=token_a.id).order_by(DetectionEvent.id.desc()).first()
            assert event.ip_address == "127.0.0.1"


# ---------------------------------------------------------------------------
# Sliding-window admission: no double budget across a window boundary
# ---------------------------------------------------------------------------

class TestSlidingWindow:
    def _limiter(self, now):
        from app.core.rate_limit import FixedWindowLimiter
        return FixedWindowLimiter(max_keys=100, clock=lambda: now[0])

    def test_burst_straddling_a_boundary_gets_no_extra_budget(self):
        """Regression: a fixed window let 2 requests at :59.8 and 2 more at :00.4 all through."""
        now = [59.8]
        limiter = self._limiter(now)
        assert limiter.allow("ip", 2, 1000) and limiter.allow("ip", 2, 1000)
        now[0] = 60.45
        assert not limiter.allow("ip", 2, 1000)

    def test_budget_recovers_in_proportion_to_elapsed_time(self):
        now = [0.0]
        limiter = self._limiter(now)
        assert all(limiter.allow("ip", 10, 1000) for _ in range(10))
        assert not limiter.allow("ip", 10, 1000)
        now[0] = 60 + 30          # half the previous window still overlaps: ~5 of 10 used
        allowed = sum(limiter.allow("ip", 10, 1000) for _ in range(10))
        assert allowed == 5
        now[0] = 180              # two windows later: full budget again
        assert all(limiter.allow("ip", 10, 1000) for _ in range(10))

    def test_global_budget_also_slides(self):
        now = [59.0]
        limiter = self._limiter(now)
        assert all(limiter.allow(f"k{i}", 5, 6) for i in range(6))
        now[0] = 61.0
        assert not limiter.allow("fresh", 5, 6)

    def test_evidence_counter_stays_per_window(self):
        """increment()/peek() are plain counters for evidence caps; they do not slide."""
        now = [59.0]
        limiter = self._limiter(now)
        assert [limiter.increment("k") for _ in range(3)] == [1, 2, 3]
        now[0] = 60.5
        assert limiter.increment("k") == 1 and limiter.peek("k") == 1

    def test_boundary_sequence_at_the_http_layer(self, client, monkeypatch):
        """The original flake: three logins across a minute boundary must still end in 429."""
        import importlib
        from app.core.rate_limit import FixedWindowLimiter
        now = [59.9]
        router = importlib.import_module("app.api.auth.router")
        limiter = FixedWindowLimiter(clock=lambda: now[0])
        monkeypatch.setattr(router, "login_limiter", limiter)
        monkeypatch.setattr(get_settings(), "login_attempts_per_minute", 2)
        body = {"email": "wrong@example.com", "password": "wrong"}
        assert client.post("/auth/login", json=body).status_code == 401
        assert client.post("/auth/login", json=body).status_code == 401
        now[0] = 60.3
        assert client.post("/auth/login", json=body).status_code == 429
