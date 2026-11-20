# Monitoring and SLOs (HONEY-027)

## Signals

| Signal | Source |
|---|---|
| Liveness | `GET /health` (no dependencies) |
| Readiness | `GET /api/v1/ready` — DB reachable, revision is head (heads parsed once per process), runtime role least-privileged (prod) |
| Metrics | `GET /metrics` on the control host with `Authorization: Bearer $METRICS_TOKEN` (Prometheus text) |
| Logs | JSON lines on stdout (`timestamp, level, logger, message, request_id`), rotated by Docker (10 MB × 3) |
| Audit | `audit_logs` (`/api/v1/audit-logs`) |

## Metrics exposed

| Metric | Type | Meaning |
|---|---|---|
| `honeyshield_ingest_requests_total{outcome}` | counter | valid_recorded, valid_suppressed, invalid_token, throttled_response |
| `honeyshield_integration_reports_total{outcome}` | counter | recorded, duplicate, auth_<reason> |
| `honeyshield_http_requests_total{status}` | counter | 2xx/3xx/4xx/5xx |
| `honeyshield_http_request_duration_seconds_sum/_count` | counter | mean latency = sum/count |
| `honeyshield_alert_outbox{status}` | gauge | PENDING/IN_FLIGHT/DELIVERED/DEAD |
| `honeyshield_alert_oldest_pending_seconds` | gauge | alert lag |
| `honeyshield_stream_subscribers`, `_dropped_events_total`, `_rejected_subscriptions_total` | gauge/counter | live feed health |
| `honeyshield_db_pool_checked_out/_size/_overflow` | gauge | connection pool |
| `honeyshield_database_up` | gauge | 1 if the scrape could query PostgreSQL |
| `honeyshield_shared_state_up`, `_errors_total`, `_fallbacks_total` | gauge/counter | Redis health (limits/stream fall back per replica when 0) |
| `honeyshield_stream_relayed_in_total`, `_relay_publish_errors_total` | counter | cross-replica live feed |

Counters are per replica: scrape every backend pod (`/metrics` accepts a pod-IP Host with the
token) and sum. Ready-made rules with unit tests: `deploy/monitoring/prometheus-rules.yml`. Backup success is not exported by the
application: alert on the age of the newest dump file / drill result in your scheduler.

## SLOs (targets, with the assumptions behind them)

| SLI | Target | Basis |
|---|---|---|
| Valid decoy hits persisted | 99.99 % of valid hits that reach the backend (excluding the documented ≥60/min/IP/decoy summarisation) | design guarantee; verified under limiter saturation in tests |
| Ingest latency | p99 < 250 ms at the edge | single indexed lookup + one transaction; measured listing queries at 1M events are 1-4 ms |
| Alert delivery | 99 % delivered < 2 min when the receiver is healthy | worker poll 2 s, first retry 30 s |
| Control-plane availability | 99.5 % monthly | single host; HA needs the target architecture |
| Analytics | top attackers / summary < 2 s | measured 0.45-0.7 s at 500k-1M events per scope |

## Alerts to configure

* `honeyshield_database_up == 0` or readiness 503 for 2 min (page).
* `increase(honeyshield_http_requests_total{status="5xx"}[5m]) > 10`.
* `honeyshield_alert_oldest_pending_seconds > 600` or any increase of `honeyshield_alert_outbox{status="DEAD"}`.
* `increase(honeyshield_ingest_requests_total{outcome="valid_suppressed"}[5m]) > 0` (flood on a decoy: investigate).
* `increase(honeyshield_integration_reports_total{outcome=~"auth_.*"}[15m]) > 50` (misconfigured or hostile client).
* Evidence: nightly `python -m app.workers.evidence verify --checkpoints …` non-zero exit (page).
* Newest backup older than 26 h; last restore drill older than 35 days.
