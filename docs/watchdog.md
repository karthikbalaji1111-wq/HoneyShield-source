# Watchdog: knowing HoneyShield still works

A detection system that has quietly stopped looks exactly like one with nothing to report. The
watchdog (`app/workers/watchdog.py`, the `watchdog` service in Compose, a Deployment in Helm) proves
every five minutes that a decoy hit is still detected, checks the parts around it, and tells you on
a channel that does not depend on HoneyShield's own alert pipeline when something is wrong.

## What it checks

| Check | Fails when |
|---|---|
| Detection self-test | A test hit sent through the public entry point (DNS or the edge address, TLS, nginx, the API, the database) is not recorded within 15 seconds |
| Database | The database does not answer |
| Alert worker | The worker that sends alerts has not reported in for 3 minutes |
| Alert delivery | An alert was given up on in the last hour, or one has waited more than 15 minutes |
| Outage buffer | Hits the edge held during an outage have waited more than 30 minutes to be replayed |
| Evidence checkpoints | No checkpoint for three intervals, or the S3 upload failed |
| Backups | The last good backup is older than 26 hours, the restore check failed, or backups are off or on this server only (warnings) |
| TLS certificates | A certificate expires within 14 days (critical within 3), has expired, or is not trusted (warning) |
| Disk space | Less than 10% free (warning), less than 5% or 512 MB (critical) |

The self-test hit is not a decoy. It never becomes a detection event, never alerts anyone and never
touches the append-only evidence tables, so it leaves nothing behind. The edge answers it like any
other request.

## Notices

Set at least one channel in `.env` (Compose) or the Helm values and Secret:

| Setting | Use |
|---|---|
| `WATCHDOG_NOTIFY_WEBHOOK_URL` | ntfy (`https://ntfy.sh/your-long-random-topic`, plain text with a title), Slack or Discord incoming webhooks, or any receiver of `{"text": ..., "content": ..., "title": ...}` |
| `WATCHDOG_NOTIFY_EMAIL` | One address, sent through the SMTP settings (`SMTP_HOST` and the rest) |

A notice goes out when a problem starts, as a reminder every `WATCHDOG_REMIND_HOURS` (6) while a
critical problem lasts, and once everything passes again. A notice that cannot be delivered is
retried at the next check.

Test the channel:

```bash
docker compose --env-file .env exec watchdog python -m app.workers.watchdog --test-notice
```

Run one cycle and print the results:

```bash
docker compose --env-file .env exec watchdog python -m app.workers.watchdog --once
```

## Dead-man's switch

The watchdog runs on the same server it watches, so it cannot report the server itself going down.
For that, it requests `WATCHDOG_HEARTBEAT_URL` after every check without a critical problem, and an
outside service warns you when those requests stop.

With Healthchecks.io (free for this use):

1. Create a check with a period of 5 minutes and a grace time of 10 minutes.
2. Set `WATCHDOG_HEARTBEAT_URL=https://hc-ping.com/<uuid>` and, optionally,
   `WATCHDOG_HEARTBEAT_FAIL_URL=https://hc-ping.com/<uuid>/fail` so a failing self-test is reported
   at once rather than after the grace time.
3. Choose where Healthchecks.io should warn you (email, phone app, Telegram, and so on).

Uptime Kuma's push monitors, Better Stack heartbeats and Cronitor work the same way.

## Self-test path

By default (Compose) the self-test connects to the edge's internal address with the public ingest
host name, so it tests nginx, TLS, the API and the database even on a server that cannot reach its
own public address. To include public DNS and the firewall, set `WATCHDOG_PROBE_CONNECT=` (empty).

While the certificate is self-signed, the installer sets `WATCHDOG_PROBE_VERIFY_TLS=false` so the
self-test does not fail on it; the certificate check still warns. Set it to `true` once a real
certificate is installed.

## In the console

System administrators see the latest checks under Overview, System health. The same data is at
`GET /api/v1/system/status` (system administrators only).
