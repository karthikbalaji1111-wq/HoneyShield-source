# Alerting and the transactional outbox (HONEY-007)

**Persist first, notify second.** A detection never waits on, or fails because of, an alert
channel.

## Flow

1. The event transaction inserts the `DetectionEvent`, its chain link and one `OutboxEvent` per
   active destination of the tenant (optionally limited to one project) whose `min_severity` the
   event meets. Commit makes all of them durable together; a rollback queues nothing.
2. The worker claims due rows: `UPDATE … SET status='IN_FLIGHT', lease_until=now()+120s WHERE id
   IN (SELECT … FOR UPDATE SKIP LOCKED LIMIT n)`. Several workers never claim the same row
   (verified: 4 concurrent workers, 40 rows, no duplicates). A crashed worker's lease expires and
   the row is retried.
3. Delivery happens outside any transaction; the outcome is then written back.

| Outcome | New status |
|---|---|
| 2xx | DELIVERED (`delivered_at`) |
| 4xx except 408/425/429 | DEAD (receiver rejected it; retrying will not help) |
| 5xx, 408/425/429, timeout, connection error | PENDING, `next_attempt_at = now + min(1h, 30s·2^(n-1)) ±20%` |
| attempts ≥ `ALERT_MAX_ATTEMPTS` (8) | DEAD |
| destination disabled / unsafe at delivery time | DEAD |

Every DEAD writes an `ALERT_DELIVERY_FAILED` audit record. Delivery state is visible in the
console (*Alerts*) and `GET /api/v1/alert-destinations/deliveries`; backlog and oldest pending age
are exported on `/metrics`.

## Destinations

`POST /api/v1/alert-destinations` (TENANT_ADMIN; SYSTEM_ADMIN must name `tenant_slug`) takes
`url`, `format`, `min_severity` and optional `project_domain`.

| `format` | `url` | Delivered as |
|---|---|---|
| `HONEYSHIELD` | `https://…` | signed JSON (below); for SOAR, custom receivers and HTTP collectors |
| `SLACK` | `https://…` | `{"text": …}`, accepted by Slack, Teams and Mattermost incoming webhooks |
| `EMAIL` | `mailto:a@x.com[,b@y.com]` (≤10) | plain-text mail through the operator's SMTP relay (`SMTP_*`), with the `X-HS-*` signature headers over the body |
| `SYSLOG_CEF` | `syslog+tls://siem.example.com:6514` | RFC 5424 over TLS (RFC 5425 octet counting), body in ArcSight CEF; parsed natively by Splunk, QRadar, Sentinel, Elastic and ArcSight |
| `PAGERDUTY` | `pagerduty://<integration key>` (`pagerduty+eu://` for an EU account) | PagerDuty Events API v2 `trigger` (below) |
| `SPLUNK_HEC` | `splunk://<HEC token>@<host>[:8088][?index=<index>]` | one JSON event to Splunk's HTTP Event Collector (below) |
| `SENTINEL` | `sentinel://<client id>:<client secret>@<DCR ingestion host>/<DCR immutable id>/<stream>?tenant=<tenant id>` | one row in the `HoneyShield_CL` table through the Azure Monitor Logs Ingestion API (below) |

The response returns the signing secret once. It is not returned for these formats, which
authenticate HoneyShield in other ways:
* `SYSLOG_CEF` relies on TLS server authentication.
* `PAGERDUTY` uses the integration key to identify the sender.
* `SPLUNK_HEC` uses the HEC token.
* `SENTINEL` uses the Entra application.

API responses and the console show Splunk tokens and Sentinel client secrets masked. `EMAIL` destinations can only be created when `SMTP_HOST` is configured.

**CEF mapping:** signature `honeytoken.<TYPE>`; severity LOW=3, MEDIUM=5, HIGH=8, CRITICAL=10.
Extensions:
* `rt` (epoch ms), `src`, `requestMethod`, `request` (token replaced by `{token}`) and
  `externalId` (delivery id);
* `cn1` event id;
* `cs1` decoy id, `cs2` project, `cs3` decoy label, `cs4` detection source, `cs5` token type;
* `cs6` MITRE ATT&CK technique ids, comma-separated (left out when the decoy type has none).

Syslog uses facility authpriv; the severity is notice/warning/err/crit by alert severity.

**Failure handling per channel:**
* *Email:* a 5xx reply or refused recipients is permanent (DEAD + audited). Connection errors
  and 4xx replies retry with backoff. If SMTP is removed, deliveries wait instead of failing.
* *Syslog:* no acknowledgement exists in the protocol. A completed TLS handshake and write
  counts as delivered; connection or TLS failures retry.
* *PagerDuty:* 2xx (PagerDuty answers 202) is delivered; 400 (bad integration key or payload) is
  permanent; 429 and 5xx retry with backoff.
* *Splunk:* a 2xx answer is delivered. 400 (for example, a wrong index) and 401/403 (a bad or
  disabled token) are permanent. 429, 503 and network errors retry.
* *Sentinel:* a 2xx answer is delivered. Each case is handled as follows:
  * *Entra refuses the credentials* (`invalid_client` and the like): permanent. The outbox records
    only the error code, never the secret.
  * *Entra is unreachable or answers 5xx:* retried.
  * *403:* retried. A new Monitoring Metrics Publisher role assignment can take up to 30 minutes
    to apply.
  * *401:* the cached token is dropped and the delivery retried.
  * *400 and 413:* permanent.

**Splunk HTTP Event Collector:** create an HEC token in Splunk (*Settings › Data inputs › HTTP
Event Collector*). Then use `splunk://<token>@<host>`:
* Port 8088 is Splunk Enterprise's default.
* Splunk Cloud uses `http-inputs-<stack>.splunkcloud.com:443`.
* Ports 443, 8088 and 8443 are allowed.

The request is `POST /services/collector/event` with `Authorization: Splunk <token>` and this event:
* `sourcetype` `honeyshield:detection`, `source` `honeyshield`;
* `time` is when the decoy fired;
* `index` is the token's default unless the URL has `?index=`;
* `event` carries the same fields as the JSON webhook, including `attack`.

HoneyShield always sends an `X-Splunk-Request-Channel` id, so tokens with indexer acknowledgement
accept it too. HoneyShield counts the HEC's 200 as delivered and does not poll for the
acknowledgement. Search with
`sourcetype="honeyshield:detection" | stats count by event.severity, event.token_type`.

**Microsoft Sentinel:** Sentinel reads custom data from its Log Analytics workspace, which
HoneyShield writes through the Logs Ingestion API. Setup takes three steps:
1. **Deploy the template.** Deploy `deploy/sentinel/honeyshield-sentinel.json` into the workspace's
   resource group, for example
   `az deployment group create -g <rg> --template-file deploy/sentinel/honeyshield-sentinel.json
   --parameters workspaceName=<workspace>`. It creates:
   * the `HoneyShield_CL` table;
   * a data collection rule of kind `Direct`, which has its own ingestion endpoint;

   Its outputs are the rule's immutable id, its logs-ingestion endpoint and the stream
   (`Custom-HoneyShield`).
2. **Create the Entra application.** Register an application in Entra ID and create a client
   secret for it. On the data collection rule, give the application the **Monitoring Metrics
   Publisher** role.
3. **Add the destination.** Use
   `sentinel://<application id>:<secret>@<endpoint host>/<immutable id>/Custom-HoneyShield?tenant=<directory id>`,
   percent-encoding the secret.

Delivery works as follows:
* HoneyShield gets a token from `login.microsoftonline.com` (client credentials, scope
  `https://monitor.azure.com//.default`) and reuses it until shortly before it expires.
* It sends each alert as a one-row JSON array to
  `/dataCollectionRules/<id>/streams/<stream>?api-version=2023-01-01`.
* Columns: `TimeGenerated`, `EventId`, `DeliveryId`, `Severity`, `DetectionSource`, `TokenType`,
  `DecoyId`, `DecoyLabel`, `Project`, `SourceIp`, `HttpMethod`, `RequestPath`, `AttackTechniques`
  (comma-separated ids) and `AttackTechniqueNames`.
* Only the Azure public cloud (`*.ingest.monitor.azure.com`) is supported.

Query the table with `HoneyShield_CL | where Severity == "CRITICAL"`, or base a Sentinel analytics
rule on it. Both the token request and the upload go through the webhook transport's SSRF checks
and address pinning.

**PagerDuty:** create an *Events API v2* integration on the service that should be paged and use
its Integration Key. Each detection is a `trigger` with `dedup_key` `honeyshield-<event id>`, so a
retried delivery never pages twice. `payload.severity` is critical (CRITICAL), error (HIGH),
warning (MEDIUM) or info (LOW); `source` and `group` are the project, `component` the decoy type,
`class` is `honeytoken`, and `custom_details` carries the same fields as the JSON webhook plus the
ATT&CK techniques. The request goes to `events.pagerduty.com` (or `events.eu.pagerduty.com`)
through the webhook transport, with the same SSRF checks and address pinning; the integration key
is never looked up in DNS or written to the audit log.

**MITRE ATT&CK:** every alert names the techniques its decoy type points to
(`backend/app/core/attack.py`): for example an AWS key decoy is T1552.001 *Credentials In Files*
and T1078.004 *Cloud Accounts*. Webhook and PagerDuty payloads carry them in `attack`, Slack ends
with `ATT&CK: …`, email has an `ATT&CK:` line and CEF uses `cs6`. They are the likely technique,
not a verdict; form honeypots map to none.

## Payload (HONEYSHIELD format)

```json
{"type":"honeyshield.detection","version":1,"data":{"delivery_id":12,"event_id":345,
 "severity":"HIGH","source":"PUBLIC_INGEST","token_type":"URL","decoy_id":"dcy_…","token_label":"…",
 "project":"app.example.com","ip_address":"203.0.113.9","http_method":"GET",
 "request_path":"/t/{token}","triggered_at":"…",
 "attack":[{"id":"T1595.003","name":"Active Scanning: Wordlist Scanning"},
           {"id":"T1213","name":"Data from Information Repositories"}]}}
```
The token value is replaced by `{token}`; headers and user agents are not sent.
Headers: `X-HS-Delivery` (de-duplicate on this), `X-HS-Event`, `X-HS-Timestamp`,
`X-HS-Signature: v1=hex(HMAC-SHA256(secret, timestamp + "." + body))`. Receivers should reject
timestamps older than 5 minutes.

## Test alerts

`POST /api/v1/alert-destinations/{id}/test` queues a delivery flagged `is_test` with no detection
event. It goes through the worker exactly like a real alert, with the same SSRF checks, signing,
retries and dead-lettering. No evidence is created, and a CHECK constraint keeps every non-test
delivery tied to an event.
* Webhooks receive `{"type": "honeyshield.test", ...}` with `source: "TEST"`.
* Slack gets a plain sentence; email uses the subject "[HoneyShield] Test alert: this
  destination works"; syslog sends CEF signature `honeytoken.TEST`; PagerDuty gets an `info`
  event whose summary says it is a test (dedup key `honeyshield-test-<delivery id>`).
* Limit: 5 per destination per minute.

## SSRF protection

https only (http only with `ALERT_ALLOW_HTTP_WEBHOOKS`, refused in production); ports 443/8443;
no userinfo; `localhost`, `*.local`, `*.internal`, `*.home.arpa` refused; literal IPs must be public.
At **every delivery** the worker resolves the host, requires every address to be public unicast
(rejects loopback, RFC 1918, ULA, link-local incl. 169.254.169.254, CGNAT, multicast, reserved,
IPv4-mapped) and connects to the validated address with TLS verified against the hostname, so
DNS rebinding cannot redirect it. Redirects are not followed. At creation, DNS is advisory (the API
runs on an internal network) but private answers are rejected.

Syslog destinations follow the same rules (port 6514 for TLS; plain `syslog+tcp://` on 514/601
only with the development flag). Email recipients are validated, and header injection (CR/LF,
`?cc=` parameters) is refused. The SMTP relay itself is operator configuration, not tenant input.

**Self-hosted receivers on private networks:** set `ALERT_ALLOWED_PRIVATE_CIDRS` (for example
`10.20.0.0/16`). Addresses inside those networks are accepted. Loopback, link-local (cloud
metadata), multicast and unspecified addresses are refused even if listed. Leave it empty on a
multi-tenant SaaS deployment.

## Not included

Other SIEM-specific APIs (QRadar, Elastic, Chronicle): use syslog/CEF or the signed JSON webhook.
Opsgenie and other paging services: their generic webhook integrations accept the signed JSON
webhook. Sentinel in Azure Government or Azure operated by 21Vianet is not supported yet.

Verification:
* The test suite uses a real SMTP server and a real TLS syslog listener on loopback.
* The deployed Compose stack (2026-11-17) delivered to an HTTPS receiver on a private network
  (`ALERT_ALLOWED_PRIVATE_CIDRS`, private CA). A test alert and a real decoy hit were both
  DELIVERED on the first attempt, both signatures verified at the receiver, and the token value
  was absent from both.
* The same stack delivered a real decoy alert to a TLS syslog receiver (RFC 5425) as RFC 5424 +
  CEF: delivered on the first attempt, token value masked.
* Delivery to a customer's production webhook, SIEM or mail relay has not been exercised.
