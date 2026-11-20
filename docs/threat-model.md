# Threat model (STRIDE, per asset)

Assets: (A1) detection evidence, (A2) decoy secrecy, (A3) tenant data, (A4) operator accounts,
(A5) availability of detection, (A6) alert delivery, (A7) integration credentials.

| # | Threat | Asset | Mitigation (implemented) | Residual risk |
|---|---|---|---|---|
| T1 | Flood ingestion with random tokens to exhaust limiters and blind detection | A5 | token resolved before any limiter; valid hits stored regardless; separate fail-open evidence counter; edge `limit_req` | DB lookup per request (bounded at the edge); one host |
| T2 | Probe whether a value is a decoy (oracle) | A2 | identical ingest responses; tenant values server-generated; no 409 across tenants; hook returns 202 for unknown/foreign decoys | SYSTEM_ADMIN may still set values (global role) |
| T3 | Spoof source IP via X-Forwarded-For | A1 | trusted only from nginx fixed IP; right-to-left parsing; nginx overwrites the header | customer-asserted IPs in CUSTOMER_HOOK events (labelled) |
| T4 | Tenant admin fabricates "observed" evidence | A1 | manual events labelled MANUAL with creator + mandatory reason + audit; DB CHECK | admin can still enter labelled manual events |
| T5 | Compromised API process rewrites/deletes evidence | A1 | runtime role: no UPDATE/DELETE/TRUNCATE/DDL; triggers; start-up guard | it can insert false new events (labelled with their source) |
| T6 | DB superuser / backup tampering | A1 | hash chain + signed checkpoints exported to WORM storage | undetectable between last checkpoint and tampering if checkpoints are not exported |
| T7 | Cross-tenant data access | A3 | SQL tenant predicates on every service; 404 masking; tests per resource family | process-level bug would affect all tenants (single DB) |
| T8 | Credential stuffing / session theft | A4 | login limits (app+edge), bcrypt, short JWTs, revocation by version, stream expiry | TOTP MFA required for admins in production; a phished TOTP code is still usable for 30–90 s (no phishing-resistant WebAuthn) |
| T9 | SSRF through webhook URLs | A6, infra | https-only, port allowlist, DNS validated per delivery and pinned, private/metadata ranges blocked, no redirects, worker is the only egress | DNS answers that are public but attacker-controlled (by design acceptable) |
| T10 | Forged or replayed integration reports | A1, A7 | HMAC over method/path/time/body; ±5 min window; idempotency unique constraint; scope = one project; revocation | a stolen secret can report false events for that project until revoked |
| T11 | Customer integration leaks the real key | A2 | hook hashes locally; server rejects reports containing the key and audits it | customer code outside our control |
| T12 | XSS in the console from attacker-controlled fields (UA, path) | A4 | console renders only via textContent; strict CSP (no inline script/style) | browser extensions, compromised endpoint |
| T13 | Live-stream resource exhaustion | A5 | 500 global / 25 per-tenant connections; bounded queues; drops counted | single-process limits |
| T14 | Alert channel outage loses alerts | A6 | transactional outbox, retries, dead-letter + audit, backlog metric | DEAD rows need operator action |
| T15 | Log injection / correlation poisoning | ops | inbound request IDs validated; JSON logs | – |

Out of scope: physical/host compromise beyond the database (assume host hardening and
patching), denial of service beyond edge rate limits (use an upstream DDoS service).
