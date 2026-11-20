# Is HoneyShield ready for companies?

Re-audit of release 1.2.0, 19 November 2026, updated for 1.3.0 on 20 November 2026. Every claim
below points at something that was run and can be run again; where something has not been done, it
says so.

## What 1.3.0 changed

The honest weak spots of 1.2.0 were operational, not in the detection code: it could stop working
without anyone being told, backups were manual and stayed on the same server, admin sign-in could be
phished, and decoy URLs were recognisable. 1.3.0 closes each one:

* a watchdog proves every five minutes that a decoy hit is still detected end to end, and tells the
  operator on a separate channel, plus a heartbeat for an outside dead-man's switch (HONEY-068);
* nightly backups encrypted to a key kept off the server, copied off-site, restorable with a
  tested drill (HONEY-069);
* passkeys and an address allowlist for the console (HONEY-070);
* decoy path prefixes of the operator's choosing (HONEY-071).


## The short answer

Yes, for a company that runs it for itself. One organisation (or a handful of tenants) can install
HoneyShield on its own server or Kubernetes cluster, plant decoys, and rely on it: hits are recorded
even through a database or API outage, the evidence is tamper-evident, upgrades do not drop requests,
and the install is one command.

Not yet as a product sold to many companies, or as a hosted service. That needs things software alone
cannot provide: an independent penetration test, a real staging environment, contracts and privacy
documents, and an operations team. It also needs some engineering for very large data volumes. Those
gaps are listed below with what it takes to close each.


## Can it fail to detect a hit?

This was the most important question, and until this release the answer was yes: a decoy hit was
written to the database while the visitor's request was being handled, so if PostgreSQL was down, or
every API replica was down, the hit raised an error and was lost (finding HONEY-067). An outage is
exactly when an attacker might be probing.

Now the edge (nginx) handles that case itself. When the backend errors, times out or cannot be
reached, nginx answers the visitor exactly as the backend would, so nothing reveals the outage, and
writes the hit to a spool file. A small worker sends spooled hits to the backend once it is back. Each
hit keeps the time the edge saw it and the edge's request id, and the database stores at most one event
per request id, so a hit can never be counted twice.

Measured:

| Test | Result |
|---|---|
| Compose: every API replica stopped, 20 hits sent, replicas restarted | 20 of 20 recorded, original times, 0 duplicates |
| Compose: database stopped, 20 hits sent, database restarted | 20 of 20 recorded, 0 duplicates |
| Kubernetes: API scaled to 0, 20 hits sent, scaled back | 20 of 20 recorded, 0 duplicates |
| Visitor's view during the outages | normal 204 responses and a byte-identical pixel |
| Evidence chains after all of the above | verify |
| Load test, 31,442 hits through the TLS edge | 31,442 events and 31,542 chain links for 31,542 events: none lost, none extra |

What can still lose a hit, stated plainly:

- The machine itself is lost (Compose, single host) or an edge pod is deleted while its spool still
  holds hits that have not been replayed (Kubernetes; the spool lives in the pod). Normal outages do
  not cause this; deleting edge pods during an outage does. The runbook says not to.
- A single address sending more than the edge allows (20 per second with a burst of 40, configurable)
  gets 429 answers for the excess. By then that address has been recorded many times; floods are
  summarised on purpose so they cannot fill the database.
- Fake API keys and form honeypots are detected inside the customer's own application and reported by
  its hook. The reference client keeps a report it cannot deliver and retries it, with the same
  idempotency key, until HoneyShield accepts it; with `spool_path` set it also survives a graceful
  restart. A report is lost only if the application crashes before sending it or its queue (10,000
  by default) overflows.
- No software detects a decoy nobody planted, or one planted where an attacker never looks. Placement
  guidance is in the decoy deployment guide.


## Area by area

| Area | Where it stands | Evidence | What is missing |
|---|---|---|---|
| Detection reliability | Strong | outage tests above; 804 automated tests | Spool loss on host or pod loss (see above) |
| Evidence integrity | Strong | per-tenant hash chains, sealed audit chain, write-once (S3 Object Lock) checkpoints, application role cannot alter evidence; restore drill re-verifies every chain | Independent review of the design |
| Availability | Good on Kubernetes, single point of failure on Compose | rolling upgrades with migrations: 0 failed requests in 6,000+ during each; API and edge run 2+ replicas | Database high availability is whatever PostgreSQL service you use (use a managed one with failover and point-in-time recovery) |
| Scale | Fine for a company; not proven for a large hosted service | 312 to 382 hits/s on a laptop through the full TLS edge (two API replicas, 1 CPU each); lists and charts stay in milliseconds at 10 million events | Time partitioning of the events table, per-tenant quotas, and a load test on real servers before promising more |
| Security | Solid design, not independently tested | MFA for admins, OpenID Connect SSO, least-privilege database roles, strict console CSP, signed integrations and alerts, vulnerability gate on every image, dependency audit, 67 findings tracked to closure | External penetration test; SAML and SCIM for large enterprises; secrets from a vault or cloud KMS instead of environment variables |
| Operations | Good | Prometheus metrics and tested alert rules, runbooks, an end-to-end verification script, a scripted restore drill | Off-site backup automation, a status page, on-call |
| Accessibility | Good | 0 axe-core violations, light and dark, desktop and phone | A screen-reader walkthrough by a person |
| Privacy and legal | Basic | free-use licence, third-party notices, configurable retention | Customer licence agreement, privacy policy, data processing agreement (source addresses are personal data under GDPR) |
| Distribution | Ready | one-command installer from published images, upgrades in place, Helm chart; signed provenance when the repository is public | Public images or a customer registry login (they are private today) |
| Commercial | Not started | | Self-service sign-up, billing, support process and SLA |


## What to do, in order

Before the first company relies on it:

1. Run it on a real server with real DNS names and certificates (the installer's server mode), and work
   through `docs/release-checklist.md` there.
2. Set `BACKUP_S3_*` to a bucket somewhere else, keep `backup-key.txt` off the server, and run
   `scripts/restore_drill.sh --dump` once with a downloaded backup.
3. Give the watchdog a notice channel and a heartbeat URL (docs/watchdog.md). Prometheus and the
   alert rules remain available for larger setups.
4. Have an independent penetration test done, and fix what it finds.
5. Get a lawyer to turn `LICENSE` into a customer agreement, and write a privacy policy and data
   processing agreement.

For larger companies:

6. SAML single sign-on and SCIM user provisioning.
7. Secrets from HashiCorp Vault or the cloud provider's KMS.
8. A load test on production-sized hardware; partition the events table by month past roughly 100
   million events.

For a hosted service run by you:

9. Per-tenant quotas, sign-up and billing, a status page, and an on-call rota.
10. A replicated spool or an edge on durable storage, so even losing an edge node mid-outage loses
    nothing.


## How this was checked

Everything above can be re-run:

- `pytest` with real PostgreSQL, S3 Object Lock and Valkey (`docs/testing-strategy.md`): 804 passed.
- `scripts/verify_deployment.py` against Compose, the installer and Kubernetes: all checks pass.
- The outage tests (API replicas stopped, database stopped, every hit recorded exactly once) and a
  31,442-hit load test through the TLS edge, all verifiable in the hash chain.
