# Verify it yourself

HoneyShield is a security tool from a small project, so there is no reason to take its claims on
trust. This page shows how to check each one with your own commands. Everything below runs from a
clone of this repository unless it says otherwise.

```bash
git clone https://github.com/karthikbalaji1111-wq/HoneyShield-source.git
cd HoneyShield-source
```


## 1. The images are built from this source

Every release image is built by this repository's own release workflow
(`.github/workflows/release.yml`) from a tagged public commit, and GitHub signs a record of that
build. Check it with the GitHub CLI:

```bash
gh attestation verify oci://ghcr.io/karthikbalaji1111-wq/honeyshield-backend:1.3.1 \
  --repo karthikbalaji1111-wq/HoneyShield-source
```

The output names the workflow run and the exact commit that produced the image; repeat for
`honeyshield-edge` and `honeyshield-db`. Each image also carries a list of its components (SBOM) and
the build parameters:

```bash
docker buildx imagetools inspect ghcr.io/karthikbalaji1111-wq/honeyshield-backend:1.3.1 \
  --format '{{json .SBOM}}' | head -c 600
```

Releases up to 1.3.0 were built before this existed and have no signed record.

**Or trust no pre-built image at all.** The installer can build every image on your own machine
from the published source of a version:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)" -- --build
```


## 2. The tests pass

Quick run on SQLite (about a minute):

```bash
cd backend
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest pytest-asyncio httpx hypothesis
JWT_SECRET_KEY="$(openssl rand -hex 32)" APP_ENV=test pytest -q
```

The full suite also runs against real PostgreSQL, S3 Object Lock and Valkey; how to start disposable
ones is in [testing-strategy.md](testing-strategy.md). Every push runs that full suite publicly:
see the repository's Actions tab, workflow **HoneyShield CI**. A skipped integration test fails the
build, so a green run means the database, S3 and Valkey tests really ran.


## 3. Security analysis, in public

| What | Where to see it | Run it yourself |
|---|---|---|
| CodeQL (Python, JavaScript, workflows; `security-extended` queries) | Security tab, Code scanning | runs on every push and weekly |
| Bandit static analysis of the backend; medium and high findings fail the build | CI log, step *Static security analysis* | `pip install bandit && bandit -r backend/app -ll -ii` |
| Dependency audit for known vulnerabilities | CI log, step *Dependency audit* | `pip install pip-audit && pip-audit -r backend/requirements.txt` |
| Image scan (Trivy): fixable high or critical vulnerabilities fail CI and the release | CI log, step *Image vulnerability gate* | `trivy image honeyshield-backend:<version>` |
| OWASP ZAP baseline scan of a running installation, console and decoy host | CI job *Install from source, self-test and web scan*; reports kept as the run's artifact | below |
| Fuzzing of the parsers that read attacker- or network-controlled bytes | `backend/tests/fuzz` (part of the suite) | below |

Accepted scanner findings are listed with their reason: Bandit in `# nosec` comments next to the
code, ZAP in [`.zap/rules.tsv`](../.zap/rules.tsv).

**Fuzzing.** Property-based tests (Hypothesis) feed generated input to the WebAuthn/CBOR decoder,
the authenticator data and COSE key parsers, the passkey sign-in and registration checks, the backup
decryption and key parsers, the XML parser for S3 responses, the decoy path handling, and the public
decoy endpoints over HTTP. The only acceptable outcome is the parser's own "invalid input" error
(and no 5xx from an endpoint). Ten times the CI effort:

```bash
cd backend && HYPOTHESIS_PROFILE=deep JWT_SECRET_KEY="$(openssl rand -hex 32)" APP_ENV=test pytest tests/fuzz -q
```

**Web scan** of an installation running on your machine (installed with the command in section 1):

```bash
docker run --rm --network host --add-host app.localhost:127.0.0.1 --add-host ingest.localhost:127.0.0.1 \
  -v "$PWD/.zap:/zap/wrk:ro" ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t https://app.localhost:8443/console/ -c rules.tsv
```

(On a Mac, replace `--network host` and the two `--add-host` options with
`--add-host app.localhost:host-gateway --add-host ingest.localhost:host-gateway`.)


## 4. Detection survives outages

The design claim: a decoy hit is never lost because part of HoneyShield is down. While the backend or
the database is unavailable the edge answers the visitor exactly as usual and keeps the hit; once
the backend is back, the hit is recorded with its original time, exactly once.

On a **test** installation (it creates a test tenant whose events, being evidence, stay):

```bash
scripts/reproduce_outage.sh ~/honeyshield 50
```

It sends 50 decoy hits with everything running, 50 with every API replica stopped and 50 with the
database stopped, then checks that exactly 150 events exist, none twice, and that the evidence chain
verifies. Its exit status is 0 only if all of that holds. It takes about five minutes, because each
phase starts on a fresh minute: by design, HoneyShield stores at most 60 hits per minute from one
address on one decoy (`INGESTION_RATE_LIMIT_PER_MINUTE_TOKEN`), and records anything beyond that as
one `DETECTION_HITS_SUPPRESSED` audit entry, so a flood cannot fill the database. Send more than that
in a minute and the script reports the shortfall, which is the cap working, not hits being lost.


## 5. The evidence cannot be changed silently

```bash
cd ~/honeyshield
docker compose --env-file .env run --rm -T --no-deps migrate python -m app.workers.evidence verify
```

This recomputes every tenant's hash chain over the detection events and the audit log. Events are
protected twice: a database trigger refuses any update or delete, and the application's own
database role has no right to change them (`python -m app.db.privileges check` shows its
privileges). To see the chain catch tampering anyway, on a test installation disable the trigger as
the database superuser, change one event's detail and run the check again: the chain breaks at that
event. How it works:
[evidence-integrity.md](evidence-integrity.md).


## 6. A deployment does what it should, end to end

`scripts/verify_deployment.py` exercises every decoy type, the integration hook, host separation,
TLS, masking, evidence and rate limits against a running installation (usage in the README).
`scripts/restore_drill.sh` restores a backup into a new database and checks counts and chains.


## What has not been verified

- No independent security audit or penetration test has been done.
- No large real-world deployment exists yet; the load and outage figures come from test machines.
- The earlier load test (31,442 hits through the TLS edge) is described in the project's notes but
  not yet packaged as a script here.
- Passkeys are tested with a software authenticator that produces the same messages as real ones,
  not with physical security keys.

Found something? Report it privately through the Security tab ([SECURITY.md](../SECURITY.md)).
