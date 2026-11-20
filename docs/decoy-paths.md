# Decoys that do not look like HoneyShield

Out of the box, decoy URLs look like `https://<ingest host>/t/<token>`, `/px/<token>.gif` and
`/collect/<token>`. Those prefixes are the same in every installation. An attacker who has seen
HoneyShield before can spot a decoy by its URL and simply not touch it. Two settings fix that.

## 1. An ingest host name that fits the company

The ingest host is the domain every decoy points at. Choose one that looks like ordinary company
infrastructure:

| Good | Avoid |
|---|---|
| `cdn.example.com`, `assets.example.com`, `static.example.net`, `files.example-cdn.com` | `honeyshield.example.com`, `canary.example.com`, `trap.example.com`, `decoy...` |

Keep it separate from the operator host (the console). The two must be different names.

## 2. Your own path prefixes

| Setting (Compose `.env`) | Helm value | Default | Example |
|---|---|---|---|
| `HS_DECOY_LINK_PATH` | `decoyPaths.link` | `t` | `static/v2` |
| `HS_DECOY_PIXEL_PATH` | `decoyPaths.pixel` | `px` | `assets/img` |
| `HS_DECOY_COLLECT_PATH` | `decoyPaths.collect` | `collect` | `telemetry/v1` |
| `HS_DECOY_LEGACY_PATHS` | `decoyPaths.legacy` | `true` | `false` once old decoys are rotated |

Rules: one to three segments of lower-case letters, digits and hyphens; no prefix may contain
another; reserved first segments (`api`, `auth`, `internal`, `integrations`, `console`, `health`,
`metrics` and similar) are refused. An invalid value stops HoneyShield from starting rather than
leaving it half-configured.

With the installer:

```bash
./install.sh --upgrade --version 1.3.0 --decoy-paths static/v2,assets/img,telemetry/v1
```

or edit the four lines in `.env` and run `docker compose --env-file .env up -d`.

## Changing paths on a running installation

Decoys already planted keep their old URLs. With `HS_DECOY_LEGACY_PATHS=true` (the default) the old
prefixes keep working, so nothing breaks. New and rotated decoys use the new prefixes. When every
old decoy has been rotated (Projects and decoys, Rotate), set `HS_DECOY_LEGACY_PATHS=false`: the old
prefixes then answer 404 like any other unknown path.

## What still identifies the service

The responses themselves: decoy links answer `204 No Content`, pixels a 43-byte transparent GIF. Many
services do the same, so this says little on its own, but it is not invisible. Decoy token values
are random and stored only in your database.
