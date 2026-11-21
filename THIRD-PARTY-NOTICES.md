# Third-party notices

HoneyShield is licensed under its own free-use licence (see `LICENSE`). It includes and runs alongside the open-source
components below, each under its own licence. Those licences govern those components; nothing in
HoneyShield's licence restricts the rights they grant. Licence texts are installed with each
package (for Python packages, in its `*.dist-info` directory inside the backend image).

Checked on 2026-11-17 from installed package metadata. A test
(`backend/tests/deployment/test_third_party_notices.py`) fails if a dependency in
`backend/requirements.txt` is missing from this list.

## Python packages in the backend image (`backend/requirements.txt`)

| Package | Version | Licence | Source |
|---|---|---|---|
| alembic | 1.20.1 | MIT | https://alembic.sqlalchemy.org |
| annotated-doc | 0.0.6 | MIT | https://github.com/fastapi/annotated-doc |
| annotated-types | 0.8.0 | MIT | https://github.com/annotated-types/annotated-types |
| anyio | 4.16.0 | MIT | https://github.com/agronholm/anyio |
| async-timeout | 5.0.1 | Apache-2.0 | https://github.com/aio-libs/async-timeout |
| bcrypt | 5.0.0 | Apache-2.0 | https://github.com/pyca/bcrypt |
| cffi | 2.1.1 | MIT-0 | https://github.com/python-cffi/cffi |
| click | 8.5.1 | BSD-3-Clause | https://github.com/pallets/click |
| cryptography | 50.0.2 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| defusedxml | 0.7.1 | PSF-2.0 | https://github.com/tiran/defusedxml |
| exceptiongroup | 1.3.1 | MIT | https://github.com/agronholm/exceptiongroup |
| fastapi | 0.163.1 | MIT | https://github.com/fastapi/fastapi |
| h11 | 0.16.0 | MIT | https://github.com/python-hyper/h11 |
| idna | 3.20 | BSD-3-Clause | https://github.com/kjd/idna |
| Mako | 1.4.3 | MIT | https://www.makotemplates.org |
| MarkupSafe | 3.0.4 | BSD-3-Clause | https://github.com/pallets/markupsafe |
| psycopg2-binary | 2.9.13 | LGPL-3.0-or-later with exceptions (see below) | https://www.psycopg.org |
| pycparser | 3.12 | BSD-3-Clause | https://github.com/eliben/pycparser |
| pydantic | 2.14.3 | MIT | https://github.com/pydantic/pydantic |
| pydantic-settings | 2.16.3 | MIT | https://github.com/pydantic/pydantic-settings |
| pydantic_core | 2.50.4 | MIT | https://github.com/pydantic/pydantic-core |
| PyJWT | 2.15.1 | MIT | https://github.com/jpadilla/pyjwt |
| python-dotenv | 1.2.4 | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| redis (client) | 8.1.0 | MIT | https://github.com/redis/redis-py |
| SQLAlchemy | 2.1.8 | MIT | https://www.sqlalchemy.org |
| starlette | 1.10.0 | BSD-3-Clause | https://github.com/Kludex/starlette |
| tomli | 2.5.0 | MIT | https://github.com/hukkin/tomli |
| typing_extensions | 4.16.0 | PSF-2.0 | https://github.com/python/typing_extensions |
| typing-inspection | 0.4.5 | MIT | https://github.com/pydantic/typing-inspection |
| uvicorn | 0.54.0 | BSD-3-Clause | https://github.com/encode/uvicorn |
| websockets | 17.4 | BSD-3-Clause | https://github.com/python-websockets/websockets |

**psycopg2.** Licensed under the GNU LGPL with exceptions that permit linking with proprietary code.
HoneyShield uses it unmodified as a separately installed, replaceable package and does not
statically link it; its source is available from the project above. The binary wheel bundles
libpq (PostgreSQL Licence) and OpenSSL (Apache-2.0).

## Runtime images and services

| Component | Licence | Use |
|---|---|---|
| Python 3.12 (`python:3.12-slim`, Debian) | PSF-2.0; Debian packages under their own licences (some GPL) | base of the backend image |
| nginx 1.30 (`nginx:alpine`, Alpine Linux) | BSD-2-Clause; Alpine packages under their own licences (some GPL) | base of the edge image |
| PostgreSQL 16 (`docker/Dockerfile.db`, built on `postgres:16`, Debian) | PostgreSQL Licence; Debian packages under their own licences | database (Compose) |
| PostgreSQL 16 client (`postgresql-client-16` from apt.postgresql.org) | PostgreSQL Licence | `pg_dump` / `pg_restore` for backups, in the backend image |
| Valkey 9.0 (`valkey/valkey`) | BSD-3-Clause | shared rate-limit and live-stream state |

GPL-licensed operating-system packages in the base images (for example the shell and core utilities)
are unmodified distribution packages. Their corresponding source is available from the
distributions' archives (Debian: https://sources.debian.org, Alpine: https://pkgs.alpinelinux.org);
on request the Owner will provide the source for the exact versions in a released image.

Redis 7.4 and later are licensed RSALv2/SSPLv1, which restrict offering Redis as part of a service.
HoneyShield therefore ships Valkey, the BSD-licensed continuation of Redis under the Linux Foundation.

## Operator console

The console (`frontend/console`) contains no third-party code, fonts or images: it uses the
operating system's fonts and is served from the product's own origin.

## Development and CI only (not distributed)

pytest, pytest-asyncio and httpx (test runner); MinIO (S3 Object Lock test double, AGPL-3.0, run only
as a disposable CI service); Trivy (image scanner); Helm, kubeconform, actionlint, shellcheck and
promtool (configuration checks). None of these is included in HoneyShield's images or charts.
