#!/usr/bin/env bash
# HoneyShield PostgreSQL bootstrap. Runs ONCE, on first volume init, from
# /docker-entrypoint-initdb.d/ as the image's bootstrap superuser (POSTGRES_USER).
#
# Creates the two non-superuser identities and hands the database to the owner:
#   honeyshield_owner  owns schema + tables, runs Alembic and the grant step (migrate service)
#   honeyshield_app    runtime role the API and worker connect as; owns nothing; gets only the
#                      privileges granted by `python -m app.db.privileges grant` after migrations
#
# Passwords come from the environment and are passed to psql as variables (:'var'), so they
# are quoted by the server and cannot inject SQL. There are NO default passwords.
set -euo pipefail

: "${HS_OWNER_DB_PASSWORD:?HS_OWNER_DB_PASSWORD must be set}"
: "${HS_APP_DB_PASSWORD:?HS_APP_DB_PASSWORD must be set}"
OWNER_ROLE="${HS_OWNER_DB_USER:-honeyshield_owner}"
APP_ROLE="${HS_APP_DB_USER:-honeyshield_app}"

echo "[init-db] creating roles ${OWNER_ROLE} (owner) and ${APP_ROLE} (runtime) in ${POSTGRES_DB}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v owner="$OWNER_ROLE" -v app="$APP_ROLE" \
     -v owner_pw="$HS_OWNER_DB_PASSWORD" -v app_pw="$HS_APP_DB_PASSWORD" \
     -v db="$POSTGRES_DB" <<'EOSQL'
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
              :'owner', :'owner_pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'owner') \gexec
SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD %L',
              :'app', :'app_pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'app') \gexec

-- The owner owns the database and the public schema; nobody else may create objects.
SELECT format('ALTER DATABASE %I OWNER TO %I', :'db', :'owner') \gexec
SELECT format('ALTER SCHEMA public OWNER TO %I', :'owner') \gexec
REVOKE ALL ON SCHEMA public FROM PUBLIC;
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', :'db') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', :'db', :'app') \gexec
SELECT format('GRANT USAGE ON SCHEMA public TO %I', :'app') \gexec
EOSQL

echo "[init-db] roles ready; the migrate service applies schema and runtime grants"
