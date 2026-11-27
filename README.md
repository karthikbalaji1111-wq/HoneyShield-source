# HoneyShield

HoneyShield catches people who are somewhere they should not be.

The idea is simple. You leave bait in places nobody has a real reason to touch. That could be a link hidden in an old config file, a fake API key in a repository, a Word document with a tempting name, or a domain account that nobody uses. Normal users never go near these things. So when one of them gets touched, it is almost always someone poking around, and HoneyShield tells you right away.

It runs on your own server. Your data stays with you.

It is free to use, including at work. The license section at the end has the details.


## Installing it

You need a Linux server with Docker, about 2 GB of memory, ports 80 and 443 open, and two domain names pointing at the server. One name is for the console you log in to. The other is for the bait. Give the bait one an ordinary name like cdn or assets, not something like honeypot.

Then run this one command on the server, with your own names and email:

bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)" -- --control-host app.example.com --ingest-host cdn.example.com --email you@example.com

If you just want to try it on your own computer first, run it without the options:

bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)"

The installer checks Docker, downloads what it needs, makes all the passwords and secrets for you, starts everything, and asks you to pick the admin password. It also creates a file called backup-key.txt. Copy that file somewhere safe off the server straight away, because your backups cannot be restored without it.

When it is done, open https://your-control-host/console/ and log in. On your own computer that is https://app.localhost:8443/console/ and your browser will warn about the certificate. That is expected, because it is a self-signed one.

The installer starts with a temporary certificate. To get a real one from Let's Encrypt, follow docs/deploy-oracle-free.md. That guide works for any Ubuntu server, not only Oracle.

To upgrade later and keep all your data:

~/honeyshield/install.sh --upgrade --version 1.5.0

If you use Kubernetes, there is a Helm chart in deploy/helm/honeyshield and the steps are in docs/kubernetes.md.


## The kinds of bait

You make a project for each app or network you want to protect, and then make bait for it. There are nine kinds right now.

- A hidden URL. A web address that only shows up where an intruder would look, like a commented-out line in a config file.
- A hidden link. The same thing, tucked inside a web page where normal visitors never see it.
- A tracking pixel. A tiny image for fake emails and documents. Opening them sets it off.
- A fake API key. It looks real. You leave it in config files or old code.
- A form honeypot. An invisible form field. People never fill it in, bots do.
- A Word document. A file with a juicy name that reports when someone opens it.
- A DNS name. Any lookup of it gets recorded, even from networks that block almost everything. You need a domain you can point at HoneyShield for this one.
- An AWS key. A real key that cannot do anything. Any use of it shows up in AWS's own logs. You need a spare AWS account for this one.
- An Active Directory account. A fake domain account with a password nobody knows. If someone tries to log in with it or tries to Kerberoast it, a small script on your domain controllers reports it. HoneyShield never connects into your network to do this.

A lot of the bait can be downloaded already sitting inside the kind of file attackers go looking for, like an AWS credentials file, a .env file, a kubeconfig or an SSH config. The Active Directory bait comes with the PowerShell scripts that set it up.


## What happens when bait is touched

HoneyShield records it as an event. Each event has the time, the address it came from, what was asked for, the browser or tool that was used, and which bait it was. It also records where that information came from, whether HoneyShield saw it directly, your own app reported it, or a person typed it in.

Events cannot be edited or deleted through the app. Each one is chained to the one before it, so if anything is changed later you can tell. A copy of the end of that chain is regularly saved to write-once storage outside the database.

If part of the system is down when bait is touched, the hit is not lost. The front door keeps it and records it once everything is back, with the right time, and only once. I tested this by stopping the API and then the database while sending hits, and every hit came through.

Then it sends an alert to wherever you set up. That can be a signed webhook, Slack or Teams, email, PagerDuty, Splunk, Microsoft Sentinel, or any SIEM over syslog. Each alert says which MITRE ATT&CK technique the bait points to. Alerts wait in a queue and retry, so if your receiver is down for a while it still gets everything when it comes back.


## What else is in it

A web console that works on a phone, with light and dark modes. It shows recent activity, the list of events with filters, your projects and bait, alert settings, the audit log, evidence checks and user management.

Separate tenants, so different teams or customers never see each other's data. Three roles: system admin, tenant admin and read-only user.

Admins have to use two-factor login, either an authenticator app or a passkey. Single sign-on works with any OpenID Connect provider like Okta, Entra ID or Google. You can make personal API keys for scripts. You can also limit the console to your own IP addresses while the bait stays reachable from anywhere.

A watchdog that sends a test hit every five minutes and checks it was recorded. It also keeps an eye on alerts, backups, certificates and disk space, and tells you if something is wrong.

Nightly backups that are encrypted with a key you keep off the server, and can be copied to any S3-compatible storage.

Bait that does not give itself away. You choose the URL paths and the domain name, so nothing in the bait points back to HoneyShield.


## Trying it from the source code

You need Docker and openssl. It takes about ten minutes.

git clone https://github.com/karthikbalaji1111-wq/HoneyShield-source.git

cd HoneyShield-source

scripts/quickstart_env.sh

docker compose --env-file .env.local up -d --build --wait

docker compose --env-file .env.local exec backend python -m app.bootstrap --email you@example.com

The script makes a settings file with fresh secrets and a self-signed certificate. It never overwrites a file you already have. The last command asks you to pick the admin password.

Then open https://app.localhost:8443/console/ and log in. A good first try is to add a tenant, add a project, make a hidden URL, and open that URL in another tab. On your own computer, add :8443 after ingest.localhost in the address. The hit shows up under Events within a few seconds.

To stop it, run docker compose --env-file .env.local down. Add -v at the end if you also want to delete the local data.


## Running it for real

For one server, use the install command above and then read docs/deployment-guide.md.

For a free cloud server, step by step, read docs/deploy-oracle-free.md.

For Kubernetes, read docs/kubernetes.md.

Before you go live, go through docs/release-checklist.md.

A real setup needs a few things only you can provide: two domain names, certificates for them, a PostgreSQL database, an S3 bucket with Object Lock for the evidence copies, and somewhere to send alerts. docs/production-readiness.md lists what has been checked and what is still up to you.

Every release comes with ready-made images for normal and ARM servers. Each one is scanned for known security problems before it is published, comes with a list of everything inside it, and has a signed record of how it was built. docs/verify-it-yourself.md shows how to check all of that yourself.


## How it is put together

In front is nginx. It answers on two names and keeps them apart. The console name serves the console and the API. The bait name only accepts bait hits and reports, nothing else.

Behind that there is the API, written in Python with FastAPI, running as two or more copies. There is a worker that sends alerts, one that seals the evidence, a watchdog, a backup job, PostgreSQL 16 for the data, and Valkey for rate limits and live updates. Nothing important is lost if Valkey is lost.

The code is laid out in plain layers. backend/app/api handles web requests and permissions, backend/app/services holds the rules, backend/app/repositories talks to the database, and backend/app/models describes the tables. The console is plain HTML, CSS and JavaScript in frontend/console. docs/architecture-as-is.md goes into more detail.


## Working on the code

cd backend

python3.12 -m venv .venv

. .venv/bin/activate

pip install -r requirements.txt pytest pytest-asyncio httpx

JWT_SECRET_KEY="$(openssl rand -hex 32)" APP_ENV=test pytest -q

That runs the tests on SQLite. Some tests need a real PostgreSQL, S3 or Valkey, and docs/testing-strategy.md explains how to point them at throwaway ones.

Every change goes through the full test suite with real PostgreSQL, S3 and Valkey, a dependency security audit, migration checks, image builds and scans, Bandit and CodeQL, and a full install from source that gets scanned with OWASP ZAP.


## More reading

Everything else is in the docs folder. Some good places to start:

- docs/deployment-guide.md for setting it up
- docs/honeytoken-deployment-guide.md for where to put bait
- docs/active-directory-decoys.md for the Active Directory bait
- docs/alerting-and-outbox.md for alerts, including Splunk and Sentinel
- docs/evidence-integrity.md and docs/backup-and-restore.md for evidence and backups
- docs/security-model.md and docs/threat-model.md for how it is protected
- docs/industry-readiness.md for an honest look at what is still missing
- docs/api-reference.md for the API

If this file and something in docs ever disagree, trust the docs.


## What I want to add next

- More details about attacker addresses, like location, network owner and reputation.
- Help from AI in making sense of what an attacker did across many events.
- Scheduled reports.
- Ready-made setups for the big cloud platforms.


## Security problems

If you find a security problem, please report it privately as described in SECURITY.md. Please do not open a public issue for it.


## License

HoneyShield is free for anyone to install and use, for any purpose, including inside a company. You can read, build and change the code for your own use. You cannot sell it, share copies of it, or run it as a paid hosted service for others. The full terms are in LICENSE. It is not an open-source license.

Copyright 2026 Karthik Balaji. The open-source parts HoneyShield uses, and their licenses, are listed in THIRD-PARTY-NOTICES.md.
