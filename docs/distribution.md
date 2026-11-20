# Getting HoneyShield to the people who will use it

This note compares the ways to ship HoneyShield and recommends one. The short version: companies
install it on their own servers with one command, from published images, and never need the source
code. A public demo runs on a small rented server with the same installer. Vercel can host a landing
page and the documentation, but not the product.


## What HoneyShield needs from wherever it runs

- Long-running processes: the API, an alert worker, an evidence checkpointer and the replay worker.
- A PostgreSQL database that keeps its data, and a place for write-once evidence checkpoints.
- Its own edge with two host names (one for the console, one for the decoys), so that the decoy host
  exposes nothing else and so that hits can be captured at the edge during an outage.
- WebSockets for the live event feed.

That rules some platforms in and some out.


## The options

**Install on your own server (recommended).** One command sets everything up from published images:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)"
```

or, on a server with two DNS names pointing at it:

```bash
bash -c "$(curl -fsSL .../install.sh)" -- --control-host app.example.com --ingest-host ingest.example.com --email you@example.com
```

It checks for Docker, downloads three small files (the Compose file, the database setup script and a
configuration template), generates every secret, pulls the images, starts the stack, waits until it
is healthy and asks for the first administrator's password. Upgrades are the same script with
`--upgrade --version X.Y.Z` and keep all data. This is what security teams expect: detection data and
evidence stay on infrastructure they control. It was tested end to end from a registry: healthy in
under a minute, all 61 checks of the verification script passing, and an upgrade that kept every
record.

**Kubernetes.** For companies that run clusters, the Helm chart (`deploy/helm/honeyshield`) is the
same product with high availability: two or more API and edge replicas, rolling upgrades with zero
failed requests in testing, NetworkPolicies and Pod Security `restricted`. See `docs/kubernetes.md`.

**A public demo.** A small virtual server (2 vCPU and 4 GB is enough; Hetzner, DigitalOcean, AWS
Lightsail and similar cost a few dollars a month) running the installer in server mode, with two DNS
names and a Let's Encrypt certificate. This is the best way to let people try it from a link, and the
best thing to put in the README and in a paper: it is the real product.

**Vercel.** Vercel hosts static sites and short-lived serverless functions. It cannot run
HoneyShield's database, workers or edge, so the product cannot live there. It is a good home for a
landing page and the documentation, which point at the demo and the installer.

**Render (or Railway, Fly.io).** These can run Docker services with a managed PostgreSQL, so a demo is
possible, but they put their own proxy in front of every service. HoneyShield's two-host edge, its
outage capture and its strict host separation would have to be reworked or lost, and the workers and
volumes make it more expensive than a small server running the real thing. Not recommended.

**Handing out the source.** The source is public in its own repository (below), so anyone can
read, audit and build it. Installing still uses the published images; nobody needs to build.


## How it is published

Two repositories and the image registry work together:

1. **The private repository** (this one) is the workshop: full history, CI, the release workflow and
   unpublished material such as the research paper.
2. **The public repository** [HoneyShield-source](https://github.com/karthikbalaji1111-wq/HoneyShield-source)
   holds the complete source of each release as one commit under GitHub's no-reply address, so no
   personal address or history is published. Everything is copied except the paths listed in
   `deploy/public/EXCLUDE`. The installer downloads its deployment files from there, tagged per
   version. The release workflow copies each release across after the images are published;
   `scripts/publish_source_repo.sh` does the same by hand. CI fails if the installer needs a file
   that would be left out, or if a personal email address would be published.
3. **The images** `honeyshield-backend`, `honeyshield-edge` and `honeyshield-db` in GitHub Container
   Registry. They must be public for the one-line install to work without a login: GitHub, your
   profile, Packages, the package, Package settings, Change visibility.

**The licence** is free for everyone, for any purpose; it forbids selling, redistributing or hosting
HoneyShield for others (LICENSE). It is not an open-source licence.
