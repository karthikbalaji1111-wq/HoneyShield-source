# Running HoneyShield on Oracle Cloud's free server

This puts a complete HoneyShield on Oracle Cloud's Always Free tier: an ARM server, real HTTPS
certificates, notices when something breaks, a dead-man's switch, and encrypted backups off the
server. Cost: nothing, apart from an optional domain name. Time: about an hour.

The published images are built for ARM as well as x86, so nothing needs building. Oracle's offer and
console change from time to time; where a detail differs, the idea stays the same.

## What you need

* An Oracle Cloud account (Free Tier). Oracle asks for a card to verify you; Always Free resources
  are not charged.
* Two host names pointing at the server: one for the console, one for the decoys. A domain you own is
  best (decoys look more natural, for example `cdn.yourname.dev`). Free alternative: two DuckDNS
  names such as `hs-console.duckdns.org` and `files-yourname.duckdns.org`.
* A free Healthchecks.io account (the dead-man's switch) and the ntfy app on your phone (notices).
* If the HoneyShield image packages are private: a GitHub token with `read:packages`.

## 1. Create the server

1. Sign up at oracle.com/cloud/free. **Pick the home region carefully: it cannot be changed later.** A
   less busy region makes step 3 easier.
2. Compute, Instances, Create instance:
   * Image: Canonical Ubuntu 24.04 (the aarch64 one is chosen automatically for ARM).
   * Shape: Ampere, `VM.Standard.A1.Flex`, 2 OCPUs and 12 GB memory. That is half the free
     allowance and far more than HoneyShield needs (about 2 GB).
   * Networking: keep "Assign a public IPv4 address".
   * SSH keys: upload your public key or let Oracle generate a pair (save the private key).
   * Boot volume: 100 GB (up to 200 GB of block storage is free).
3. "Out of host capacity" means there are no free ARM servers in that availability domain right now.
   Try another availability domain, or again later; it usually works within a day.
4. Note the public IP address.

## 2. Open ports 80 and 443

Oracle has two firewalls and both block web traffic by default.

**Cloud firewall.** Networking, Virtual cloud networks, your VCN, Security Lists, Default Security
List, Add Ingress Rules: source `0.0.0.0/0`, TCP, destination port `80`; repeat for `443`.

**Server firewall.** Oracle's Ubuntu image ships iptables rules that reject everything but SSH:

```bash
ssh ubuntu@<public-ip>
sudo iptables -I INPUT 1 -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW -j ACCEPT
sudo netfilter-persistent save
```

## 3. Keep the server from being reclaimed

Oracle may reclaim Always Free servers that look idle for seven days (very low CPU, network and
memory use), and a quiet HoneyShield does look idle. The reliable fix is to upgrade the account to
Pay As You Go (Billing, Upgrade): Always Free resources stay free, and according to Oracle's
documentation at the time of writing, idle reclamation applies only to free accounts. Then add a budget alert of 1 (Billing, Budgets) so you hear about any charge at once.

If you stay on the free account, keep the heartbeat (step 9) set up: if the server is reclaimed, you
are told within minutes, and your backups (step 8) let you rebuild.

## 4. Install Docker

```bash
sudo apt-get update && sudo apt-get -y upgrade
curl -fsSL https://get.docker.com | sudo sh        # Docker's official install script
sudo usermod -aG docker ubuntu && exit             # log out and back in for the group to apply
```

After logging in again, `docker run --rm hello-world` should print a greeting.

## 5. Point the names at the server

* Own domain: two `A` records (for example `app` and `cdn`) to the public IP.
* DuckDNS: sign in at duckdns.org, add both subdomains, set each to the public IP.

Check from your own computer: `nslookup app.example.com` shows the IP.

## 6. Install HoneyShield

If the images are private, log in first: `docker login ghcr.io -u <github-user>` and paste the token.

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/karthikbalaji1111-wq/HoneyShield-source/main/deploy/install/install.sh)" -- \
  --control-host app.example.com --ingest-host cdn.example.com --email you@example.com \
  --decoy-paths static/v2,assets/img,telemetry/v1
```

The installer asks for the first administrator's password. It also creates `~/honeyshield/backup-key.txt`.
**Copy it off the server now**, from your own computer:

```bash
scp ubuntu@<public-ip>:honeyshield/backup-key.txt .
```

Store it in your password manager. Without it no backup can ever be decrypted.

## 7. Real HTTPS certificates (Let's Encrypt)

The installer starts with a temporary self-signed certificate. Replace it:

```bash
sudo apt-get install -y certbot
cd ~/honeyshield
sudo certbot certonly --webroot -w "$PWD/proxy/acme" -d app.example.com -d cdn.example.com \
  --agree-tos -m you@example.com --non-interactive
```

Install the certificate and let renewals install themselves (certbot renews on its own timer; this
hook copies the new files and reloads nginx without stopping it):

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/honeyshield.sh >/dev/null <<'EOF'
#!/bin/sh
set -e
cd /home/ubuntu/honeyshield
cp "$RENEWED_LINEAGE/fullchain.pem" proxy/certs/live.crt
cp "$RENEWED_LINEAGE/privkey.pem" proxy/certs/live.key
chown ubuntu:ubuntu proxy/certs/live.crt proxy/certs/live.key
chmod 644 proxy/certs/live.crt; chmod 600 proxy/certs/live.key
docker compose --env-file .env exec -T nginx nginx -s reload || true
EOF
sudo chmod 755 /etc/letsencrypt/renewal-hooks/deploy/honeyshield.sh
sudo RENEWED_LINEAGE=/etc/letsencrypt/live/app.example.com /etc/letsencrypt/renewal-hooks/deploy/honeyshield.sh

sed -i 's/^HS_\(CONTROL\|INGEST\)_CERT=.*/HS_\1_CERT=live.crt/; s/^HS_\(CONTROL\|INGEST\)_KEY=.*/HS_\1_KEY=live.key/' .env
sed -i 's/^WATCHDOG_PROBE_VERIFY_TLS=.*/WATCHDOG_PROBE_VERIFY_TLS=true/' .env
docker compose --env-file .env up -d
```

Open `https://app.example.com/console/`: the browser shows a valid padlock.

## 8. Backups off the server

Oracle's Object Storage gives 20 GB free. It protects against losing the server, though not against
losing the Oracle account itself; a bucket at another provider (Backblaze B2 has 10 GB free) protects
against both. Either works the same way.

For Oracle:

1. Storage, Buckets, Create bucket (private), for example `honeyshield-backups`. Optionally enable
   versioning, so deleted or overwritten copies can be recovered.
2. Your profile (top right), Customer secret keys, Generate. Copy the secret (shown once) and the
   access key.
3. The namespace is under Tenancy details (Object storage namespace).

Then in `~/honeyshield/.env`:

```
BACKUP_S3_ENDPOINT=https://<namespace>.compat.objectstorage.<region>.oraclecloud.com
BACKUP_S3_BUCKET=honeyshield-backups
BACKUP_S3_REGION=<region, e.g. ap-mumbai-1>
BACKUP_S3_ACCESS_KEY_ID=<access key>
BACKUP_S3_SECRET_ACCESS_KEY=<secret>
```

Apply and make a first backup right away:

```bash
docker compose --env-file .env up -d
docker compose --env-file .env exec backup python -m app.workers.backup run
docker compose --env-file .env exec backup python -m app.workers.backup list
```

## 9. Be told when anything breaks

**Notices.** Install ntfy on your phone and subscribe to a long random topic name (anyone who knows
the name can read it), for example `hs-7f3k9q2m4x8w`. Then in `.env`:

```
WATCHDOG_NOTIFY_WEBHOOK_URL=https://ntfy.sh/hs-7f3k9q2m4x8w
```

**Dead-man's switch.** At healthchecks.io create a check: period 5 minutes, grace 10 minutes, and
choose how it reaches you (email, the app, Telegram). Then:

```
WATCHDOG_HEARTBEAT_URL=https://hc-ping.com/<uuid>
WATCHDOG_HEARTBEAT_FAIL_URL=https://hc-ping.com/<uuid>/fail
```

Apply and test:

```bash
docker compose --env-file .env up -d
docker compose --env-file .env exec watchdog python -m app.workers.watchdog --test-notice
docker compose --env-file .env exec watchdog python -m app.workers.watchdog --once
```

Every line of the last command should say OK. Healthchecks.io should show the check as up.

## 10. Lock down the console (optional)

If you always connect from the same address or through a VPN, allow only that:

```
HS_CONTROL_ALLOW_CIDRS=<your-ip>/32
```

then `docker compose --env-file .env up -d`. Decoys stay reachable from everywhere. If you lock
yourself out, SSH in, empty the line and apply again.

## 11. First steps in the console

1. Sign in and add a passkey when asked (your laptop's fingerprint or a phone). Add a second one under
   Account so a lost device does not lock you out.
2. Overview, System health: every check should be OK.
3. Tenants, add one for yourself; Projects and decoys, add a project and a decoy; open the decoy's URL
   from your phone. The hit appears under Events within seconds.
4. Alerts: add where detections should go (email, Slack, a webhook).

## Keeping it healthy

| When | What |
|---|---|
| A notice arrives | `docker compose --env-file .env ps` and `logs <service>` on the server |
| Monthly | Restore drill with a downloaded backup (docs/backup-and-restore.md, "Restoring") |
| New release | `~/honeyshield/install.sh --upgrade --version X.Y.Z` (keeps data and settings) |
| Monthly | `sudo apt-get update && sudo apt-get -y upgrade`, reboot if the kernel changed |

Certificates renew by themselves, and the watchdog warns 14 days before one would expire.
