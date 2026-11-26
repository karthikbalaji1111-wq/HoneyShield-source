# DNS decoys

A DNS decoy is a host name, such as `k2m7q4xw3ra5tbnp6yzc8dhv2e.dns.example.com`, that reports every
lookup. Plant it where only an intruder would use it, for example:

* a database host in a config file
* an SSH `HostName`
* a backup script
* an internal wiki page

When someone resolves it, their resolver asks HoneyShield's name server, and the query becomes a
detection event. This needs no code where the name is planted. It also works from networks that
block everything except DNS.

## What a hit shows, and what it does not

| Recorded | Meaning |
|---|---|
| Source address | The **resolver** that asked: the user's own, their ISP's or a public one (8.8.8.8, 1.1.1.1). It is rarely the machine that typed the name. |
| Client subnet | Some public resolvers add the user's network (EDNS client subnet, e.g. `198.51.100.0/24`). It is stored when sent. |
| Name | The full name looked up. Anything in front of the decoy is kept: `laptop-7.<decoy>` shows which machine fired it. |
| Query type, transport, time | As the name server received them. |

Things to expect when you read the events:

* A single lookup can produce more than one event. Resolvers ask for A and AAAA, retry over TCP, and
  with QNAME minimisation ask for the shorter name first. Identical retransmissions within 5 seconds
  are merged.
* A lookup answered from a resolver's cache never reaches HoneyShield. Answers carry a 30-second
  TTL (`DNS_TTL`), so repeated use soon shows again.
* Security products and mail filters sometimes resolve names they see in documents. Triage those
  the way you would a crawler following a hidden link.

Events are `PUBLIC_INGEST` (HoneyShield's own server saw the query) and HIGH severity.

## How it works

```
resolver ──UDP/TCP 53──► dns service (no database access)
                           │ appends each decoy lookup to its spool volume
                           ▼
                         backend /internal/v1/dns-hits (signed, internal network only)
                           │ checks the name is in DNS_TOKEN_ZONE and belongs to a DNS decoy
                           ▼
                         detection event → evidence chain → alerts
```

* **Same answer for every name.** Every name in the zone gets the same answer, whether or not it
  is a decoy (`DNS_ANSWER_IPV4` / `_IPV6`, or no data). The server cannot be used to test names.
* **Not an open resolver.** Other zones are refused (`REFUSED`), and nothing is resolved
  recursively.
* **Per-address rate limit.** Each source address is limited (`DNS_RATE_PER_SECOND`, default 50),
  so the server is a poor reflector and a flood cannot fill the spool. Answers are small: no
  amplification.
* **Hits survive outages.** A hit is written to the spool (64 MB cap) before it is sent. The spool
  position moves only after the backend accepts a batch, so hits survive a backend outage and
  restarts.
* **Monitoring.** The listener sends a heartbeat every minute. The watchdog warns when it stops
  (`DNS decoys` check).

## Set it up (Docker Compose)

You need a domain whose DNS you can edit, and a server reachable on **port 53, UDP and TCP**. Free
dynamic-DNS names such as DuckDNS cannot delegate a zone. Use a domain you own; a cheap one is
enough.

1. **Choose a zone** under your domain, e.g. `dns.example.com`. Use something unremarkable: the
   zone is part of every decoy name.
2. **Delegate it** at your domain's DNS provider with two records:

   ```
   dns.example.com.       NS   ns1.dns.example.com.
   ns1.dns.example.com.   A    <server public IPv4>
   ```

3. **Open port 53** for UDP and TCP from anywhere in the cloud firewall (for Azure, the network
   security group).
4. **Configure** the env file:

   ```
   COMPOSE_PROFILES=dns
   DNS_TOKEN_ZONE=dns.example.com
   DNS_ANSWER_IPV4=<server public IPv4>
   HS_DNS_BIND=<server private IPv4>     # see "Port 53 on Ubuntu"
   ```

5. **Start it:**

   ```bash
   docker compose --env-file .env up -d
   ```

6. **Check** that the server answers directly, then through the public DNS:

   ```bash
   dig @<server public IPv4> dns.example.com SOA +short
   ```

   ```bash
   dig ns1.dns.example.com +short
   ```

7. **Generate a DNS decoy** in the console (Projects, then the project, then **DNS host name**).
   Look its name up with `dig <name>`. The event appears within a few seconds.

### Port 53 on Ubuntu

`systemd-resolved` listens on `127.0.0.53:53`, so publishing `0.0.0.0:53` fails with "address
already in use". Set `HS_DNS_BIND` to the server's private address (`ip -4 addr`; on Azure the NIC
address, e.g. `10.0.0.4`). Alternatively, turn off the stub listener (`DNSStubListener=no` in
`/etc/systemd/resolved.conf`, then `systemctl restart systemd-resolved`).

## Kubernetes

```yaml
dnsDecoys:
  enabled: true
  zone: dns.example.com
  answerIpv4: <edge or dns load balancer address>
```

The chart creates a `LoadBalancer` Service on port 53 with UDP and TCP and `externalTrafficPolicy:
Local`, which keeps resolver addresses. Delegate the zone to that Service's address. Mixed-protocol
load balancers need Kubernetes 1.26 or later and a provider that supports them.

## Limits

* The resolver is the only address HoneyShield can see. Attributing a hit to a person or a machine
  needs the tag in front of the name or other evidence.
* A name that is copied but never resolved is not detected.
* One listener per installation. Run a second name server, with its own delegation, only if you
  need DNS redundancy.
