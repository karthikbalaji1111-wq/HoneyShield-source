# Active Directory decoys (`AD_ACCOUNT`)

An Active Directory decoy is a domain account nobody uses, with a password nobody knows. Nobody has a
reason to touch it, so whoever does is almost certainly an intruder:

* **Kerberoasting.** By default the account has a service principal name (SPN). Requesting a
  Kerberos service ticket for it (Rubeus, `GetUserSPNs.py`, `Invoke-Kerberoast`) is the first step
  of Kerberoasting.
* **Password spraying and guessing.** Any sign-in with the account fails, whether by Kerberos, NTLM,
  interactive or network logon, and every failure is reported.
* **Use of a stolen password.** A successful sign-in should be impossible, because nobody knows the
  password. If one happens, treat the domain as compromised.
* **Directory enumeration (opt-in).** With read auditing on, every read of the account object is
  reported. BloodHound, PowerView and `ldapsearch` read every account.

The account is in no groups and can do nothing.

## How it works

```
 HoneyShield                         your network
 ───────────                         ────────────
 decoy: svc_sqlbackup  ◄── signed ── HoneyShield-DCCollector.ps1  (scheduled task, every minute,
 (AD_ACCOUNT)              HTTPS      on every domain controller)
                                         │ reads the Security log for events naming the decoy
                                         ▼
                                      4768 4769 4771 4776 4624 4625 (4662)
```

HoneyShield never connects into your network, and it never sees directory credentials. Each domain
controller runs the collector. It fetches the list of decoy accounts, reads new Security log events
that name one of them, and reports each event. It reports through the signed channel that
[customer integrations](customer-integrations.md) use: an HMAC-signed request with a timestamp,
made with a per-project credential that can only report. Only events about decoy accounts leave
the controller.

## Setting one up

1. **Integration credential.** In the console, go to *Integrations* and create a credential for
   the project. Keep the secret: HoneyShield shows it once. One credential can serve every domain
   controller. Create one per controller if you want to revoke them one at a time.
2. **Generate the decoy.** In *Projects & decoys*, choose *Active Directory account*. You can enter
   an account name; otherwise HoneyShield picks a plausible service-account profile. The profile
   includes a name, a description and an SPN, and an account name you enter gets a matching SPN.
   Choose *Also reads of the account* only if you want read auditing (see below).
3. **Create the account.** Download *Setup script (run once)*. Run it as a Domain Admin on a
   domain controller, or on any machine with the ActiveDirectory module:

   ```powershell
   .\New-HoneyShieldDecoy-svc_sqlbackup.ps1 -Path 'OU=Service Accounts,DC=corp,DC=example,DC=com'
   ```

   Put the account where your real service accounts are. `-WhatIf` shows what would happen. The
   script:
   * generates a 68-character random password on the machine, which is never shown, saved or sent;
   * creates the account with that password, enabled and with a password that never expires;
   * adds the SPN, with your domain's DNS name appended;
   * sets `adminCount=1`, which enumeration tools highlight and which grants nothing;
   * adds the read audit rule, if you chose read auditing.

   The script refuses to run if the account name or the SPN already exists.
4. **Install the collector on every domain controller.** Download *DC collector*; it is the same
   file for every AD decoy. As an administrator, on each domain controller, run:

   ```powershell
   .\HoneyShield-DCCollector.ps1 -Install -IntegrationId hsi_0123456789abcdef01234567
   ```

   * It asks for the secret. The secret is not put on the command line, so it stays out of the
     shell history.
   * It stores the secret under `C:\ProgramData\HoneyShield`, encrypted with DPAPI. The folder can be
     read only by SYSTEM and Administrators.
   * It checks that HoneyShield accepts the credential.
   * It registers the scheduled task *HoneyShield DC Collector*, which runs as SYSTEM every minute.

   The ingest host is already filled in from `PUBLIC_INGEST_BASE_URL`. If it is not, pass `-BaseUrl`.
5. **Check it.** Run `.\HoneyShield-DCCollector.ps1 -Test`. It shows:
   * the decoys this controller watches;
   * the audit policy;
   * the scheduled task's last run;
   * the end of the collector's log.

   Kerberos events are only logged by the domain controller that handled the request, so a
   controller without the collector is a blind spot.

Requirements: Windows Server 2016 or later, with Windows PowerShell 5.1 or PowerShell 7. If Group
Policy enforces a script execution policy, sign the collector or allow it.

### Audit policy

The domain controllers must log these subcategories, normally set through the Default Domain
Controllers Policy. Most environments already log them.

| Subcategory | Setting | Events |
|---|---|---|
| Account Logon › Credential Validation | Success and Failure | 4776 |
| Account Logon › Kerberos Authentication Service | Success and Failure | 4768, 4771 |
| Account Logon › Kerberos Service Ticket Operations | Success and Failure | 4769 |
| Logon/Logoff › Logon | Success and Failure | 4624, 4625 |
| DS Access › Directory Service Access | Success (read auditing only) | 4662 |

## What a hit shows

Every event has provenance `CUSTOMER_HOOK`, because your domain controller asserted it. The event's
kind, severity and ATT&CK technique are decided by HoneyShield from the Windows event ID, never by
the reporter.

| Windows event | Request | Severity | ATT&CK |
|---|---|---|---|
| 4769 service ticket for the decoy's SPN | `AD ad/service-ticket` | CRITICAL | T1558.003 Kerberoasting |
| 4771 Kerberos pre-authentication failed | `AD ad/preauth-failure` | CRITICAL | T1110 Brute Force |
| 4768 ticket-granting ticket refused | `AD ad/tgt-failure` | CRITICAL | T1110 |
| 4625 logon failed | `AD ad/logon-failure` | CRITICAL | T1110 |
| 4776 NTLM validation failed | `AD ad/ntlm-failure` | CRITICAL | T1110 |
| 4768 granted, 4776 validated, 4624 logon | `AD ad/tgt-issued`, `ad/ntlm-validated`, `ad/logon-success` | CRITICAL | T1078.002 Domain Accounts |
| 4662 the account object was read | `AD ad/object-read` | HIGH | T1087.002 Account Discovery: Domain Account |

The source address is the event's `IpAddress`, so `::ffff:10.0.0.5` is stored as `10.0.0.5`. When
the event has no address (4776 names only a workstation), it is stored as `0.0.0.0`. The event detail
(*Directory event* in the console) carries:

* `ad-event-id`
* `ad-domain-controller`
* `ad-target`: the name as the client typed it
* `ad-workstation`
* `ad-actor`: who requested the ticket (4769) or read the object (4662)
* `ad-status`: the Kerberos or NTSTATUS failure code
* `ad-logon-type`
* `ad-ticket-encryption`: `0x17` is RC4, which Kerberoasting tools ask for
* `ad-record-id`: the event's record number in that controller's Security log

## Read auditing (enumeration)

With read auditing, the setup script adds an audit rule: *Everyone, Read Property, Success*. Every
read of the decoy object then logs event 4662. Enumeration tools read every account, so this
catches BloodHound-style collection even when the attacker never touches the decoy afterwards.
It is off by default, because legitimate software reads every account too:

* Entra Connect / Azure AD Connect
* identity governance and HR sync tools
* backup and inventory products
* some security scanners

Turn it on for one decoy and see what reports before relying on it.

The collector ignores reads by SYSTEM and by the domain controller's own computer account. The
collector itself looks the account up once, as the computer account, and caches its GUID. A
consequence: an attacker who already runs as SYSTEM on a domain controller is not reported by
4662. Their sign-in and ticket events still are.

`-Test` does not look the accounts up: that read would raise an event.

## Not detected

* Activity handled by a domain controller without the collector, or without the audit policy.
* Enumeration, when read auditing is off.
* An attacker who sees the account and leaves it alone.
* Events beyond 500 per decoy per minute on one controller. The collector logs that it skipped them.
  HoneyShield stores at most 60 a minute for one decoy and source, and audits the excess
  (`DETECTION_HITS_SUPPRESSED`).
* A client that typed the account name in mixed case. Event-log queries compare case-sensitively.
  The collector matches the name as created, in lower case and in upper case, which are the forms
  that spraying tools and ticket requests use.

## Rotate, retire, remove

* **Rotate** gives the decoy a new id and keeps the same account and settings. Nothing changes in
  Active Directory. The collector picks up the new id from the manifest within a minute.
* **Revoke** retires the decoy. It stays in the collector's manifest: an account that still exists
  is still worth an alert. To remove it, run the setup script with `-Remove`, which asks before
  deleting.
* **Uninstall the collector** with `.\HoneyShield-DCCollector.ps1 -Uninstall`, then revoke the
  integration credential in HoneyShield.

## The wire contract

The collector follows [customer integrations](customer-integrations.md#directory-decoys). Any
other collector can follow it as well, such as a SIEM rule or a Windows Event Forwarding
subscriber.
