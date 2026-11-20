# Security policy

HoneyShield records evidence of intrusions, so its own security matters more than most software's.
Thank you for helping keep it and its users safe.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a
vulnerability**. Only the maintainer sees the report. Do not send exploit details through any
public channel.

Please include:

* what is affected (component, endpoint, version or commit) and the impact you see;
* steps to reproduce, or a proof of concept against your own deployment;
* whether you believe it is being exploited.

## What to expect

* An acknowledgement within **3 working days**.
* An initial assessment (accepted or not, and severity) within **10 working days**.
* Updates at least every 14 days until it is resolved, and credit in the advisory if you want it.
* A fix released before details are published. We aim to publish within 90 days of the report and
  will agree a date with you.

## Scope

In scope: the backend API and workers, the operator console, the edge configuration, the Helm chart
and Compose files, the customer integration hook, and the evidence/audit integrity mechanisms
(hash chains, checkpoints, retention archives).

Out of scope: findings that need an already compromised host or database superuser (the evidence
chains are designed to *detect* such tampering, not prevent it; see `docs/evidence-integrity.md`),
denial of service by volume alone, missing hardening that has no demonstrated impact, and
vulnerabilities in third-party services you configure (identity provider, mail server, SIEM, S3).

## Testing rules

Test only against a deployment you own or are authorised to test. Do not access, change or delete
other people's data, and stop and report as soon as you have shown the issue.

## Supported versions

Security fixes are made on `main` and released as new images; run the latest release. Deployment
and upgrade procedures are in `docs/deployment-guide.md` and `docs/kubernetes.md`.
