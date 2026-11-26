# Cloud canaries (AWS access keys)

An AWS key decoy is a **real** AWS access key that can do nothing. HoneyShield creates it, you plant
it, and any use of it is recorded:

* in any region HoneyShield watches
* from any tool: the AWS CLI, an SDK, a key-checking script, a cloud-pentest framework

Detection needs nothing where the key is planted. Plant it in places like these:

* `~/.aws/credentials`
* CI variables
* `.env` files
* backups
* repositories

## What a hit shows

AWS CloudTrail records every API call made with the key. Calls are denied, except
`sts:GetCallerIdentity`, which AWS allows for every identity. The cloud-canary worker reads those
records and stores each one as a CRITICAL event with provenance `CLOUD_AUDIT`, meaning AWS recorded
it, not HoneyShield. Each event carries:

| Field | From CloudTrail |
|---|---|
| Source address | `sourceIPAddress`: the caller's address. If AWS called on someone's behalf, the address is `0.0.0.0` and the service name is kept as `aws-source-address`. |
| User agent | `userAgent`, e.g. `aws-cli/2.17.0 ...` or `Boto3/1.35.0 ...` |
| Request | `<service>/<API>`, e.g. `sts.amazonaws.com/GetCallerIdentity` |
| Context | Region, error code (normally `AccessDenied`), read-only flag and the CloudTrail event ID |

**Delay.** CloudTrail delivers events up to about 15 minutes after the call, and the worker polls
every 5 minutes (`AWS_CANARY_POLL_SECONDS`). Expect an alert within about 20 minutes. This is a
tripwire, not a block: the key can do nothing in the meantime.

**What the attacker learns.** `GetCallerIdentity` returns the account ID and the user's ARN. The
user name looks like an ordinary service account (`svc-deploy-3fa1c0...`, `ci-runner-...`), and
the path is `AWS_CANARY_IAM_PATH`. Tools that flag the well-known shared canary accounts do not
recognise your own account. Use a dedicated AWS account anyway (below).

## How it works

1. **Generate.** Generating an AWS key decoy (console or API) picks the IAM user name and marks the
   decoy `provisioning`.
2. **Provision.** Within about 10 seconds the cloud-canary worker:
   * creates the user under `AWS_CANARY_IAM_PATH`, with the deny-all permissions boundary and a
     `honeyshield-decoy` tag;
   * attaches a deny-all inline policy;
   * creates one access key.

   The console then shows a `~/.aws/credentials` block and environment variables to copy.
3. **Watch.** Every poll reads CloudTrail event history in each watched region for each active
   key (the `AccessKeyId` lookup). Polls overlap, because CloudTrail is late. Each CloudTrail event
   is stored once, keyed by its event ID.
4. **Clean up.** Revoking or rotating the decoy makes the worker delete the IAM user and its key.
   The worker only ever deletes or reuses a user that carries its own tag, and its IAM policy
   reaches only users under the canary path.

Only the `cloud-canary` service holds AWS credentials and talks to AWS. The API has no internet
access and never sees them. The watchdog reports when the worker stops reporting, when AWS refuses
its requests, and when a region cannot be read (`Cloud canaries` check).

## Set it up

### 1. An AWS account for canaries

Use an account of its own, not your production account. With AWS Organizations, create one in a
minute ("Add an AWS account"). The account ID is visible to whoever uses a key, and the account
holds nothing else.

CloudTrail **event history** (90 days of management events, free) is on in every account. No trail
needs to be created.

### 2. The boundary policy

Create a customer-managed policy named `honeyshield-canary-boundary`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Deny", "Action": "*", "Resource": "*" }]
}
```

Every canary user gets it as its permissions boundary. A user with a deny-all boundary can do
nothing, whatever policies are later attached to it.

### 3. The worker's IAM user

Create an IAM user `honeyshield-canary-worker`. Do not put it under the canary path. Give it this
inline policy, with `ACCOUNT` replaced and the path matching `AWS_CANARY_IAM_PATH`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateCanariesOnlyWithTheBoundary",
      "Effect": "Allow",
      "Action": ["iam:CreateUser", "iam:PutUserPolicy"],
      "Resource": "arn:aws:iam::ACCOUNT:user/svc/*",
      "Condition": { "StringEquals": {
        "iam:PermissionsBoundary": "arn:aws:iam::ACCOUNT:policy/honeyshield-canary-boundary" } }
    },
    {
      "Sid": "ManageCanaries",
      "Effect": "Allow",
      "Action": ["iam:TagUser", "iam:ListUserTags", "iam:CreateAccessKey", "iam:ListAccessKeys",
                 "iam:DeleteAccessKey", "iam:DeleteUserPolicy", "iam:DeleteUser"],
      "Resource": "arn:aws:iam::ACCOUNT:user/svc/*"
    },
    { "Sid": "ReadCloudTrail", "Effect": "Allow", "Action": "cloudtrail:LookupEvents", "Resource": "*" }
  ]
}
```

With the boundary condition, even a stolen worker key can only create users that can do nothing.
It cannot touch any other user and cannot remove a boundary. Create an access key for this user.

### 4. Configure and start

In the env file:

```
COMPOSE_PROFILES=cloud-canary            # add dns too if you use DNS decoys: dns,cloud-canary
AWS_CANARY_ENABLED=true
AWS_CANARY_ACCESS_KEY_ID=<worker access key id>
AWS_CANARY_SECRET_ACCESS_KEY=<worker secret>
AWS_CANARY_PERMISSIONS_BOUNDARY=arn:aws:iam::ACCOUNT:policy/honeyshield-canary-boundary
```

Then:

```bash
docker compose --env-file .env up -d
```

The worker logs `Cloud canaries in AWS account ACCOUNT, watching 17 region(s)`.

### 5. Test it

Generate an **AWS access key** decoy in the console and wait for the credentials. Then, on any
machine:

```bash
AWS_ACCESS_KEY_ID=<decoy key id> AWS_SECRET_ACCESS_KEY=<decoy secret> aws sts get-caller-identity
```

The event appears within about 20 minutes.

### Kubernetes

```yaml
cloudCanary:
  enabled: true
  accessKeyId: <worker access key id>
  permissionsBoundary: arn:aws:iam::ACCOUNT:policy/honeyshield-canary-boundary
```

Add `AWS_CANARY_SECRET_ACCESS_KEY` to the Secret.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `AWS_CANARY_IAM_PATH` | `/svc/` | Path of the canary users (part of their ARN). The worker's policy must match it. |
| `AWS_CANARY_REGIONS` | the 17 regions enabled in every account | Regions whose CloudTrail is read. Add opt-in regions you have enabled. |
| `AWS_CANARY_POLL_SECONDS` | 300 | How often CloudTrail is read. LookupEvents allows 2 requests per second per region. |
| `AWS_CANARY_LOOKBACK_MINUTES` | 30 | How far each poll reads back, to cover CloudTrail's delivery delay. |

## Planting a key in public

AWS and GitHub scan public repositories for AWS keys. If a canary key is published, AWS attaches its
`AWSCompromisedKeyQuarantine` policy to the user and notifies the account owner. That is expected: the
key stays a canary, and uses are still recorded. Key-harvesting bots often try such keys within
minutes, which is exactly what the decoy is there to catch.

## Limits

* CloudTrail does not log every AWS API. The calls attackers make first (STS, IAM, S3 listing, EC2
  describe calls) are logged.
* Calls in regions that are not watched are missed. Opt-in regions need to be enabled in the
  account and listed.
* The alert is up to about 20 minutes after the call.
* A key copied but never used is not detected.
