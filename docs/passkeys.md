# Passkeys and the operator allowlist

## Why passkeys

An authenticator app's six-digit code can be phished. A fake sign-in page asks for the password and
the code, and replays both to the real site within the code's 30 seconds. A passkey cannot be used
that way: the browser only lets it sign for the site it was created on, so a look-alike domain gets
nothing it can use.

## How it works in HoneyShield

* A passkey is a second factor. Signing in is password plus passkey (fingerprint, face, device PIN or
  a security key).
* Add passkeys under Account, Passkeys. Add two, for example laptop and phone, so losing one does not
  lock you out.
* An account with a passkey counts as having MFA, including for roles where MFA is required. When a
  role requires MFA, the set-up screen offers a passkey first.
* With at least one passkey you can turn the authenticator app off (Account, Two-factor
  authentication). That leaves only the phishing-resistant factor. Recovery codes belong to the
  authenticator app and go with it, so keep two passkeys.
* Lost every passkey: another administrator resets your MFA (Users, Reset MFA), which removes
  passkeys and the authenticator app and signs you out everywhere.
* A passkey is bound to the operator host name (`HS_CONTROL_HOST`). Moving the console to another
  host name means adding passkeys again. `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGINS` override the defaults.

What is checked on every sign-in: the browser's origin and the host binding, that a person was
present, the signature with the stored public key, a single-use challenge that expires after five
minutes, and the signature counter. A counter that goes backwards suggests a cloned key and is
refused and audited (`PASSKEY_CLONE_SUSPECTED`). Only public keys are stored.

## Allowlist for the operator host

`HS_CONTROL_ALLOW_CIDRS` (Compose) or `controlAllowCidrs` (Helm) limits the console and API to the
addresses you list, for example your office and VPN:

```
HS_CONTROL_ALLOW_CIDRS=203.0.113.7/32,198.51.100.0/24
```

Everyone else gets 403 from the edge, and the backend checks the same list again. Decoys on the
ingest host stay reachable from everywhere, as they must. If your home address changes often, use a
VPN (WireGuard or Tailscale) and allow only the VPN's range. If you lock yourself out, edit `.env` on
the server and run `docker compose --env-file .env up -d`.
