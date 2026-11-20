# Single sign-on (OpenID Connect)

HoneyShield signs operators in through any OpenID Connect provider: Okta, Microsoft Entra ID,
Google Workspace, Keycloak, Auth0 or Ping. Password sign-in keeps working alongside SSO.

## Set up

1. At the IdP, create a **web application** (confidential client):
   * grant type: authorization code (PKCE is used automatically);
   * redirect URI: `https://<control host>/auth/oidc/callback`;
   * scopes: `openid email profile`.
2. Set the environment and restart the backend:

   | Variable | Example |
   |---|---|
   | `OIDC_ISSUER` | `https://acme.okta.com`, `https://login.microsoftonline.com/<tenant-id>/v2.0`, `https://accounts.google.com` |
   | `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | from the IdP |
   | `OIDC_REDIRECT_URI` | `https://app.example.com/auth/oidc/callback` |
   | `OIDC_DISPLAY_NAME` | `Acme SSO` (button text) |

3. Create the HoneyShield users (or keep the existing ones) with the **same email** as at the
   IdP. SSO never creates accounts or changes roles; access is still granted in HoneyShield.

The sign-in page then shows "Sign in with <display name>".

**Network access.** The API must reach the IdP over HTTPS, for discovery, signing keys and code
exchange. By default the API has no internet egress, so with SSO on:
* **Compose:** add `-f docker-compose.sso.yml`. It puts the API on the egress network.
* **Kubernetes:** set `backend.extraEnv.OIDC_ISSUER`. The chart then allows the API HTTPS egress,
  with link-local and metadata addresses excluded.

Without this, sign-in fails closed with `idp_unreachable`. For an IdP with a private CA, mount the
CA and set `OIDC_CA_FILE`.

**Verified on the Compose stack (2026-11-17)** against a standalone OIDC provider container (TLS,
private CA, RS256, PKCE enforced):
* sign-in through the public edge, IdP, callback and one-time code exchange;
* the flow cookie was HttpOnly, Secure, SameSite=Lax and path-scoped;
* the user was signed in with MFA satisfied from the IdP's `amr`;
* code replay was refused;
* without the egress file, sign-in failed with `idp_unreachable`.

## Provider notes

* **Microsoft Entra ID:** ID tokens often have no `email`/`email_verified`. Use
  `OIDC_EMAIL_CLAIM=preferred_username` and `OIDC_REQUIRE_EMAIL_VERIFIED=false`, and make sure
  every UPN equals the HoneyShield email. Add the `email` optional claim if you can.
* **Google Workspace:** `email` and `email_verified` are present; restrict the OAuth client to
  your organisation (internal app).
* **Okta / Keycloak / Auth0:** defaults work.

## MFA

`OIDC_MFA=amr_claim` (default): an SSO session counts as MFA only if the ID token's `amr` lists a
second factor (`mfa`, `otp`, `hwk`, `swk`, `fpt`, `face`, ...). Otherwise:
* a user with HoneyShield MFA enabled cannot use SSO (`mfa_required`);
* an administrator role that must use MFA gets the enrolment-only session.

If your IdP enforces MFA for this application, set `OIDC_MFA=trust_idp`. Every SSO session then
counts as MFA.

## Security properties

* **Code flow with PKCE (S256).** `state`, `nonce` and the PKCE verifier travel in an HMAC-signed,
  HttpOnly, SameSite=Lax cookie that lasts 10 minutes and is scoped to `/auth/oidc`. A callback
  without the cookie that started the flow is refused, which stops login CSRF. No server-side
  state is kept, so any replica can finish a flow.
* **ID token checks.** The signature is verified against the IdP's JWKS: RS/PS/ES algorithms
  only, never HS* or `none`. An unknown `kid` refetches the keys at most every 30 s, which covers
  key rotation. `iss`, `aud`, `azp` (with several audiences), `exp`, `iat` and `nonce` are all
  checked, with 60 s leeway.
* **Hand-off to the console.** The callback redirects with a **one-time code** (stored hashed,
  valid 60 s) that the console exchanges for a session. The session token never appears in a URL,
  in history or in `Referer`.
* **Errors.** The browser only sees a fixed error identifier; IdP text is never reflected. Every
  failure is audited as `AUTH_SSO_FAILURE` with the reason, and every success as
  `AUTH_LOGIN_SUCCESS` with `method: oidc` and the IdP subject.
* **Tests.** `tests/auth/test_oidc_sso.py` runs the real HTTP flow against a local IdP. It covers
  forged and invalid tokens (wrong audience, issuer or key, HS256 signed with the client secret,
  `alg: none`, expired, nonce mismatch), state and cookie tampering, PKCE, key rotation, ES256,
  MFA mapping and replayed or expired hand-off codes.
