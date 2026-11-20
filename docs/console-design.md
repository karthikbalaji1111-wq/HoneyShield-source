# Operator console: design system

The console (`frontend/console`: `index.html`, `app.css`, `app.js`) is plain HTML, CSS and JavaScript
served by the edge under a strict Content-Security-Policy (`script-src 'self'; style-src 'self'`).
This page records the design decisions so changes stay consistent.

## Design read

| | |
|---|---|
| Artifact | Operational security console: detection overview, evidence log, administration |
| Audience | SOC analysts and tenant administrators, long sessions on laptops and large monitors |
| Visual language | Instrument panel: graphite frame, warm neutral surfaces, hairline structure, one accent |
| Mode | Redesign, preserve: navigation, routes, element ids, form field names and copy are contracts |
| Dials (1-10) | variance 2 · motion 2 · density 7 · asset dependence 2 · brand fidelity 8 |

## Tokens (all in `app.css` `:root`, redefined for dark mode)

* **Frame:** graphite `--frame` (app bar + navigation) in both themes; the product's recognisable shell.
* **Accent:** honey amber `--honey` (the logo colour) only for the mark, the active location
  (3 px marker + icon) and focus rings. Never for body backgrounds or decoration.
* **Primary action:** ink (`--action`), not a hue. Destructive actions: red text on a neutral button.
* **Severity** is the only loud colour. Text colours (`--crit --high --warn`) meet WCAG AA 4.5:1 on
  every surface in both themes; chart fills (`--fill-*`) are a separate area scale:
  critical red, high orange, medium amber, low warm grey.
* **Status** (Active, Delivered, Revoked) is quiet: a 6 px dot and coloured text, no pill.
* **Provenance** (`PUBLIC_INGEST`, `CUSTOMER_HOOK`, `MANUAL`, `LEGACY_UNVERIFIED`) is plain small
  capitals; only asserted sources are tinted so analysts weigh them.
* **Type:** the platform UI face (`--sans`): SF Pro on Apple devices, Segoe UI Variable on Windows.
  Licensed with the operating system, so never bundled or fetched. SF Mono (`--mono`) only for
  identifiers, addresses, paths and keys, where `0/O` and `l/1` must be distinguishable.
  Figures use tabular lining numerals so columns line up.
* **Spacing** on a 4 px grid (4 8 12 16 24 32 48). **Radius:** 3 tags, 5 controls, 7 surfaces.
* **Elevation:** hairlines; one barely-there shadow on light surfaces, none in dark mode. Only the
  toast floats.
* **Motion:** 120 ms ease-out for state changes; a short highlight when a live event arrives;
  everything off under `prefers-reduced-motion`.

## Patterns

* **Stat strip:** one surface divided by hairlines, never four floating cards. Each figure has a
  context line (all time, yesterday, window).
* **Detections chart:** HTML bars sized through the CSSOM (allowed by `style-src 'self'`; no style
  attributes), stacked by severity, today emphasised, a full text alternative per bar. Data:
  `GET /api/v1/detection-events/activity`, served from trigger-maintained daily totals.
* **Tables:** numbers right-aligned (`num: true` in `table()`), identifiers monospace and truncated
  with the full value on hover, row actions pinned to the right edge of wide tables.
* **Timestamps:** `YYYY-MM-DD HH:MM:SS` in local time; the hover text carries the UTC offset and the
  exact ISO value. Locale formats were ambiguous between day and month.
* **Failure states:** each overview part loads independently; a failed part says what happened
  (timeout versus not loaded) and that event lists and counts are unaffected.
* **Live feed:** reconnects with exponential backoff and jitter (5 s doubling to 60 s).
* **Admin pages:** forms that need explaining use labelled fields (`.form-grid`) with a hint that
  follows the choice (alert address formats); system administrators pick a tenant from a list.
  Opaque ids sit under a readable name (`twoLine`), never alone. Audit types and chain-failure
  kinds are shown in words with the code underneath.
* **Evidence:** a verdict (intact / failed) first, then the head sequence and hash to compare with
  an exported checkpoint (one-click copy), then each failure explained. Alert deliveries link to the
  event they reported (`GET /api/v1/detection-events/{id}`), and the event panel's pivot works from
  any page.
* **Decoys:** named by what they are ("Fake API key", not `API_KEY`), sorted so the ones that have
  fired come first, with when each last fired (a link to that decoy's events, shown as a removable
  filter chip that also applies to the CSV export); options that only apply to one type (key style)
  appear only for it.
* **People and tenants:** adding a user never asks the admin for a password: the console sets a
  random one nobody keeps and issues a one-time set-up link. Role changes, deactivation and tenant
  deactivation say what happens to sessions and evidence; deactivating a tenant needs its slug typed.
* **One-time secrets:** integration secrets, webhook signing secrets and reset links always come
  with a copy button and say they are shown once.
* **Theme:** follows the system; the toggle cycles system, light, dark and is remembered per browser.

## Guard rails (automated)

`backend/tests/deployment/test_console_contract.py` fails the build if an element id the script
uses is missing or duplicated, if markup would be blocked by the CSP (inline scripts, style blocks,
style attributes, inline handlers), if anything is loaded from another origin, if `app.js` uses an
HTML sink (`innerHTML`, `insertAdjacentHTML`, `document.write`, `eval`), if the session token could
reach a URL or `localStorage`, or if a colour token lacks a dark-mode value. It also scans the backend: every audit event type it
records must be in the console's audit filter, and every chain-failure kind must have an explanation.

## Accessibility audit (axe-core 4.14.1, 2026-11-18)

WCAG 2.0/2.1/2.2 A and AA plus axe best practices, run in the browser against every signed-in view
(with the event panel open, the add-user form open and an evidence verification shown), in light and
dark themes, at 1360 px and 390 px, and on the sign-in and forgot-password pages. Found and fixed: a
*serious* label-in-name failure (WCAG 2.5.3: a decoy's "last triggered" link and a delivery's event
link were announced with words that were not their visible text), empty headers on action columns,
and the event panel using `role="dialog"` on an `<aside>`. Result after the fixes: **0 violations**
in every view and theme, no horizontal page scroll at phone width. axe checks only what can be
tested automatically; a screen-reader walkthrough is still worth doing before a public launch.

## Avoided on purpose

Gradients, glows and coloured shadows; emoji; rounded cards with a coloured left border; pill
badges everywhere; uppercase eyebrows above every heading; fabricated figures (the chart shows only
real data and says so when it cannot).
