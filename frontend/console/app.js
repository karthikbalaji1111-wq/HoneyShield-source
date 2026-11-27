// HoneyShield operator console. Same-origin with the API; no external code.
// Security notes:
//  * Every value from the API is rendered with textContent (never innerHTML): event fields such
//    as user agents and paths are attacker-controlled.
//  * The access token lives in sessionStorage (cleared when the tab closes) and is sent only in
//    the Authorization header / the WebSocket auth message, never in a URL.
"use strict";

const state = { token: null, me: null, project: null, eventsCursor: null, auditCursor: null, ws: null, wsRetryMs: 0 };
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

// ------------------------------------------------------------------ helpers
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

// Messages appear as a toast (click to dismiss); errors stay longer than confirmations.
let toastTimer = null;
function status(message, isError = false) {
  const box = $("#status");
  clearTimeout(toastTimer);
  box.textContent = message || "";
  box.className = "toast" + (isError ? " error" : "");
  box.hidden = !message;
  if (message) toastTimer = setTimeout(() => { box.hidden = true; }, isError ? 9000 : 5000);
}

// Thin progress bar while requests are in flight.
let busyCount = 0;
function busy(delta) {
  busyCount = Math.max(0, busyCount + delta);
  $("#busy").classList.toggle("on", busyCount > 0);
}

const EMPTY_ICON_PATHS = ["M12 2.5 20.5 7.5v9L12 21.5l-8.5-5v-9z", "M3.5 7.5 12 12.5l8.5-5M12 12.5v9"];

// Evidence timestamps: unambiguous YYYY-MM-DD HH:MM:SS in the viewer's local time; the hover
// text carries the UTC offset and the exact ISO value (locale formats confuse day and month).
const pad2 = (n) => String(n).padStart(2, "0");
function fmtTime(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  const text = `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  const off = -d.getTimezoneOffset();
  const zone = `UTC${off >= 0 ? "+" : "-"}${pad2(Math.floor(Math.abs(off) / 60))}:${pad2(Math.abs(off) % 60)}`;
  return el("time", { datetime: d.toISOString(), title: `${zone} · ${d.toISOString()}` }, text);
}

function emptyState(title, hint) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const d of EMPTY_ICON_PATHS) {
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return el("div", { class: "empty" }, svg, el("strong", {}, title), hint || "");
}

// Column options: mono (identifiers, attacker-supplied strings), num (right-aligned figures),
// wrap (long prose). A column without a label holds row actions.
// empty: a title, or [title, one line on what to do next].
function table(columns, rows, empty = "Nothing here yet", opts = {}) {
  if (!rows.length) return Array.isArray(empty) ? emptyState(empty[0], empty[1]) : emptyState(empty);
  const cls = (c) => [c.mono ? "mono" : "", c.num ? "num" : "", c.wrap ? "wrap" : "", c.label ? "" : "col-actions"].join(" ").trim();
  return el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, columns.map((c) => el("th", { class: c.label ? (c.num ? "num" : "") : "col-actions" },
      c.label || el("span", { class: "sr-only" }, "Actions"))))),
    el("tbody", {}, rows.map((r) => el("tr", opts.onRow ? {
      class: "clickable", tabindex: "0", "aria-label": opts.rowLabel ? opts.rowLabel(r) : null,
      onclick: (ev) => { if (!ev.target.closest("button, a")) opts.onRow(r, ev.currentTarget); },
      onkeydown: (ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); opts.onRow(r, ev.currentTarget); } },
    } : {}, columns.map((c) => {
      let v = c.render ? c.render(r) : r[c.key];
      // Long identifiers and attacker-supplied strings stay on one line; full value on hover.
      if (c.mono && typeof v === "string" && v) v = el("span", { class: "trunc", title: v }, v);
      return el("td", { class: cls(c) }, v);
    }))))));
}

function badge(text, cls = "") { return el("span", { class: `badge ${cls}` }, text); }

// A name with its identifier underneath, for rows that would otherwise show only an opaque id.
function twoLine(primary, secondary) {
  return el("span", { class: "two-line" }, el("span", { class: "primary", title: typeof primary === "string" ? primary : null }, primary),
    secondary ? el("span", { class: "mono sub-id", title: secondary }, secondary) : null);
}

// System administrators choose a tenant from a list (all pages of it), not by typing a slug.
async function allTenants(refresh = false) {
  if (!state.tenants || refresh) {
    const all = [];
    for (let offset = 0; ; offset += 100) {
      const page = await api("GET", `/api/v1/tenants?active_only=false&limit=100&offset=${offset}`);
      all.push(...page);
      if (page.length < 100) break;
    }
    state.tenants = all;
  }
  return state.tenants;
}

async function fillTenantSelects() {
  if (!isSysAdmin()) return;
  const active = (await allTenants()).filter((t) => t.is_active);
  for (const sel of $$(".tenant-select")) {
    const keep = sel.value;
    sel.replaceChildren(...active.map((t) => el("option", { value: t.slug }, `${t.name} · ${t.slug}`)));
    if (keep) sel.value = keep;
  }
}

// Operator emails for actor columns; ids are kept for anyone outside the caller's scope.
async function userEmails() {
  if (!state.userEmails) {
    state.userEmails = new Map();
    try { (await api("GET", "/api/v1/users?limit=100")).forEach((u) => state.userEmails.set(u.id, u.email)); } catch {}
  }
  return state.userEmails;
}

// Threat score 0-100: the figure plus a small meter, coloured by band (>= 70 high, >= 40 elevated).
function scoreMeter(score) {
  const v = Math.max(0, Math.min(100, Number(score) || 0));
  const band = v >= 70 ? "bad" : v >= 40 ? "warn" : "";
  const fill = el("span", {});
  fill.style.width = `${v}%`;   // CSSOM, not an inline style attribute: allowed under style-src 'self'
  return el("span", { class: `score ${band}`, title: `Threat score ${v} of 100` },
    el("span", { class: "score-bar", "aria-hidden": "true" }, fill), String(v));
}

const fmtNum = (v) => (v === null || v === undefined || v === "" ? "" : Number(v).toLocaleString());

// ------------------------------------------------------------------ colour theme
// "system" follows the operating system; an explicit choice is remembered in this browser only.
const THEMES = ["system", "light", "dark"];
function applyTheme(theme) {
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
  const b = $("#theme-toggle");
  if (b) { const label = `Colour theme: ${theme}`; b.setAttribute("aria-label", label); b.title = label; }
}
let currentTheme = "system";
try { currentTheme = localStorage.getItem("hs_theme") || "system"; } catch {}
if (!THEMES.includes(currentTheme)) currentTheme = "system";
applyTheme(currentTheme);
$("#theme-toggle").addEventListener("click", () => {
  currentTheme = THEMES[(THEMES.indexOf(currentTheme) + 1) % THEMES.length];
  try { localStorage.setItem("hs_theme", currentTheme); } catch {}
  applyTheme(currentTheme);
  status(`Theme: ${currentTheme === "system" ? "follow the system" : currentTheme}.`);
});

// opts.credentialCheck: a 401 means "wrong password/code", not "session ended" -- keep the session.
async function api(method, path, body, opts = {}) {
  const headers = { Accept: "application/json" };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let resp;
  busy(1);
  try {
    resp = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body),
                               credentials: "omit", cache: "no-store" });
  } catch (e) {
    status("Network error: the API is unreachable.", true);
    throw e;
  } finally {
    busy(-1);
  }
  if (resp.status === 401 && state.token && !opts.credentialCheck) {
    signOutLocal("Your session ended. Please sign in again.", true);
    throw new Error("unauthorized");
  }
  const text = await resp.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = null; }
  if (!resp.ok) {
    const detail = (data && data.detail) || `HTTP ${resp.status}`;
    const rid = data && data.request_id ? ` (request ${data.request_id})` : "";
    status(`${detail}${rid}`, true);
    throw new Error(detail);
  }
  return data;
}

function isAdmin() { return state.me && (state.me.role === "TENANT_ADMIN" || state.me.role === "SYSTEM_ADMIN"); }
function isSysAdmin() { return state.me && state.me.role === "SYSTEM_ADMIN"; }

// ------------------------------------------------------------------ session
function show(view) {
  $$(".view").forEach((v) => { v.hidden = v.id !== `view-${view}`; });
  $$("#nav button").forEach((b) => {
    const on = b.dataset.view === view;
    b.classList.toggle("active", on);
    if (on) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  const loaders = { overview: loadOverview, tokens: loadProjects, events: () => loadEvents(true),
                    integrations: loadIntegrations, alerts: loadAlerts, audit: () => loadAudit(true),
                    evidence: fillTenantSelects, tenants: loadTenants, users: loadUsers, account: () => Promise.all([renderMfaStatus(), loadPasskeys(), loadKeys()]) };
  if (loaders[view]) loaders[view]().catch(() => {});
  try { sessionStorage.setItem("hs_view", view); } catch {}
}

function applyRole() {
  $$("[data-admin]").forEach((n) => { n.hidden = !isAdmin(); });
  $$("[data-sysadmin]").forEach((n) => { n.hidden = !isSysAdmin(); });
  renderWho(true);
}

const ROLE_NAMES = { SYSTEM_ADMIN: "System admin", TENANT_ADMIN: "Tenant admin", TENANT_USER: "Tenant user" };

function renderWho(withRole) {
  const me = state.me;
  $("#whoami").hidden = !me;
  if (!me) return;
  $("#who-avatar").textContent = (me.email || "?").charAt(0);
  $("#who-email").textContent = me.email;
  const role = ROLE_NAMES[me.role] || me.role;
  $("#who-role").textContent = withRole ? `${role}${me.tenant_slug ? " · " + me.tenant_slug : ""}` : "";
}

function setLayout(signedIn) {
  document.body.classList.toggle("signed-out", !signedIn);
}

async function startSession(token) {
  state.token = token;
  state.me = await api("GET", "/auth/me");
  try { sessionStorage.setItem("hs_token", token); } catch {}
  if (state.me.mfa_enrollment_required) { startEnrolment(true); return; }
  setLayout(true);
  $("#nav").hidden = false;
  applyRole();
  connectLive();
  let view = "overview";
  try { view = sessionStorage.getItem("hs_view") || view; } catch {}
  // Only restore a view this role can open (the tab may have been used by another account).
  const navButton = document.querySelector(`#nav button[data-view="${view}"]`);
  if (!navButton || navButton.hidden) view = "overview";
  show(view);
}

// Everything one account loaded or was shown once. Cleared on sign-out so the next account in the
// same tab never sees it (tenant lists, user emails, set-up links, secrets, verification results).
const ONE_TIME_BOXES = ["#user-created", "#int-secret", "#alert-secret", "#pw-reset-result", "#artifact"];
const ACCOUNT_CONTENT = ["#users-table", "#tenants-table", "#destinations", "#deliveries", "#integrations", "#audit",
                         "#ev-result", "#audit-verify-result", "#projects", "#tokens", "#events", "#keys-table"];
function forgetAccountData() {
  Object.assign(state, { tenants: null, userEmails: null, events: [], eventsCursor: null, auditCursor: null,
                         auditShown: 0, project: null });
  for (const sel of ONE_TIME_BOXES) { const n = $(sel); if (n) { n.replaceChildren(); n.hidden = true; } }
  for (const sel of ACCOUNT_CONTENT) { const n = $(sel); if (n) n.replaceChildren(); }
  $$(".tenant-select").forEach((s) => s.replaceChildren());
  $$("form").forEach((f) => f.reset());
}

function signOutLocal(message, isError = false) {
  state.token = null; state.me = null;
  forgetAccountData();
  try { sessionStorage.removeItem("hs_token"); sessionStorage.removeItem("hs_view"); } catch {}
  if (state.ws) { try { state.ws.close(); } catch {} state.ws = null; }
  $("#nav").hidden = true;
  closeEvent();
  setLayout(false);
  renderWho(false);
  $("#live").replaceChildren(el("li", { class: "feed-empty" }, "Waiting for detections…"));
  $$(".view").forEach((v) => { v.hidden = v.id !== "view-login"; });
  status(message || "", isError);
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const body = { email: f.get("email"), password: f.get("password") };
    const otp = (f.get("otp") || "").trim();
    if (otp) body.otp = otp;
    const res = await api("POST", "/auth/login", body);
    e.target.reset();
    $("#otp-row").hidden = true;
    await startSession(res.access_token);
  } catch (err) {
    if (err && err.message === "MFA code required") {
      $("#otp-row").hidden = false;
      $("#passkey-signin").hidden = !passkeysSupported();
      $("#login-form [name=otp]").focus();
      status(passkeysSupported() ? "Enter the code from your authenticator app (or a recovery code), or use your passkey."
                                 : "Enter the code from your authenticator app (or a recovery code).");
    } else if (err && err.message === "Passkey required") {
      $("#otp-row").hidden = true;
      $("#passkey-signin").hidden = false;
      if (passkeysSupported()) { status("Confirm with your passkey to finish signing in."); signInWithPasskey(); }
      else status("This account signs in with a passkey, which this browser does not support.", true);
    }
  }
});

// ------------------------------------------------------------------ passkeys (WebAuthn)
// The server sends options with base64url strings; the browser API wants ArrayBuffers.
function passkeysSupported() { return !!(window.PublicKeyCredential && navigator.credentials); }
function fromB64url(s) {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0)).buffer;
}
function toB64url(buf) {
  let b = "";
  new Uint8Array(buf).forEach((x) => { b += String.fromCharCode(x); });
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function credList(list) { return (list || []).map((c) => ({ ...c, id: fromB64url(c.id) })); }
function credentialJson(cred) {
  const r = cred.response, out = { id: cred.id, rawId: toB64url(cred.rawId), type: cred.type, response: {
    clientDataJSON: toB64url(r.clientDataJSON) } };
  if (r.attestationObject) {
    out.response.attestationObject = toB64url(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports();
  } else {
    out.response.authenticatorData = toB64url(r.authenticatorData);
    out.response.signature = toB64url(r.signature);
    if (r.userHandle) out.response.userHandle = toB64url(r.userHandle);
  }
  return out;
}
function passkeyError(e) {
  if (e && e.name === "NotAllowedError") return "The passkey request was cancelled or timed out.";
  if (e && e.name === "InvalidStateError") return "This passkey is already registered.";
  return null;
}
async function createPasskey(password, name, headersToken) {
  const o = await api("POST", "/auth/passkeys/register/options", { current_password: password }, { credentialCheck: true });
  const pk = o.options;
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey: { ...pk, challenge: fromB64url(pk.challenge),
      user: { ...pk.user, id: fromB64url(pk.user.id) }, excludeCredentials: credList(pk.excludeCredentials) } });
  } catch (e) { status(passkeyError(e) || `Passkey not created: ${e.message || e}`, true); throw e; }
  return api("POST", "/auth/passkeys/register", { challenge_id: o.challenge_id, name, credential: credentialJson(cred) },
             { credentialCheck: true });
}
async function signInWithPasskey() {
  const f = $("#login-form");
  const email = f.querySelector("[name=email]").value, password = f.querySelector("[name=password]").value;
  if (!email || !password) { status("Enter your email and password first.", true); return; }
  try {
    const o = await api("POST", "/auth/passkey/login/options", { email, password });
    const pk = o.options;
    let cred;
    try {
      cred = await navigator.credentials.get({ publicKey: { ...pk, challenge: fromB64url(pk.challenge),
        allowCredentials: credList(pk.allowCredentials) } });
    } catch (e) { status(passkeyError(e) || `Passkey sign-in failed: ${e.message || e}`, true); return; }
    const res = await api("POST", "/auth/passkey/login", { challenge_id: o.challenge_id, credential: credentialJson(cred) });
    f.reset();
    $("#otp-row").hidden = true;
    $("#passkey-signin").hidden = true;
    await startSession(res.access_token);
  } catch {}
}
$("#passkey-signin").addEventListener("click", signInWithPasskey);

$("#mfa-passkey-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await createPasskey(f.get("current_password"), f.get("name").trim());
    e.target.reset();
    status("Passkey created. Two-factor authentication is on.");
    await startSession(r.access_token);
  } catch {}
});

async function loadPasskeys() {
  $("#passkey-unsupported").hidden = passkeysSupported();
  $("#passkey-add-form").hidden = !passkeysSupported();
  const rows = await api("GET", "/auth/passkeys");
  $("#passkey-table").replaceChildren(table([
    { label: "Name", render: (p) => p.name },
    { label: "Added", render: (p) => fmtTime(p.created_at) },
    { label: "Last used", render: (p) => (p.last_used_at ? fmtTime(p.last_used_at) : el("span", { class: "muted" }, "Never")) },
    { label: "", render: (p) => el("button", { type: "button", class: "link", onclick: () => {
        const form = $("#passkey-remove-form");
        form.hidden = false;
        form.querySelector("[name=id]").value = p.id;
        $("#passkey-remove-name").textContent = p.name;
        form.querySelector("[name=current_password]").focus();
      } }, "Remove") },
  ], rows, "No passkeys yet"));
}

$("#passkey-add-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await createPasskey(f.get("current_password"), f.get("name").trim());
    e.target.reset();
    state.token = r.access_token;
    state.me = await api("GET", "/auth/me");
    status("Passkey added.");
    await Promise.all([loadPasskeys(), renderMfaStatus()]);
  } catch {}
});

$("#passkey-remove-cancel").addEventListener("click", () => { $("#passkey-remove-form").hidden = true; });
$("#passkey-remove-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("POST", `/auth/passkeys/${f.get("id")}/remove`, { current_password: f.get("current_password") },
              { credentialCheck: true });
    e.target.reset();
    e.target.hidden = true;
    state.me = await api("GET", "/auth/me");
    status("Passkey removed.");
    await Promise.all([loadPasskeys(), renderMfaStatus()]);
  } catch {}
});

// ------------------------------------------------------------------ session renewal
// Tokens live 30 minutes. While the operator is active, renew shortly before expiry (the server
// keeps the original sign-in time and refuses after SESSION_MAX_HOURS). Idle consoles expire.
const RENEW_BEFORE_MS = 5 * 60 * 1000;
const ACTIVE_WITHIN_MS = 25 * 60 * 1000;
let lastActivity = Date.now();
["click", "keydown", "pointermove", "wheel"].forEach((t) =>
  document.addEventListener(t, () => { lastActivity = Date.now(); }, { passive: true }));

function tokenExpiryMs(token) {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload.exp * 1000;
  } catch { return 0; }
}

async function renewIfDue() {
  if (!state.token || !state.me || state.me.mfa_enrollment_required) return;
  const left = tokenExpiryMs(state.token) - Date.now();
  if (left > RENEW_BEFORE_MS || Date.now() - lastActivity > ACTIVE_WITHIN_MS) return;
  try {
    const r = await api("POST", "/auth/refresh");
    state.token = r.access_token;
    try { sessionStorage.setItem("hs_token", r.access_token); } catch {}
    if (state.ws) { const old = state.ws; state.ws = null; try { old.close(1000, "renewed"); } catch {} }
    connectLive();
  } catch {}
}
setInterval(renewIfDue, 60 * 1000);

// ------------------------------------------------------------------ password reset
function showAuthView(name) {
  $$(".view").forEach((v) => { v.hidden = v.id !== `view-${name}`; });
}

function clearResetHash() {
  if (location.hash.startsWith("#reset=")) history.replaceState(null, "", location.pathname);
}

$("#forgot-link").addEventListener("click", () => {
  const email = $("#login-form [name=email]").value;
  if (email) $("#forgot-form [name=email]").value = email;
  showAuthView("forgot");
});
$$(".back-to-login").forEach((b) => b.addEventListener("click", () => { clearResetHash(); showAuthView("login"); }));

$("#forgot-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("POST", "/auth/password-reset/request", { email: f.get("email") });
    e.target.reset();
    showAuthView("login");
    status("If that account exists, a reset link is on its way. Check your inbox.");
  } catch {}
});

$("#reset-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  if (f.get("new_password") !== f.get("confirm")) { status("The two passwords do not match.", true); return; }
  const token = decodeURIComponent(location.hash.slice("#reset=".length));
  try {
    await api("POST", "/auth/password-reset/confirm", { token, new_password: f.get("new_password") },
              { credentialCheck: true });
    e.target.reset();
    clearResetHash();
    showAuthView("login");
    status("Password changed. Sign in with the new password.");
  } catch {}
});

// ------------------------------------------------------------------ MFA enrolment
function startEnrolment(forced) {
  $("#nav").hidden = true;
  setLayout(false);
  $$(".view").forEach((v) => { v.hidden = v.id !== "view-mfa"; });
  $("#mfa-intro").hidden = !forced;
  // Required enrolment offers a passkey first; from the Account page this screen adds the app only
  // (passkeys are added there).
  $("#mfa-passkey-form").hidden = !(forced && passkeysSupported());
  $("#mfa-totp-heading").hidden = !(forced && passkeysSupported());
  $("#mfa-setup-form").hidden = false;
  $("#mfa-secret").hidden = true;
  $("#mfa-codes").hidden = true;
}

$("#mfa-setup-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await api("POST", "/auth/mfa/setup", { current_password: f.get("current_password") },
                        { credentialCheck: true });
    e.target.reset();
    e.target.hidden = true;
    $("#mfa-secret-key").textContent = r.secret.replace(/(.{4})/g, "$1 ").trim();
    $("#mfa-secret-uri").textContent = r.otpauth_uri;
    $("#mfa-secret").hidden = false;
    $("#mfa-enable-form [name=code]").focus();
  } catch {}
});

$("#mfa-enable-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await api("POST", "/auth/mfa/enable", { code: f.get("code").trim() }, { credentialCheck: true });
    e.target.reset();
    state.pendingToken = r.access_token;
    $("#mfa-secret").hidden = true;
    $("#mfa-secret-key").textContent = "";
    $("#mfa-secret-uri").textContent = "";
    $("#mfa-codes-list").textContent = r.recovery_codes.join("\n");
    $("#mfa-codes").hidden = false;
    status("MFA is on.");
  } catch {}
});

$("#mfa-continue").addEventListener("click", async () => {
  $("#mfa-codes-list").textContent = "";
  const token = state.pendingToken || state.token;
  state.pendingToken = null;
  try { await startSession(token); } catch { signOutLocal(); }
});

$("#mfa-signout").addEventListener("click", async () => {
  try { await api("POST", "/auth/logout"); } catch {}
  signOutLocal("Signed out.");
});

async function renderMfaStatus() {
  if (!state.me) return;
  const me = state.me;
  const any = me.mfa_enabled || me.passkey_enabled;
  const how = [me.passkey_enabled ? `${me.passkeys} passkey${me.passkeys === 1 ? "" : "s"}` : null,
               me.mfa_enabled ? "authenticator app" : null].filter(Boolean).join(" and ");
  $("#mfa-status-text").replaceChildren(
    any ? badge("Enabled", "ok") : badge("Disabled", me.mfa_required ? "bad" : ""), " ",
    el("span", { class: "muted" }, [any ? `Using ${how}.` : "", me.mfa_required ? "Required for your role."
      : any ? "" : "Recommended."].filter(Boolean).join(" ")));
  $("#mfa-status-text").className = "status-row";
  $("#mfa-start").hidden = me.mfa_enabled;
  $("#mfa-start").textContent = me.passkey_enabled ? "Also set up an authenticator app" : "Set up MFA";
  $("#mfa-regen-form").hidden = !me.mfa_enabled;
  // The app can go when the role does not require MFA, or when a passkey keeps the account protected.
  $("#mfa-disable-form").hidden = !me.mfa_enabled || (me.mfa_required && !me.passkey_enabled);
}

$("#mfa-start").addEventListener("click", () => startEnrolment(false));

$("#mfa-regen-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const r = await api("POST", "/auth/mfa/recovery-codes", { code: f.get("code").trim() }, { credentialCheck: true });
    e.target.reset();
    startEnrolment(false);
    $("#mfa-setup-form").hidden = true;
    $("#mfa-codes-list").textContent = r.recovery_codes.join("\n");
    $("#mfa-codes").hidden = false;
  } catch {}
});

$("#mfa-disable-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  if (!confirm("Turn off two-factor authentication? All your sessions will be signed out.")) return;
  try {
    await api("POST", "/auth/mfa/disable", { current_password: f.get("current_password"), code: f.get("code").trim() },
              { credentialCheck: true });
    signOutLocal("MFA turned off. All sessions were signed out.");
  } catch {}
});

// ------------------------------------------------------------------ tenants (system admins)
const slugify = (name) => name.toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, "")
  .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 63).replace(/-+$/, "");

async function loadTenants() {
  const all = await allTenants(true);
  $("#tenants-table").replaceChildren(table([
    { label: "Name", render: (t) => twoLine(t.name, t.slug) },
    { label: "Status", render: (t) => (t.is_active ? badge("Active", "ok") : badge("Deactivated")) },
    { label: "Created", render: (t) => fmtTime(t.created_at) },
    { label: "", render: (t) => t.is_active ? el("button", { class: "danger", type: "button", onclick: async () => {
        const typed = prompt(`Deactivate ${t.name}? Its users can no longer sign in and its integration hooks are refused. ` +
          `Hits on its planted decoys are still recorded as evidence. This cannot be undone from the console.\n\nType the slug “${t.slug}” to confirm.`);
        if (typed === null) return;
        if (typed.trim() !== t.slug) { status("The slug did not match; nothing was changed.", true); return; }
        try { await api("DELETE", `/api/v1/tenants/${encodeURIComponent(t.slug)}`); status(`${t.name} was deactivated.`); await loadTenants(); } catch {}
      } }, "Deactivate") : "" },
  ], all, ["No tenants yet", "Create one for each customer organisation, then add its first admin on Users."]));
}

function toggleTenantForm(open) {
  $("#tenant-form").hidden = !open;
  $("#tenant-add").setAttribute("aria-expanded", String(open));
  if (open) $("#tenant-form [name=name]").focus();
}
$("#tenant-add").addEventListener("click", () => toggleTenantForm($("#tenant-form").hidden));
$("#tenant-cancel").addEventListener("click", () => { $("#tenant-form").reset(); toggleTenantForm(false); });
// The slug follows the name until the operator edits it.
$("#tenant-form [name=name]").addEventListener("input", (e) => {
  const slug = $("#tenant-form [name=slug]");
  if (!slug.dataset.edited) slug.value = slugify(e.target.value);
});
$("#tenant-form [name=slug]").addEventListener("input", (e) => { e.target.dataset.edited = e.target.value ? "1" : ""; });
$("#tenant-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const t = await api("POST", "/api/v1/tenants", { name: f.get("name").trim(), slug: f.get("slug").trim() });
    status(`${t.name} created. Add its first admin on Users.`);
    e.target.reset();
    delete e.target.querySelector("[name=slug]").dataset.edited;
    toggleTenantForm(false);
    await loadTenants();
  } catch {}
});

// ------------------------------------------------------------------ users (admins)
// A strong throwaway password for a new account: never shown or stored. The person sets their own
// through the one-time set-up link, so nobody else ever knows their password.
function throwawayPassword() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  return btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, "x") + "-Aa1";
}

async function setUser(u, body, done) {
  try { await api("PATCH", `/api/v1/users/${u.id}`, body); status(done); state.userEmails = null; await loadUsers(); } catch {}
}

function userActions(u) {
  if (state.me && u.id === state.me.id) return el("span", { class: "muted small" }, "You");
  const buttons = [];
  if (u.is_active && u.role !== "SYSTEM_ADMIN") {
    const toAdmin = u.role === "TENANT_USER";
    buttons.push(el("button", { class: "secondary", type: "button", onclick: () => {
      const msg = toAdmin
        ? `Make ${u.email} a tenant admin? They can manage decoys, integrations, alerts and users, and must set up two-factor authentication. Their current sessions end.`
        : `Make ${u.email} a read-only tenant user? Their current sessions end.`;
      if (confirm(msg)) setUser(u, { role: toAdmin ? "TENANT_ADMIN" : "TENANT_USER" }, `${u.email} is now a ${toAdmin ? "tenant admin" : "tenant user"}.`);
    } }, toAdmin ? "Make admin" : "Make read-only"));
  }
  buttons.push(u.is_active
    ? el("button", { class: "danger", type: "button", onclick: async () => {
        if (!confirm(`Deactivate ${u.email}? They are signed out everywhere and cannot sign in. Their audit history is kept.`)) return;
        try { await api("POST", `/api/v1/users/${u.id}/deactivate`); status(`${u.email} was deactivated.`); await loadUsers(); } catch {}
      } }, "Deactivate")
    : el("button", { class: "secondary", type: "button", onclick: () => {
        if (confirm(`Reactivate ${u.email}? They can sign in again with their existing password and two-factor settings.`))
          setUser(u, { is_active: true }, `${u.email} was reactivated.`);
      } }, "Reactivate"));
  return el("div", { class: "row-actions" }, buttons);
}

async function loadUsers() {
  const [users] = await Promise.all([api("GET", "/api/v1/users?limit=100"), fillTenantSelects().catch(() => {})]);
  const tenantName = new Map((state.tenants || []).map((t) => [t.id, t.slug]));
  const columns = [
    { label: "Email", key: "email" },
    { label: "Role", render: (u) => ROLE_NAMES[u.role] || u.role },
    { label: "Status", render: (u) => (u.is_active ? badge("Active", "ok") : badge("Deactivated", "bad")) },
    { label: "Two-factor", render: (u) => (u.mfa_enabled || u.passkey_enabled ? badge("On", "ok")
        : u.role === "TENANT_USER" ? badge("Off") : badge("Not set up", "warn")) },
    { label: "Added", render: (u) => fmtTime(u.created_at) },
    { label: "", render: userActions },
  ];
  if (isSysAdmin()) columns.splice(2, 0, { label: "Tenant", mono: true,
    render: (u) => u.tenant_id ? (tenantName.get(u.tenant_id) || `#${u.tenant_id}`) : "" });
  $("#users-table").replaceChildren(table(columns, users, ["No users", "Add the people who should see or manage this tenant."]));
  // Only other users with MFA on can be reset (resetting your own needs another administrator).
  const resettable = users.filter((u) => (u.mfa_enabled || u.passkey_enabled) && !(state.me && u.id === state.me.id));
  const select = $("#mfa-reset-form [name=user_id]");
  select.replaceChildren(...resettable.map((u) => el("option", { value: String(u.id) }, u.email)));
  $("#mfa-reset-panel").hidden = !resettable.length;
  const others = users.filter((u) => u.is_active && !(state.me && u.id === state.me.id));
  $("#pw-reset-form [name=user_id]").replaceChildren(...others.map((u) => el("option", { value: String(u.id) }, u.email)));
  $("#pw-reset-panel").hidden = !others.length;
}

// Only system admins may create system admins; a system admin has no tenant. Recomputed whenever the
// form opens, resets or the role changes (a reset does not fire "change").
function syncUserForm() {
  const role = $("#user-form [name=role]");
  const sysOpt = role.querySelector("option[value=SYSTEM_ADMIN]");
  sysOpt.hidden = sysOpt.disabled = !isSysAdmin();
  if (sysOpt.disabled && role.value === "SYSTEM_ADMIN") role.value = "TENANT_USER";
  $("#user-tenant-field").hidden = !isSysAdmin() || role.value === "SYSTEM_ADMIN";
}
function toggleUserForm(open) {
  $("#user-form").hidden = !open;
  $("#user-add").setAttribute("aria-expanded", String(open));
  if (open) { syncUserForm(); $("#user-form [name=email]").focus(); }
}
$("#user-add").addEventListener("click", () => toggleUserForm($("#user-form").hidden));
$("#user-cancel").addEventListener("click", () => { $("#user-form").reset(); toggleUserForm(false); });
$("#user-form [name=role]").addEventListener("change", syncUserForm);
$("#user-form").addEventListener("reset", () => setTimeout(syncUserForm, 0));

$("#user-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const email = f.get("email").trim();
  const role = f.get("role");
  const body = { email, role, password: throwawayPassword() };
  if (role !== "SYSTEM_ADMIN") {
    if (isSysAdmin()) {
      const t = (state.tenants || []).find((x) => x.slug === f.get("tenant_slug"));
      if (!t || !t.is_active) { status("Choose the tenant this person belongs to.", true); return; }
      body.tenant_id = t.id;
    } else {
      body.tenant_id = state.me.tenant_id;
    }
  }
  let user;
  try { user = await api("POST", "/api/v1/users", body); } catch { return; }
  const box = $("#user-created");
  try {
    const r = await api("POST", `/api/v1/users/${user.id}/password-reset`,
                        { reason: "New account: set-up link issued at creation" });
    box.replaceChildren(
      el("p", { class: "callout-title" }, `${email} was created. Give them this set-up link through a channel you trust.`),
      el("p", {}, "It works once, until ", fmtTime(r.expires_at), ". They choose their own password",
         role === "TENANT_USER" ? "." : ", then set up two-factor authentication."),
      copyBlock("set-up link", r.reset_url));
  } catch {
    box.replaceChildren(el("p", { class: "callout-title" },
      `${email} was created, but the set-up link could not be issued. Use “Password reset link” below to send one.`));
  }
  box.hidden = false;
  e.target.reset();
  toggleUserForm(false);
  state.userEmails = null;
  await loadUsers();
});

$("#pw-reset-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const label = e.target.querySelector("select").selectedOptions[0]?.textContent || "user";
  try {
    const r = await api("POST", `/api/v1/users/${f.get("user_id")}/password-reset`, { reason: f.get("reason") });
    const box = $("#pw-reset-result");
    box.replaceChildren(
      el("p", { class: "callout-title" }, `Reset link for ${label}. Shown once; it works until `, fmtTime(r.expires_at), "."),
      copyBlock("reset link", r.reset_url));
    box.hidden = false;
    e.target.reset();
  } catch {}
});

$("#mfa-reset-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const label = e.target.querySelector("select").selectedOptions[0]?.textContent || "user";
  try {
    await api("POST", `/api/v1/users/${f.get("user_id")}/mfa/reset`, { reason: f.get("reason") });
    e.target.reset();
    status(`MFA reset for ${label}; they were signed out and will enrol again at next sign-in.`);
    loadUsers();
  } catch {}
});

// ------------------------------------------------------------------ overview
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

// Stacked bars per day (HTML, sized through CSSOM so the strict CSP holds). Each bar carries a
// full text alternative in its title; the panel has an aria-label.
function activityChart(days) {
  const max = Math.max(1, ...days.map((d) => d.total));
  const cols = days.map((d, i) => {
    const stack = el("div", { class: "bar" });
    for (const sev of SEVERITIES) {
      const v = d.by_severity[sev] || 0;
      if (!v) continue;
      const seg = el("span", { class: `seg seg-${sev}` });
      seg.style.height = `${(v / max) * 100}%`;
      stack.append(seg);
    }
    const parts = SEVERITIES.filter((s) => d.by_severity[s]).map((s) => `${s} ${fmtNum(d.by_severity[s])}`);
    const label = `${d.date}: ${fmtNum(d.total)} event${d.total === 1 ? "" : "s"}${parts.length ? " (" + parts.join(", ") + ")" : ""}`;
    const isToday = i === days.length - 1;
    return el("div", { class: `col${isToday ? " today" : ""}`, title: label },
      el("div", { class: "col-val" }, d.total ? fmtNum(d.total) : ""),
      el("div", { class: "bar-area" }, stack),
      el("div", { class: "col-day" }, isToday ? "Today" : d.date.slice(5).replace("-", "/")));
  });
  return el("div", { class: "bars" }, cols);
}

function severityMix(days) {
  const totals = Object.fromEntries(SEVERITIES.map((s) => [s, days.reduce((a, d) => a + (d.by_severity[s] || 0), 0)]));
  const all = SEVERITIES.reduce((a, s) => a + totals[s], 0);
  const track = el("div", { class: "mix-track", "aria-hidden": "true" });
  for (const sev of SEVERITIES) {
    if (!totals[sev]) continue;
    const seg = el("span", { class: `seg seg-${sev}` });
    seg.style.width = `${(totals[sev] / all) * 100}%`;
    track.append(seg);
  }
  return [
    el("div", { class: "mix-head" }, el("span", { class: "mix-title" }, "By severity"),
       el("span", { class: "mix-total" }, `${fmtNum(all)} in 14 days`)),
    all ? track : el("div", { class: "mix-track empty-track" }),
    el("ul", { class: "mix-legend" }, SEVERITIES.map((sev) => el("li", {},
      el("span", { class: `key seg-${sev}` }), el("span", { class: "mix-name" }, sev.charAt(0) + sev.slice(1).toLowerCase()),
      el("span", { class: "mix-n" }, fmtNum(totals[sev])),
      el("span", { class: "mix-pct" }, all ? `${Math.round((totals[sev] / all) * 100)}%` : "–")))),
  ];
}

async function loadHealth() {
  if (!isSysAdmin()) return;
  const panel = $("#health-panel");
  let r;
  try { r = await api("GET", "/api/v1/system/status"); } catch { return; }
  panel.hidden = false;
  const w = r.watchdog;
  if (!w) {
    $("#health-meta").textContent = "";
    $("#health-body").replaceChildren(el("p", { class: "panel-text" },
      "The watchdog has not reported yet. It runs every few minutes as its own service (docs/watchdog.md)."));
    return;
  }
  const stale = r.watchdog_age_seconds !== null && r.watchdog_age_seconds > 20 * 60;
  $("#health-meta").replaceChildren("Checked ", fmtTime(w.last_cycle_at));
  const rows = (w.checks || []).map((c) => ({ ...c }));
  const channels = w.channels || {};
  const notes = [];
  if (stale) notes.push(el("div", { class: "callout warn" }, "The watchdog has not reported for over 20 minutes: it may have stopped."));
  if (!channels.webhook && !channels.email) notes.push(el("div", { class: "callout warn" },
    "No notice channel is set: problems are shown here only. Set WATCHDOG_NOTIFY_WEBHOOK_URL or WATCHDOG_NOTIFY_EMAIL."));
  if (!channels.heartbeat) notes.push(el("p", { class: "hint" },
    "No heartbeat URL: nothing outside this server will notice if it stops completely (WATCHDOG_HEARTBEAT_URL)."));
  $("#health-body").replaceChildren(notes.length ? el("div", { class: "panel-body stack" }, notes) : "", table([
    { label: "Check", render: (c) => c.label },
    { label: "Status", render: (c) => (c.ok ? badge("OK", "ok") : badge(c.severity === "critical" ? "Problem" : "Warning",
                                                                       c.severity === "critical" ? "bad" : "warn")) },
    { label: "Details", wrap: true, render: (c) => el("span", { class: c.ok ? "muted" : "" }, c.detail || "") },
  ], rows, "No checks yet"));
}

async function loadOverview() {
  loadHealth();
  // Each part renders on its own: slow analytics (503) must not blank the counters.
  const [stats, summary, top, activity] = await Promise.allSettled([
    api("GET", "/api/v1/detection-events/statistics"),
    api("GET", "/api/v1/threats/summary"),
    api("GET", "/api/v1/threats/top-attackers?limit=10"),
    api("GET", "/api/v1/detection-events/activity?days=14"),
  ]);
  const ok = (r) => r.status === "fulfilled";
  const tile = (label, value, sub, cls = "") =>
    el("div", { class: "tile" }, el("div", { class: "tile-label" }, label),
       el("div", { class: `tile-value ${cls}` }, value), el("div", { class: "tile-sub" }, sub || ""));
  const s = ok(stats) ? stats.value : null;
  const m = ok(summary) ? summary.value : null;
  const days = ok(activity) ? activity.value : null;
  const n = fmtNum;
  const yesterday = days && days.length > 1 ? days[days.length - 2].total : null;
  const score = m ? m.highest_threat_score : null;
  $("#ov-stats").replaceChildren(
    tile("Total events", s ? n(s.total_events) : "–", "All time"),
    tile("Today", s ? n(s.today_events) : "–", yesterday === null ? "UTC day" : `Yesterday ${n(yesterday)}`),
    tile("Source IPs", m ? n(m.distinct_ip_addresses) : "–", "Distinct, last 30 days"),
    tile("Highest threat score", m ? String(score) : "–",
         score === null ? "" : score >= 70 ? "High: investigate" : score >= 40 ? "Elevated" : "Low", score >= 70 ? "bad" : ""));
  if (days) {
    $("#ov-activity").replaceChildren(activityChart(days));
    $("#ov-mix").replaceChildren(...severityMix(days));
  } else {
    $("#ov-activity").replaceChildren(el("p", { class: "panel-text chart-msg" },
      activity.reason && /too long/i.test(activity.reason.message)
        ? "Activity took too long to compute for this window. Event lists and counts are unaffected."
        : "Activity could not be loaded. Event lists and counts are unaffected."));
    $("#ov-mix").replaceChildren();
  }
  const note = $("#ov-sampled");
  if (note) {
    note.hidden = !(m && m.sampled);
    // When sampled, total_events is the number of (most recent) events the figures cover.
    note.textContent = m && m.sampled
      ? `Very high volume: threat figures cover the most recent ${n(m.total_events)} events of the last 30 days.` : "";
  }
  if (!ok(top)) {
    $("#ov-top").replaceChildren(el("p", { class: "panel-text" },
      top.reason && /too long/i.test(top.reason.message)
        ? "Threat ranking took too long to compute. Event lists and counts are unaffected."
        : "Threat ranking could not be loaded. Event lists and counts are unaffected."));
    return;
  }
  $("#ov-top").replaceChildren(table([
    { label: "IP address", key: "ip_address", mono: true },
    { label: "Threat score", render: (r) => scoreMeter(r.threat_score) },
    { label: "Events", num: true, render: (r) => fmtNum(r.total_events) },
    { label: "Decoys", num: true, render: (r) => fmtNum(r.distinct_honey_tokens) },
    { label: "Last seen", render: (r) => fmtTime(r.last_seen) },
  ], top.value, ["No attackers recorded yet", "Addresses appear here, ranked, once decoys are touched."], {
    // Pivot: every event from this address, newest first.
    onRow: (r) => showEventsFor(r.ip_address),
    rowLabel: (r) => `${r.ip_address}, threat score ${r.threat_score}: show its events`,
  }));
}

function connectLive() {
  if (!state.token || state.ws) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/v1/events/stream/ws`);
  state.ws = ws;
  const stateBadge = $("#live-state");
  ws.addEventListener("open", () => ws.send(JSON.stringify({ type: "auth", token: state.token })));
  ws.addEventListener("message", (msg) => {
    let data; try { data = JSON.parse(msg.data); } catch { return; }
    if (data.type === "auth_success") {
      stateBadge.textContent = "Live"; stateBadge.className = "badge ok"; state.wsRetryMs = 0; return;
    }
    if (data.event_type !== "detection_event") return;
    const li = el("li", {}, badge(data.severity, `sev-${data.severity}`),
                  el("span", { class: "mono" }, data.ip_address),
                  el("span", { class: "feed-time" }, fmtTime(data.triggered_at)),
                  el("span", { class: "feed-req" }, `${data.http_method} ${data.request_path}  ·  ${data.source}`));
    const feed = $("#live");
    const placeholder = feed.querySelector(".feed-empty");
    if (placeholder) placeholder.remove();
    feed.prepend(li);
    while (feed.children.length > 100) feed.lastChild.remove();
  });
  ws.addEventListener("close", (ev) => {
    if (state.ws !== ws) return;  // replaced (session renewed): the new socket owns the badge
    state.ws = null;
    stateBadge.textContent = ev.reason ? `Offline: ${ev.reason}` : "Offline"; stateBadge.className = "badge";
    // 1008: auth ended, do not loop. Otherwise retry with exponential backoff (5 s doubling to
    // 60 s, +/-20 % jitter) so an outage is not met by every open console reconnecting in step.
    if (state.token && ev.code !== 1008) {
      state.wsRetryMs = Math.min(60000, state.wsRetryMs ? state.wsRetryMs * 2 : 5000);
      setTimeout(connectLive, state.wsRetryMs * (0.8 + Math.random() * 0.4));
    }
  });
}

// ------------------------------------------------------------------ projects & tokens
async function loadProjects() {
  const [projects] = await Promise.all([api("GET", "/api/v1/projects"), fillTenantSelects().catch(() => {})]);
  const tenantSlug = new Map((state.tenants || []).map((t) => [t.id, t.slug]));
  const columns = [
    { label: "Name", key: "name" },
    { label: "Domain", key: "domain", mono: true },
    { label: "Status", render: (p) => badge(p.is_active ? "Active" : "Inactive", p.is_active ? "ok" : "") },
    { label: "Added", render: (p) => fmtTime(p.created_at) },
    { label: "", render: (p) => el("button", { class: "secondary", type: "button", onclick: () => selectProject(p) }, "View decoys") },
  ];
  if (isSysAdmin()) columns.splice(2, 0, { label: "Tenant", mono: true, render: (p) => tenantSlug.get(p.tenant_id) || "" });
  $("#projects").replaceChildren(table(columns, projects,
    ["No projects yet", "Add the domain you want to protect, then generate decoys for it."]));
  return projects;
}

$("#project-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const slug = isSysAdmin() ? f.get("tenant_slug") : state.me.tenant_slug;
  if (!slug) { status("Choose the tenant this project belongs to.", true); return; }
  try {
    await api("POST", "/api/v1/projects", { tenant_slug: slug, name: f.get("name"), domain: f.get("domain") });
    e.target.reset();
    await loadProjects();
  } catch {}
});

async function selectProject(p) {
  state.project = p;
  $("#token-panel").hidden = false;
  $("#tok-project").textContent = p.domain;
  $("#artifact").hidden = true;
  await Promise.all([loadTokens(), markAvailableTypes()]);
}

const DECOY_TYPES = { URL: "Hidden URL", LINK: "Hidden link", PIXEL: "Tracking pixel",
                      FORM_FIELD: "Form honeypot", API_KEY: "Fake API key", DNS: "DNS host name",
                      AWS_KEY: "AWS access key", DOCUMENT: "Word document", AD_ACCOUNT: "AD account" };

// DNS and AWS key decoys need a service of their own; options this installation cannot watch are
// disabled (the server refuses them anyway) and say why.
async function markAvailableTypes() {
  if (state.decoyTypes) return;
  try { state.decoyTypes = (await api("GET", "/api/v1/honey-tokens/types")).types; } catch { return; }
  for (const opt of $("#generate-form [name=token_type]").options) {
    if (state.decoyTypes[opt.value] === false) {
      opt.disabled = true;
      if (!opt.textContent.endsWith("(not set up)")) opt.textContent += " (not set up)";
    }
  }
}

async function loadTokens() {
  const tokens = await api("GET", `/api/v1/honey-tokens?project_domain=${encodeURIComponent(state.project.domain)}&active_only=false&limit=100`);
  // Active decoys first; within each group the most recently fired first, then the newest.
  tokens.sort((a, b) => (b.is_active - a.is_active)
    || String(b.last_triggered_at || "").localeCompare(String(a.last_triggered_at || ""))
    || String(b.created_at).localeCompare(String(a.created_at)));
  const fired = tokens.filter((t) => t.last_triggered_at).length;
  $("#tokens-note").textContent = tokens.length
    ? `${fmtNum(tokens.length)} decoy${tokens.length === 1 ? "" : "s"}, ${fmtNum(fired)} ever triggered` : "";
  $("#tokens").replaceChildren(table([
    // the type sits under the name with the public id, so the row fits beside its actions
    { label: "Decoy", render: (t) => twoLine(t.label || DECOY_TYPES[t.token_type] || t.token_type,
        `${DECOY_TYPES[t.token_type] || t.token_type} · ${t.decoy_id}`) },
    { label: "Value", key: "token_value", mono: true },
    { label: "Last triggered", render: (t) => t.last_triggered_at
        ? el("button", { class: "link fired", type: "button", title: "Show this decoy's events",
                         onclick: () => showEventsForDecoy(t) }, fmtTime(t.last_triggered_at),
             el("span", { class: "sr-only" }, `, show events of ${t.label || DECOY_TYPES[t.token_type]}`))
        : el("span", { class: "muted" }, "Never") },
    { label: "Status", render: (t) => badge(t.is_active ? "Active" : "Revoked", t.is_active ? "ok" : "") },
    { label: "", render: (t) => isAdmin() && t.is_active ? el("div", { class: "row-actions" },
        el("button", { class: "secondary", type: "button", onclick: () => showArtifact(t) }, "Artifact"),
        el("button", { class: "secondary", type: "button", onclick: () => rotate(t) }, "Rotate"),
        el("button", { class: "danger", type: "button", onclick: () => revoke(t) }, "Revoke")) : "" },
  ], tokens, ["No decoys in this project yet", "Generate one above and plant it where only an intruder would look."]));
}

$("#generate-form [name=token_type]").addEventListener("change", (e) => {
  $("#generate-form [name=provider_style]").hidden = e.target.value !== "API_KEY";
  $("#generate-form [name=template]").hidden = e.target.value !== "DOCUMENT";
  $("#generate-form [name=account_name]").hidden = e.target.value !== "AD_ACCOUNT";
  $("#generate-form [name=audit_reads]").hidden = e.target.value !== "AD_ACCOUNT";
});

const GUIDANCE = {
  URL: "Place the URL where only an intruder would find it: internal wikis, config comments, robots.txt Disallow lines, decoy bookmarks. Any request to it is HIGH severity.",
  LINK: "Hide the link in internal pages. Crawlers and link previews can follow it, so events are MEDIUM and should be triaged.",
  PIXEL: "Embed only in decoy documents and decoy emails, never in normal web pages: every viewer would trigger it. Mail clients that pre-fetch images can trigger it.",
  FORM_FIELD: "Insert the snippet inside protected forms and check the field server-side with the HoneyShield hook; a non-empty value means a bot filled it. Requires an integration credential.",
  API_KEY: "Plant the key in decoy config files and repositories. Detection needs the HoneyShield hook in your authentication middleware. Use against third-party APIs is not detectable.",
  DNS: "Plant the host name where an intruder would use it: config files, SSH configs, backup scripts, internal docs. Any lookup is recorded with the resolver that asked, so it works from networks that block everything but DNS. Nothing in front of the name is needed, but anything there (a machine name, a username) is recorded too.",
  DOCUMENT: "Download the Word file and leave it where an intruder would open it: file shares, home folders, backup archives, mailboxes. Opening it in Word loads a 1-pixel picture from HoneyShield and is recorded as HIGH. Word's Protected View (files marked as downloaded from the internet) holds the picture back until editing is enabled, so plant the file, don't email it.",
  AD_ACCOUNT: "A domain account nobody uses, with a password nobody knows. Any sign-in attempt with it, or any Kerberos ticket requested for its SPN (Kerberoasting), is reported by the collector on your domain controllers as CRITICAL within about a minute. The account is in no groups and can do nothing.",
  AWS_KEY: "A real AWS key with a deny-all policy: plant it in ~/.aws/credentials, CI variables, .env files or repositories. Any use of it, from any tool, is read from CloudTrail and alerted as CRITICAL, usually within 20 minutes. It can do nothing in your AWS account.",
};

// Copy text to the clipboard. Browsers that refuse the async Clipboard API (permissions policy,
// locked-down profiles) get the legacy copy command; if that is refused too, the value is selected
// so a single Cmd/Ctrl+C copies it. Returns "copied" or "selected".
async function copyText(value, selectNode) {
  try { await navigator.clipboard.writeText(value); return "copied"; } catch {}
  try {
    const ta = el("textarea", { class: "offscreen", readonly: true, "aria-hidden": "true" });
    ta.value = value;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand && document.execCommand("copy");
    ta.remove();
    if (ok) return "copied";
  } catch {}
  if (selectNode) {
    const range = document.createRange();
    range.selectNodeContents(selectNode);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  return "selected";
}

// A value an administrator must plant exactly: shown in full with a one-click copy.
function copyBlock(label, value) {
  const pre = el("pre", { class: "mono" }, value);
  const btn = el("button", { class: "secondary copy-btn", type: "button", "aria-label": `Copy ${label}` }, "Copy");
  btn.addEventListener("click", async () => {
    const how = await copyText(value, pre);
    btn.textContent = how === "copied" ? "Copied" : "Selected";
    if (how === "selected") status("This browser blocks clipboard access: the value is selected, press Cmd+C or Ctrl+C.");
    setTimeout(() => { btn.textContent = "Copy"; }, 1800);
  });
  return el("div", { class: "copy-block" }, el("div", { class: "copy-head" }, el("strong", {}, label), btn), pre);
}

function showArtifact(t) {
  const m = t.metadata || {};
  const box = $("#artifact");
  const items = [];
  for (const key of ["url", "pixel_url", "embed_html", "html_tag", "html_snippet"]) {
    if (m[key]) items.push(copyBlock(key, m[key]));
  }
  if (t.token_type === "API_KEY") items.push(copyBlock("decoy key", t.token_value));
  if (t.token_type === "DNS" && m.hostname) {
    items.push(copyBlock("host name", m.hostname));
    if (m.examples && m.examples.config) items.push(copyBlock("in a config file", m.examples.config));
    if (m.tagged_example) items.push(copyBlock("with a tag in front (recorded too)", m.tagged_example));
  }
  if (t.token_type === "AWS_KEY") items.push(...awsKeyArtifact(t));
  if (t.token_type === "AD_ACCOUNT") items.push(...adAccountArtifact(t));
  if ((t.files || []).length) items.push(el("div", { class: "bait-files" }, el("strong", {}, "Download as:"),
    ...t.files.map((kind) => el("button", { class: "secondary", type: "button",
      onclick: () => downloadBaitFile(t, kind) }, BAIT_FILES[kind] || kind))));
  if (m.detection) items.push(el("p", {}, badge(m.detection.status, "info"), " ", m.detection.rule || ""));
  if (m.placement_warning) items.push(el("p", { class: "bad" }, m.placement_warning));
  items.push(el("p", { class: "muted" }, GUIDANCE[t.token_type] || ""));
  box.replaceChildren(el("h3", {}, `${t.token_type} artifact`), ...items);
  box.hidden = false;
}

// Ready-to-plant files carrying the decoy (GET /api/v1/honey-tokens/{decoy_id}/files/{kind}).
const BAIT_FILES = { "aws-credentials": "~/.aws/credentials", env: ".env file", kubeconfig: "kubeconfig",
                     "ssh-config": "SSH config", docx: "Word document",
                     "setup-script": "Setup script (run once)", "dc-collector": "DC collector" };

// An AD decoy is set up in the customer's directory: what to run, where, and in which order.
function adAccountArtifact(t) {
  const m = t.metadata || {};
  const items = [copyBlock("account name", m.account_name || "")];
  if (m.spn) items.push(copyBlock("SPN (the domain is added on the controller)", m.spn));
  items.push(el("ol", { class: "steps" },
    el("li", {}, "Create an integration credential for this project (Integrations) and keep its secret."),
    el("li", {}, "Download the setup script and run it once as a Domain Admin. Add -Path with the OU of your service accounts."),
    el("li", {}, "Download the DC collector and, on every domain controller, run it with -Install -IntegrationId <id>. It asks for the secret."),
    el("li", {}, "Run the collector with -Test to check the audit policy and the connection.")));
  if (m.audit_reads) items.push(el("p", { class: "muted" }, "Reads are audited too: enumeration tools that read every account (BloodHound, PowerView) trigger HIGH events. So can inventory or sync tools; see docs/active-directory-decoys.md."));
  return items;
}

async function downloadBaitFile(t, kind) {
  busy(1);
  try {
    const resp = await fetch(`/api/v1/honey-tokens/${encodeURIComponent(t.decoy_id)}/files/${encodeURIComponent(kind)}`, {
      headers: { Authorization: `Bearer ${state.token}` }, credentials: "omit", cache: "no-store" });
    if (!resp.ok) { status(`Download failed (HTTP ${resp.status}).`, true); return; }
    const cd = resp.headers.get("Content-Disposition") || "";
    const utf8 = cd.match(/filename\*=UTF-8''([^;]+)/);
    const plain = cd.match(/filename="([^"]+)"/);
    let name = plain ? plain[1] : kind;
    try { if (utf8) name = decodeURIComponent(utf8[1]); } catch {}
    const a = el("a", { href: URL.createObjectURL(await resp.blob()), download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    status(`Downloaded ${name}. Plant it where only an intruder would open it.`);
  } catch { status("Download failed: the API is unreachable.", true); }
  finally { busy(-1); }
}

// An AWS key decoy is created by the cloud-canary worker a few seconds after generation.
function awsKeyArtifact(t) {
  const m = t.metadata || {};
  if (m.status === "active" && m.access_key_id && m.secret_access_key) {
    const profile = m.profile_name || "default";
    return [
      copyBlock("~/.aws/credentials", `[${profile}]\naws_access_key_id = ${m.access_key_id}\naws_secret_access_key = ${m.secret_access_key}\n`),
      copyBlock("environment variables", `AWS_ACCESS_KEY_ID=${m.access_key_id}\nAWS_SECRET_ACCESS_KEY=${m.secret_access_key}`),
      el("p", { class: "muted" }, `IAM user ${m.iam_arn || m.iam_user}. Deny-all policy; nothing in the account is reachable with it.`),
    ];
  }
  if (m.status === "failed") return [el("p", { class: "bad" }, `AWS refused to create the key: ${m.last_error || "unknown error"}. Revoke this decoy and check the worker's IAM policy (docs/cloud-canaries.md).`)];
  if (m.status === "deleted") return [el("p", { class: "muted" }, "The key was deleted from AWS when this decoy was revoked.")];
  if (t.is_active) setTimeout(() => refreshArtifact(t, (t._tries || 0) + 1), 5000);
  return [el("p", { class: "muted" }, "Creating the key in AWS. This takes a few seconds; the credentials appear here.")];
}

async function refreshArtifact(t, tries) {
  if (tries > 24 || $("#artifact").hidden || !state.project) return;
  try {
    const tokens = await api("GET", `/api/v1/honey-tokens?project_domain=${encodeURIComponent(state.project.domain)}&active_only=false&limit=100`);
    const now = tokens.find((x) => x.id === t.id);
    if (!now) return;
    now._tries = tries;
    showArtifact(now);
    if ((now.metadata || {}).status !== "provisioning") await loadTokens();
  } catch {}
}

$("#generate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const params = f.get("token_type") === "API_KEY" && f.get("provider_style") ? { provider_style: f.get("provider_style") }
    : f.get("token_type") === "DOCUMENT" && f.get("template") ? { template: f.get("template") }
    : f.get("token_type") === "AD_ACCOUNT" ? Object.assign({ audit_reads: f.get("audit_reads") === "1" },
        f.get("account_name") ? { account_name: f.get("account_name").trim() } : {}) : undefined;
  try {
    const t = await api("POST", `/api/v1/projects/${encodeURIComponent(state.project.domain)}/honey-tokens/generate`,
                        { token_type: f.get("token_type"), generator_params: params });
    await loadTokens();
    showArtifact(t);
  } catch {}
});

async function rotate(t) {
  const note = t.token_type === "AD_ACCOUNT"
    ? "Rotate this decoy? It gets a new id but keeps the same account: nothing changes in Active Directory."
    : "Rotate this decoy? The old value is revoked (its future triggers are still recorded) and a new artifact is issued that you must redeploy.";
  if (!confirm(note)) return;
  try { const nt = await api("POST", "/api/v1/honey-tokens/rotate", { old_token_value: t.token_value }); await loadTokens(); showArtifact(nt); } catch {}
}

async function revoke(t) {
  if (!confirm("Revoke this decoy? Triggers are still recorded as evidence.")) return;
  try { await api("POST", "/api/v1/honey-tokens/revoke", { token_value: t.token_value }); await loadTokens(); } catch {}
}

// ------------------------------------------------------------------ events
// Filters live in the form; the same query drives the list, "Load older" and the CSV export.
function eventFilters() {
  const f = new FormData($("#events-filter"));
  const p = new URLSearchParams();
  if (f.get("severity")) p.append("severity", f.get("severity"));
  const ip = (f.get("ip") || "").trim();
  if (ip) p.append("ip_address", ip);
  const days = Number(f.get("range") || 0);
  if (days) p.append("since", new Date(Date.now() - days * 86400000).toISOString());
  if (f.get("decoy_id")) p.append("decoy_id", f.get("decoy_id"));
  return p;
}

// The decoy filter is set from a decoy row, shown as a removable chip, and travels with the list,
// "Load older" and the CSV export. A hidden input is not cleared by form.reset(), so it is done here.
function setDecoyFilter(t) {
  $("#events-filter [name=decoy_id]").value = t ? t.decoy_id : "";
  const chip = $("#events-decoy");
  chip.hidden = !t;
  chip.replaceChildren(...(t ? [
    el("span", {}, "Decoy: ", el("strong", {}, t.label || DECOY_TYPES[t.token_type] || t.decoy_id)),
    el("button", { type: "button", class: "chip-x", "aria-label": "Remove the decoy filter", title: "Remove the decoy filter",
                   onclick: () => { setDecoyFilter(null); loadEvents(true).catch(() => {}); } }, "×"),
  ] : []));
}

function showEventsForDecoy(t) {
  const f = $("#events-filter");
  f.querySelector("[name=severity]").value = "";
  f.querySelector("[name=range]").value = "";
  f.querySelector("[name=ip]").value = "";
  setDecoyFilter(t);
  show("events");
}

const EVENT_COLUMNS = [
  { label: "When", render: (e) => fmtTime(e.triggered_at) },
  { label: "Severity", render: (e) => badge(e.severity, `sev-${e.severity}`) },
  { label: "Source", render: (e) => el("span", { class: `prov prov-${e.source}` }, e.source) },
  { label: "IP", key: "ip_address", mono: true },
  { label: "Request", render: (e) => `${e.http_method} ${e.request_path}`, mono: true },
  { label: "Decoy", render: (e) => e.decoy_label || e.decoy_type || "" },
  { label: "User agent", key: "user_agent", mono: true },
];

async function loadEvents(reset) {
  const filters = eventFilters();
  if (reset) { state.eventsCursor = null; state.events = []; }
  const q = new URLSearchParams(filters);
  q.set("limit", "100");
  if (state.eventsCursor) q.set("cursor", state.eventsCursor);
  const page = await api("GET", `/api/v1/detection-events?${q}`);
  state.events = (state.events || []).concat(page);
  const filtered = [...filters.keys()].length > 0;
  $("#events").replaceChildren(table(EVENT_COLUMNS, state.events,
    filtered ? ["No events match these filters", "Widen the time range or clear the filters."]
             : ["No detection events yet", "When a planted decoy is touched, the event appears here within seconds."],
    { onRow: openEvent, rowLabel: (e) => `${e.severity} event from ${e.ip_address}, open details` }));
  state.eventsCursor = page.length ? page[page.length - 1].id : null;
  $("#events-more").hidden = page.length < 100;
  $("#events-clear").hidden = !filtered;
  $("#events-note").textContent = state.events.length
    ? `${fmtNum(state.events.length)} ${filtered ? "matching " : ""}event${state.events.length === 1 ? "" : "s"} shown, newest first` : "";
}
$("#events-filter").addEventListener("submit", (e) => { e.preventDefault(); loadEvents(true).catch(() => {}); });
// (signing out resets every form; with nobody signed in there is nothing to reload)
$("#events-filter").addEventListener("reset", () => setTimeout(() => {
  setDecoyFilter(null);
  if (state.token) loadEvents(true).catch(() => {});
}, 0));
$("#events-filter [name=severity]").addEventListener("change", () => loadEvents(true).catch(() => {}));
$("#events-filter [name=range]").addEventListener("change", () => loadEvents(true).catch(() => {}));

function showEventsFor(ip) {
  const f = $("#events-filter");
  f.querySelector("[name=severity]").value = "";
  f.querySelector("[name=range]").value = "";
  f.querySelector("[name=ip]").value = ip;
  setDecoyFilter(null);
  show("events");
}

// ------------------------------------------------------------------ event details
let drawerReturnFocus = null;
function detailRow(label, value, mono = false) {
  if (value === null || value === undefined || value === "") return null;
  return [el("dt", {}, label), el("dd", { class: mono ? "mono" : "" }, value)];
}
function openEvent(e, fromRow) {
  drawerReturnFocus = fromRow || document.activeElement;
  $("#drawer-title").replaceChildren(badge(e.severity, `sev-${e.severity}`), ` Event ${e.id}`);
  const headers = e.headers && Object.keys(e.headers).length
    ? el("table", { class: "kv" }, el("tbody", {}, Object.entries(e.headers).map(([k, v]) =>
        el("tr", {}, el("th", { scope: "row" }, k), el("td", { class: "mono" }, String(v))))))
    : el("p", { class: "muted small" }, "No headers were captured.");
  const contextTitle = { AD: "Directory event", AWS: "Cloud event" }[e.http_method] || "Request headers";
  const utc = new Date(e.triggered_at);
  $("#event-detail").replaceChildren(
    el("section", { class: "drawer-section" }, el("h3", {}, "What happened"),
      el("dl", { class: "facts" }, [
        detailRow("When", fmtTime(e.triggered_at)),
        detailRow("UTC", isNaN(utc) ? e.triggered_at : utc.toISOString(), true),
        detailRow("Source address", e.ip_address, true),
        detailRow("Request", `${e.http_method} ${e.request_path}`, true),
        detailRow("User agent", e.user_agent, true),
        detailRow("Provenance", el("span", { class: `prov prov-${e.source}` }, e.source)),
        detailRow("Entered by", e.created_by_user_id ? `user #${e.created_by_user_id}` : null),
        detailRow("Recorded", fmtTime(e.created_at)),
        // A public hit stored well after the edge saw it was captured during a backend outage and replayed.
        detailRow("Recovery", e.source === "PUBLIC_INGEST" && new Date(e.created_at) - new Date(e.triggered_at) > 60000
          ? "Captured by the edge while the backend was unavailable and recorded once it was back; the time above is when the edge saw it."
          : null),
      ].flat().filter(Boolean))),
    el("section", { class: "drawer-section" }, el("h3", {}, "Decoy"),
      el("dl", { class: "facts" }, [
        detailRow("Label", e.decoy_label),
        detailRow("Type", e.decoy_type),
        detailRow("ATT&CK", (e.attack || []).length ? el("span", { class: "attack" }, ...e.attack.map((t) =>
          el("a", { href: t.url, target: "_blank", rel: "noopener noreferrer", title: t.tactics.join(", ") },
             `${t.id} ${t.name}`))) : null),
        detailRow("Decoy id", e.decoy_id, true),
        detailRow("Project", e.project_domain, true),
      ].flat().filter(Boolean))),
    el("section", { class: "drawer-section" }, el("h3", {}, contextTitle), headers),
    el("div", { class: "drawer-actions" },
      // "All events from this address": the address alone, whatever was filtered before, and from
      // whichever page the panel was opened (an alert delivery, the overview).
      el("button", { class: "secondary", type: "button", onclick: () => { closeEvent(); showEventsFor(e.ip_address); } },
        "Show all events from this address"),
      el("button", { class: "secondary", type: "button", onclick: async () => {
        const how = await copyText(e.ip_address);
        status(how === "copied" ? "Address copied." : "This browser blocks clipboard access: copy the address from the panel.");
      } }, "Copy address")),
  );
  $("#event-drawer").hidden = false;
  $("#drawer-backdrop").hidden = false;
  $("#drawer-close").focus();
}
function closeEvent() {
  if ($("#event-drawer").hidden) return;
  $("#event-drawer").hidden = true;
  $("#drawer-backdrop").hidden = true;
  if (drawerReturnFocus && document.contains(drawerReturnFocus)) drawerReturnFocus.focus();
}
$("#drawer-close").addEventListener("click", closeEvent);
$("#drawer-backdrop").addEventListener("click", closeEvent);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") closeEvent();
  // keep keyboard focus inside the open dialog
  if (ev.key === "Tab" && !$("#event-drawer").hidden) {
    const f = $$("#event-drawer button, #event-drawer [tabindex]").filter((n) => !n.hidden);
    if (!f.length) return;
    const first = f[0], last = f[f.length - 1];
    if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
  }
});
$("#events-more").addEventListener("click", () => loadEvents(false).catch(() => {}));

// ------------------------------------------------------------------ integrations
async function loadIntegrations() {
  const projects = await api("GET", "/api/v1/projects");
  const sel = $("#int-project");
  sel.replaceChildren(...projects.map((p) => el("option", { value: p.domain }, p.domain)));
  const rows = [];
  for (const p of projects) {
    const creds = await api("GET", `/api/v1/projects/${encodeURIComponent(p.domain)}/integrations`);
    creds.forEach((c) => rows.push({ ...c, project: p.domain }));
  }
  $("#integrations").replaceChildren(table([
    { label: "Project", key: "project", mono: true },
    { label: "Integration id", key: "integration_id", mono: true },
    { label: "Label", key: "label", wrap: true },
    { label: "Status", render: (c) => badge(c.is_active ? "Active" : "Revoked", c.is_active ? "ok" : "") },
    { label: "Last used", render: (c) => fmtTime(c.last_used_at) },
    { label: "", render: (c) => c.is_active ? el("button", { class: "danger", onclick: async () => {
        if (!confirm("Revoke this credential? Reports signed with it will be refused.")) return;
        try { await api("POST", `/api/v1/projects/${encodeURIComponent(c.project)}/integrations/${c.integration_id}/revoke`); await loadIntegrations(); } catch {}
      } }, "Revoke") : "" },
  ], rows, ["No integration credentials yet", "Create one for each service that reports API_KEY or FORM_FIELD decoy hits."]));
}

$("#integration-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const c = await api("POST", `/api/v1/projects/${encodeURIComponent(f.get("project"))}/integrations`, { label: f.get("label") || null });
    const box = $("#int-secret");
    box.replaceChildren(el("p", { class: "callout-title" }, "Copy now: this secret is shown only once."),
      copyBlock("environment", `HONEYSHIELD_INTEGRATION_ID=${c.integration_id}\nHONEYSHIELD_INTEGRATION_SECRET=${c.secret}`));
    box.hidden = false;
    await loadIntegrations();
  } catch {}
});

// ------------------------------------------------------------------ alerts
const ALERT_FORMATS = {
  HONEYSHIELD: { name: "Signed JSON webhook", placeholder: "https://hooks.example.com/honeyshield",
                 hint: "HTTPS on a public host. Every request is signed; the secret is shown once when you add it." },
  SLACK: { name: "Slack or Teams", placeholder: "https://hooks.slack.com/services/…",
           hint: "An incoming-webhook URL from Slack, Microsoft Teams or Mattermost." },
  EMAIL: { name: "Email", placeholder: "mailto:soc@example.com,oncall@example.com",
           hint: "mailto: with one or more addresses, sent through your mail relay." },
  SYSLOG_CEF: { name: "SIEM (syslog + CEF)", placeholder: "syslog+tls://siem.example.com:6514",
                hint: "Syslog over TLS (RFC 5425) carrying an ArcSight CEF message." },
  PAGERDUTY: { name: "PagerDuty", placeholder: "pagerduty://<integration key>",
               hint: "The Integration Key of an Events API v2 integration. Use pagerduty+eu:// for an EU account." },
  SPLUNK_HEC: { name: "Splunk", placeholder: "splunk://<HEC token>@hec.example.com:8088?index=security",
                hint: "An HTTP Event Collector token and host (Splunk Cloud: http-inputs-<stack>.splunkcloud.com:443). index= is optional. The token is masked once saved." },
  SENTINEL: { name: "Microsoft Sentinel", placeholder: "sentinel://<client id>:<secret>@<DCR ingestion host>/<dcr-…>/Custom-HoneyShield?tenant=<tenant id>",
              hint: "An Entra app with Monitoring Metrics Publisher on the data collection rule from deploy/sentinel. Percent-encode the secret. It is masked once saved." },
};
const SEND_FROM = { LOW: "Every event", MEDIUM: "Medium and above", HIGH: "High and above", CRITICAL: "Critical only" };

function alertFormatHint() {
  const fmt = ALERT_FORMATS[$("#alert-form [name=format]").value] || ALERT_FORMATS.HONEYSHIELD;
  $("#alert-form [name=url]").placeholder = fmt.placeholder;
  $("#alert-url-hint").textContent = fmt.hint;
}
$("#alert-form [name=format]").addEventListener("change", alertFormatHint);
alertFormatHint();

function deliveryStatus(d) {
  if (d.status === "DELIVERED") return badge("Delivered", "ok");
  if (d.status === "DEAD") return badge("Failed", "bad");
  if (d.status === "IN_FLIGHT") return badge("Sending", "info");
  return d.attempts ? badge("Retrying", "warn") : badge("Queued");
}

async function openEventById(id, button) {
  try { openEvent(await api("GET", `/api/v1/detection-events/${id}`), button); } catch {}
}

async function loadAlerts() {
  const [dests, deliveries] = await Promise.all([api("GET", "/api/v1/alert-destinations"),
                                                 api("GET", "/api/v1/alert-destinations/deliveries?limit=50"),
                                                 fillTenantSelects().catch(() => {})]);
  const names = new Map(dests.map((d) => [d.destination_id, d.label || ALERT_FORMATS[d.format]?.name || d.format]));
  $("#destinations").replaceChildren(table([
    { label: "Destination", render: (d) => twoLine(d.label || ALERT_FORMATS[d.format]?.name || d.format, d.destination_id) },
    { label: "Address", key: "url", mono: true },
    { label: "Type", render: (d) => ALERT_FORMATS[d.format]?.name || d.format },
    { label: "Sends", render: (d) => SEND_FROM[d.min_severity] || d.min_severity },
    { label: "Status", render: (d) => badge(d.is_active ? "Active" : "Disabled", d.is_active ? "ok" : "") },
    { label: "", render: (d) => d.is_active ? el("div", { class: "row-actions" },
        el("button", { class: "secondary", type: "button", onclick: async () => {
          try {
            await api("POST", `/api/v1/alert-destinations/${d.destination_id}/test`);
            status("Test alert queued. Its result appears under Recent deliveries within a few seconds.");
            setTimeout(() => loadAlerts().catch(() => {}), 4000);
          } catch {}
        } }, "Send test"),
        el("button", { class: "danger", type: "button", onclick: async () => {
          if (!confirm(`Disable “${names.get(d.destination_id)}”? It stops receiving alerts; past deliveries stay listed.`)) return;
          try { await api("DELETE", `/api/v1/alert-destinations/${d.destination_id}`); await loadAlerts(); } catch {}
        } }, "Disable")) : "" },
  ], dests, ["No alert destinations yet", "Add a webhook, Slack or Teams, email or SIEM destination to be told when a decoy fires."]));
  $("#deliveries").replaceChildren(table([
    { label: "Queued", render: (d) => fmtTime(d.created_at || d.next_attempt_at) },
    { label: "Destination", render: (d) => names.get(d.destination_id) || el("span", { class: "mono" }, d.destination_id) },
    { label: "Event", render: (d) => d.is_test ? badge("Test", "info") : d.detection_event_id
        ? el("button", { class: "link mono", type: "button", title: "Open this event",
                         onclick: (ev) => openEventById(d.detection_event_id, ev.currentTarget) }, `#${d.detection_event_id}`,
             el("span", { class: "sr-only" }, ", open event"))
        : "" },
    { label: "Status", render: deliveryStatus },
    { label: "Attempts", key: "attempts", num: true },
    { label: "Result", wrap: true, render: (d) => d.last_error || (d.last_status_code ? `HTTP ${d.last_status_code}` : "") },
    { label: "Delivered", render: (d) => d.delivered_at ? fmtTime(d.delivered_at)
        : d.status === "PENDING" && d.attempts ? el("span", { class: "muted" }, "Next try ", fmtTime(d.next_attempt_at)) : "" },
  ], deliveries, ["No deliveries yet", "Use “Send test” on a destination to check it end to end."]));
}

$("#alert-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const body = { url: f.get("url").trim(), format: f.get("format"), min_severity: f.get("min_severity"),
                 label: (f.get("label") || "").trim() || null };
  if (isSysAdmin()) {
    if (!f.get("tenant_slug")) { status("Choose the tenant this destination belongs to.", true); return; }
    body.tenant_slug = f.get("tenant_slug");
  }
  try {
    const d = await api("POST", "/api/v1/alert-destinations", body);
    const box = $("#alert-secret");
    if (d.signing_secret) {
      box.replaceChildren(
        el("p", { class: "callout-title" }, "Signing secret, shown once. Store it with the receiver."),
        el("p", {}, "Verify each request: X-HS-Signature must equal v1=HMAC-SHA256(secret, timestamp + \".\" + body)."),
        copyBlock("signing secret", d.signing_secret));
      box.hidden = false;
    } else {
      box.hidden = true;
    }
    e.target.reset();
    alertFormatHint();
    await loadAlerts();
  } catch {}
});

// ------------------------------------------------------------------ audit
// Every type the backend records (a contract test keeps this list complete), grouped for the filter.
const AUDIT_TYPES = [
  ["Sign-in", { AUTH_LOGIN_SUCCESS: "Signed in", AUTH_LOGIN_FAILURE: "Sign-in failed", AUTH_MFA_FAILURE: "Wrong MFA code",
    AUTH_SSO_FAILURE: "SSO sign-in failed", AUTH_ACCOUNT_THROTTLED: "Account throttled", AUTH_LOGOUT: "Signed out" }],
  ["Two-factor", { MFA_SETUP_STARTED: "MFA setup started", MFA_ENABLED: "MFA turned on", MFA_DISABLED: "MFA turned off",
    MFA_RESET: "MFA reset by an admin", MFA_RECOVERY_CODE_USED: "Recovery code used",
    MFA_RECOVERY_CODES_REGENERATED: "Recovery codes replaced", MFA_PASSWORD_CHECK_FAILED: "MFA change: wrong password",
    PASSKEY_REGISTERED: "Passkey added", PASSKEY_REMOVED: "Passkey removed", AUTH_PASSKEY_FAILURE: "Passkey check failed",
    PASSKEY_CLONE_SUSPECTED: "Passkey counter went back (possible copy)" }],
  ["Passwords", { PASSWORD_CHANGE: "Password changed", PASSWORD_CHANGE_FAILED: "Password change failed",
    PASSWORD_RESET_REQUESTED: "Reset requested", PASSWORD_RESET_REQUESTED_UNKNOWN: "Reset requested (unknown email)",
    PASSWORD_RESET_ISSUED: "Reset link issued by an admin", PASSWORD_RESET_COMPLETED: "Password reset completed",
    PASSWORD_RESET_FAILED: "Password reset failed" }],
  ["Access", { AUTHORIZATION_DENIED: "Permission denied", TENANT_ACCESS_DENIED: "Cross-tenant access denied",
    USER_CREATED: "User created", USER_ACTIVATED: "User reactivated", USER_DEACTIVATED: "User deactivated",
    ROLE_CHANGED: "Role changed", API_KEY_CREATED: "API key created", API_KEY_REVOKED: "API key revoked",
    SYSTEM_ADMIN_BOOTSTRAPPED: "First system admin created" }],
  ["Decoys and events", { PROJECT_CREATED: "Project created", PROJECT_DELETED: "Project deleted",
    HONEY_TOKEN_CREATED: "Decoy created", HONEY_TOKEN_GENERATED: "Decoy generated", HONEY_TOKEN_ROTATED: "Decoy rotated",
    HONEY_TOKEN_FILE_DOWNLOADED: "Decoy downloaded as a file",
    HONEY_TOKEN_REVOKED: "Decoy revoked", DETECTION_EVENT_MANUALLY_RECORDED: "Event entered by hand",
    DETECTION_HITS_SUPPRESSED: "Repeated hits suppressed", DETECTION_EVENTS_RECOVERED: "Hits recovered after an outage",
    EVENTS_EXPORTED: "Events exported", CLOUD_CANARY_PROVISIONED: "AWS key decoy created in AWS",
    CLOUD_CANARY_FAILED: "AWS refused an AWS key decoy", CLOUD_CANARY_DELETED: "AWS key decoy deleted from AWS" }],
  ["Integrations and alerts", { INTEGRATION_CREDENTIAL_CREATED: "Integration credential created",
    INTEGRATION_CREDENTIAL_REVOKED: "Integration credential revoked",
    INTEGRATION_REPORT_REJECTED_SECRET: "Hook report refused (bad signature)",
    ALERT_DESTINATION_CREATED: "Alert destination added", ALERT_DESTINATION_DISABLED: "Alert destination disabled",
    ALERT_TEST_REQUESTED: "Test alert sent", ALERT_DELIVERY_FAILED: "Alert delivery failed" }],
  ["Tenants and retention", { TENANT_CREATED: "Tenant created", TENANT_DELETED: "Tenant deactivated",
    RETENTION_PURGE: "Retention purge" }],
];
const AUDIT_LABELS = Object.assign({}, ...AUDIT_TYPES.map(([, types]) => types));
$("#audit-type").append(...AUDIT_TYPES.map(([group, types]) =>
  el("optgroup", { label: group }, Object.entries(types).map(([code, name]) => el("option", { value: code }, name)))));

async function loadAudit(reset) {
  if (reset) { state.auditCursor = null; state.auditShown = 0; $("#audit").replaceChildren(); }
  const type = $("#audit-type").value;
  const params = new URLSearchParams({ limit: "100" });
  if (type) params.set("event_type", type);
  if (state.auditCursor) params.set("before_id", state.auditCursor);
  const [rows, emails] = await Promise.all([api("GET", `/api/v1/audit-logs?${params}`), userEmails()]);
  const actor = (r) => r.actor_user_id
    ? (emails.get(r.actor_user_id) || `user #${r.actor_user_id}`)
    : el("span", { class: "muted" }, r.actor_source === "api" ? "Unauthenticated request" : (r.actor_source || "System"));
  const sevClass = (v) => v === "WARNING" ? "warn" : (v === "ERROR" || v === "CRITICAL") ? "bad" : "";
  $("#audit").append(table([
    { label: "When", render: (r) => fmtTime(r.created_at) },
    { label: "Event", render: (r) => twoLine(AUDIT_LABELS[r.event_type] || r.event_type, r.event_type) },
    { label: "Severity", render: (r) => badge(r.severity.charAt(0) + r.severity.slice(1).toLowerCase(), sevClass(r.severity)) },
    { label: "Message", key: "message", wrap: true },
    { label: "Actor", render: actor },
  ], rows, state.auditShown ? "No older entries" : type ? ["No entries of this type", "Choose “All events” to see everything."] : "No audit entries yet"));
  state.auditShown = (state.auditShown || 0) + rows.length;
  state.auditCursor = rows.length ? rows[rows.length - 1].id : null;
  $("#audit-more").hidden = rows.length < 100;
  $("#audit-note").textContent = state.auditShown ? `${fmtNum(state.auditShown)} shown, newest first` : "";
}
$("#audit-form").addEventListener("submit", (e) => { e.preventDefault(); loadAudit(true).catch(() => {}); });
$("#audit-type").addEventListener("change", () => loadAudit(true).catch(() => {}));
$("#audit-more").addEventListener("click", () => loadAudit(false).catch(() => {}));

// ------------------------------------------------------------------ evidence
const VERDICT_PATHS = { ok: ["M12 3 20 6.5v5.5c0 4.6-3.3 7.9-8 9-4.7-1.1-8-4.4-8-9V6.5z", "m8.5 12 2.5 2.5 4.5-5"],
                        bad: ["M12 3 20 6.5v5.5c0 4.6-3.3 7.9-8 9-4.7-1.1-8-4.4-8-9V6.5z", "M12 8v5", "M12 16.2v.1"] };
function verdict(ok, title, detail) {
  const NS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  for (const d of VERDICT_PATHS[ok ? "ok" : "bad"]) {
    const p = document.createElementNS(NS, "path");
    p.setAttribute("d", d);
    svg.append(p);
  }
  return el("div", { class: `verdict ${ok ? "ok" : "bad"}`, role: "status" }, svg, el("strong", {}, title), el("p", {}, detail));
}

// What each verifier failure means, in the words an investigator needs (codes stay visible).
const CHAIN_FAILURES = {
  broken_link: "A link's hash does not match the record it covers or the link before it",
  sequence_gap: "Links are missing from the sequence",
  head_mismatch: "The stored head does not match the last link",
  event_modified: "A detection event changed after it was chained",
  event_missing: "A chained detection event no longer exists",
  record_modified: "An audit record changed after it was sealed",
  record_missing: "A sealed audit record no longer exists",
  unchained_after_chain_start: "Events were written without a link, bypassing the application",
  unsealed_records: "Audit records older than the last seal were never sealed",
  checkpoint_mismatch: "The chain disagrees with an exported checkpoint",
  checkpoint_ahead_of_chain: "An exported checkpoint is ahead of the chain: links were removed",
};

// Shows a chain verification: the verdict, the head to compare with an exported checkpoint, and
// any failures as recorded by the verifier.
function renderVerification(box, r, { title, pendingLabel, pendingKey }) {
  const hash = el("code", { class: "mono hash" }, r.head_hash);
  const copy = el("button", { class: "secondary copy-btn", type: "button", "aria-label": "Copy head hash" }, "Copy");
  copy.addEventListener("click", async () => {
    copy.textContent = (await copyText(r.head_hash, hash)) === "copied" ? "Copied" : "Selected";
    setTimeout(() => { copy.textContent = "Copy"; }, 1800);
  });
  const checkedAt = new Date().toISOString();
  const facts = el("dl", { class: "facts wide" }, [
    detailRow("Links recomputed", fmtNum(r.links_checked)),
    detailRow("Head sequence", fmtNum(r.head_seq)),
    detailRow("Head hash", el("span", { class: "hash-line" }, hash, copy)),
    detailRow(pendingLabel, fmtNum(r[pendingKey] || 0)),
    detailRow("Checked", fmtTime(checkedAt)),
  ].flat().filter(Boolean));
  const failures = r.failures && r.failures.length ? [
    el("h3", { class: "verify-sub" }, `Failures (${r.failures.length}${r.failures.length >= 50 ? ", first 50" : ""})`),
    table([
      { label: "Problem", wrap: true, render: (f) => twoLine(CHAIN_FAILURES[f.kind] || f.kind, f.kind) },
      { label: "Details", wrap: true, render: (f) => {
          const { kind, ...rest } = f;
          return el("span", { class: "mono" }, Object.entries(rest).map(([k, v]) => `${k}=${typeof v === "object" ? JSON.stringify(v) : v}`).join("  "));
        } },
    ], r.failures),
  ] : [];
  box.replaceChildren(
    verdict(r.ok, r.ok ? `${title} intact` : `${title} failed verification`,
      r.ok ? "Every link was recomputed from the stored records and matches. Compare the head with your latest exported checkpoint."
           : "The problems found are listed below. Preserve the database and the exported checkpoints before investigating."),
    el("div", { class: "verify-body" }, facts, ...failures, r.note ? el("p", { class: "hint verify-note" }, r.note) : null));
}

async function runVerification(button, box, path, opts) {
  button.disabled = true;
  const label = button.textContent;
  button.textContent = "Verifying…";
  box.replaceChildren();
  try { renderVerification(box, await api("GET", path), opts); }
  catch {} finally { button.disabled = false; button.textContent = label; }
}

$("#ev-verify").addEventListener("click", (e) => {
  let q = "";
  if (isSysAdmin()) {
    const slug = $("#ev-tenant").value;
    if (!slug) { status("Choose a tenant to verify.", true); return; }
    q = `?tenant_slug=${encodeURIComponent(slug)}`;
  }
  runVerification(e.currentTarget, $("#ev-result"), `/api/v1/evidence/verify${q}`,
    { title: "Evidence chain", pendingLabel: "Events without a link", pendingKey: "unchained_events" });
});
$("#audit-verify").addEventListener("click", (e) => {
  runVerification(e.currentTarget, $("#audit-verify-result"), "/api/v1/audit-logs/verify",
    { title: "Audit log chain", pendingLabel: "Not yet sealed", pendingKey: "unsealed_records" });
});

// ------------------------------------------------------------------ CSV export
$("#events-export").addEventListener("click", async () => {
  busy(1);
  try {
    const p = eventFilters();
    p.delete("severity"); const sev = $("#events-filter [name=severity]").value; if (sev) p.set("severity", sev);
    const resp = await fetch(`/api/v1/detection-events/export${p.toString() ? "?" + p : ""}`, {
      headers: { Authorization: `Bearer ${state.token}` }, credentials: "omit", cache: "no-store" });
    if (!resp.ok) { status(`Export failed (HTTP ${resp.status}).`, true); return; }
    const blob = await resp.blob();
    const name = (resp.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    const a = el("a", { href: URL.createObjectURL(blob), download: name ? name[1] : "honeyshield-events.csv" });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 10000);
    const rows = resp.headers.get("X-Export-Rows");
    status(`Exported ${rows} event(s)${resp.headers.get("X-Export-Truncated") === "true" ? " (first 50,000)" : ""}.`);
  } catch { status("Export failed: the API is unreachable.", true); }
  finally { busy(-1); }
});

// ------------------------------------------------------------------ API keys
function when(iso) { return iso ? fmtTime(iso) : el("span", { class: "muted" }, "Never"); }

async function loadKeys() {
  const keys = await api("GET", "/api/v1/api-keys");
  const live = (k) => !k.revoked_at && new Date(k.expires_at) > new Date();
  $("#keys-table").replaceChildren(table([
    { label: "Name", key: "name" },
    { label: "Key", key: "key_id", mono: true },
    { label: "Owner", render: (k) => k.owner_email || String(k.owner_user_id) },
    { label: "Scope", render: (k) => (k.scope === "write" ? "Read and write" : "Read only") },
    { label: "Last used", render: (k) => when(k.last_used_at) },
    { label: "Expires", render: (k) => when(k.expires_at) },
    { label: "Status", render: (k) => (k.revoked_at ? badge("Revoked", "bad") : live(k) ? badge("Active", "ok") : badge("Expired")) },
    { label: "", render: (k) => live(k) ? el("button", { class: "danger", onclick: async () => {
        try { await api("DELETE", `/api/v1/api-keys/${k.key_id}`); status(`Key ${k.name} revoked.`); await loadKeys(); } catch {}
      } }, "Revoke") : "" },
  ], keys, "No API keys yet"));
}

$("#key-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    const k = await api("POST", "/api/v1/api-keys",
                        { name: f.get("name"), scope: f.get("scope"), expires_in_days: Number(f.get("expires_in_days")) });
    const box = $("#key-secret");
    box.replaceChildren(
      el("strong", {}, `API key "${k.name}" (shown once). Send it as: Authorization: Bearer <key>`),
      el("pre", { class: "mono" }, k.api_key));
    box.hidden = false;
    e.target.reset();
    await loadKeys();
  } catch {}
});

// ------------------------------------------------------------------ account
$("#password-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api("POST", "/auth/change-password", { current_password: f.get("current_password"), new_password: f.get("new_password") },
              { credentialCheck: true });
    e.target.reset();
    signOutLocal("Password changed. All sessions were signed out; sign in with the new password.");
  } catch {}
});

$("#logout").addEventListener("click", async () => {
  try { await api("POST", "/auth/logout"); } catch {}
  signOutLocal("Signed out on every device.");
});

$$("#nav button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
$("#status").addEventListener("click", () => { $("#status").hidden = true; });

// ------------------------------------------------------------------ boot
const SSO_ERRORS = {
  session_expired: "The sign-in took too long or was started in another tab. Try again.",
  idp_error: "The identity provider returned an error.",
  idp_unreachable: "The identity provider could not be reached.",
  idp_denied: "Sign-in was cancelled or denied at the identity provider.",
  invalid_token: "The identity provider's response could not be verified.",
  no_email: "The identity provider did not send an email address.",
  email_unverified: "The identity provider did not confirm your email address.",
  unknown_user: "No HoneyShield account uses this email. Ask an administrator to add you.",
  account_disabled: "This account is disabled.",
  mfa_required: "Your account uses HoneyShield two-factor authentication, which this SSO sign-in did not satisfy. Sign in with your password and code.",
  invalid_code: "The sign-in link expired. Try again.",
};

async function offerSso() {
  try {
    const cfg = await fetch("/auth/oidc/config", { credentials: "omit", cache: "no-store" }).then((r) => r.json());
    if (cfg.enabled) {
      $("#sso-button").textContent = `Sign in with ${cfg.display_name || "SSO"}`;
      $("#sso-row").hidden = false;
    }
  } catch {}
}

async function finishSso() {
  const params = new URLSearchParams(location.hash.slice(1));
  history.replaceState(null, "", location.pathname);   // the code is single use: drop it from history
  if (params.has("sso_error")) {
    signOutLocal(SSO_ERRORS[params.get("sso_error")] || "Single sign-on failed.", true);
    return;
  }
  try {
    const r = await api("POST", "/auth/oidc/exchange", { code: params.get("sso_code") }, { credentialCheck: true });
    await startSession(r.access_token);
  } catch { signOutLocal(SSO_ERRORS.invalid_code, true); }
}

// Links that carry state in the fragment (SSO return, password reset). Handled at start-up and
// when the fragment changes in an already-open console tab (no page load happens then).
async function routeFragment() {
  if (location.hash.startsWith("#sso_code=") || location.hash.startsWith("#sso_error=")) {
    try { sessionStorage.removeItem("hs_token"); } catch {}
    await finishSso();
    return true;
  }
  if (location.hash.startsWith("#reset=")) {
    // A reset link: start signed out (signOutLocal also forgets any stored session).
    signOutLocal();
    showAuthView("reset");
    return true;
  }
  return false;
}
window.addEventListener("hashchange", () => { routeFragment().catch(() => {}); });

(async () => {
  offerSso();
  if (await routeFragment()) return;
  let saved = null;
  try { saved = sessionStorage.getItem("hs_token"); } catch {}
  if (saved) { try { await startSession(saved); return; } catch { signOutLocal(); } }
  signOutLocal();
})();
