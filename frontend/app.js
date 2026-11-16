"use strict";
// MC Sentinel dashboard. All server-provided strings go through esc().

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const NA = '<span class="unavail">Data unavailable</span>';
const fmtTs = (t) => (t ? new Date(t * 1000).toLocaleString() : "—");
const ago = (t) => {
  if (!t) return "—";
  const s = Date.now() / 1000 - t;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};
const sevBadge = (s) => `<span class="badge b-${esc(s === "info" ? "" : s)}">${esc(s)}</span>`;

let TOKEN = null;
try { TOKEN = sessionStorage.getItem("mcs_token"); } catch (_) {}

async function api(path, opts = {}) {
  const r = await fetch(path, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}`, ...(opts.headers || {}) },
  });
  if (r.status === 401) { showLogin(); throw new Error("Not signed in"); }
  const ct = r.headers.get("content-type") || "";
  const body = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(body?.detail ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : `HTTP ${r.status}`);
  return body;
}

async function download(path, filename) {
  const r = await fetch(path, { headers: { Authorization: `Bearer ${TOKEN}` } });
  if (!r.ok) return alert(`Export failed: HTTP ${r.status}`);
  const url = URL.createObjectURL(await r.blob());
  const a = Object.assign(document.createElement("a"), { href: url, download: filename });
  document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

// ------------------------------------------------------------------ auth & nav
function showLogin() { $("#app").hidden = true; $("#login").hidden = false; }
$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  TOKEN = $("#token").value.trim();
  try {
    await api("/api/stats");
    try { sessionStorage.setItem("mcs_token", TOKEN); } catch (_) {}
    $("#login").hidden = true; $("#app").hidden = false; show("overview");
  } catch (err) { $("#login-err").textContent = "Invalid token."; }
});
$("#logout").addEventListener("click", () => {
  try { sessionStorage.removeItem("mcs_token"); } catch (_) {}
  TOKEN = null; showLogin();
});

const loaders = {};
let pollTimer = null;
function show(view) {
  $$(".view").forEach((v) => (v.hidden = v.id !== `view-${view}`));
  $$(".nav").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  clearInterval(pollTimer);
  loaders[view]?.();
}
$$(".nav").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
$$("[data-refresh]").forEach((b) => b.addEventListener("click", () => loaders[b.dataset.refresh]()));

function bars(items) {
  if (!items?.length) return NA;
  const max = Math.max(...items.map((i) => i.n));
  return items.map((i) => `<div class="bar-row"><span class="lbl" title="${esc(i.label)}">${esc(i.label)}</span>
    <div><div class="bar" style="width:${(i.n / max) * 100}%"></div></div><span class="n">${i.n}</span></div>`).join("");
}

// ------------------------------------------------------------------ overview
loaders.overview = async () => {
  const s = await api("/api/stats");
  const t = [
    ["Servers indexed", s.servers_indexed], ["Online now", s.servers_online], ["Seen in 24h", s.servers_seen_24h],
    ["Players reported", s.players_reported], ["Running scans", s.scan_jobs_running],
    ["Federation servers", s.federation_servers], ["Known identities", s.federation_identities],
    ["Players online (fed.)", s.online_now], ["Active bans", s.active_bans],
  ];
  $("#stat-tiles").innerHTML = t.map(([k, v]) => `<div class="tile"><div class="v">${esc(v)}</div><div class="k">${esc(k)}</div></div>`).join("");
  $("#sw-bars").innerHTML = bars(s.software);
  $("#ver-bars").innerHTML = bars(s.versions);
  const al = await api("/api/alerts?days=7");
  $("#ov-alerts").innerHTML = alertList(al.slice(0, 8)) || '<p class="muted">No alerts in the last 7 days.</p>';
  bindUuidLinks($("#ov-alerts"));
};

// ------------------------------------------------------------------ discovery
loaders.discovery = async () => {
  const p = await api("/api/scan/policy");
  $("#scan-policy").textContent = `Default ${p.default_rate} conn/s (max ${p.max_rate}), concurrency ${p.concurrency}, ` +
    `timeout ${p.timeout_s}s, max ${p.max_targets_per_job.toLocaleString()} targets/job. ` +
    (p.reserved_ranges_excluded ? "Private/reserved ranges are excluded." : "Private ranges ALLOWED (lab mode).") +
    ` ${p.exclusion_count} opt-out range(s).`;
  await Promise.all([loadJobs(), loadExcl()]);
  pollTimer = setInterval(loadJobs, 2000);
};
async function loadJobs() {
  const jobs = await api("/api/scan/jobs");
  $("#jobs").innerHTML = jobs.length ? `<div class="table-wrap"><table><thead><tr><th>Job</th><th>Kind</th><th>Status</th>
    <th>Progress</th><th>Found</th><th>Skipped</th><th>Rate</th><th></th></tr></thead><tbody>${jobs.map((j) => {
      const pct = j.total ? Math.min(100, (j.done / j.total) * 100) : 0;
      const errs = Object.entries(j.errors || {}).map(([k, v]) => `${k}: ${v}`).join(", ");
      return `<tr><td class="mono">${esc(j.job_id)}<div class="muted small">${esc(j.summary)}</div></td>
        <td>${esc(j.kind)}</td><td>${sevBadgeStatus(j.status)}</td>
        <td style="min-width:140px"><div class="progress"><div style="width:${pct}%"></div></div>
          <span class="small muted">${j.done.toLocaleString()} / ${j.total.toLocaleString()}</span>
          ${errs ? `<div class="small muted">${esc(errs)}</div>` : ""}</td>
        <td class="num">${j.found}</td><td class="num">${j.skipped}</td><td class="num">${esc(j.rate)}/s</td>
        <td>${j.status === "running" ? `<button data-cancel="${esc(j.job_id)}">Cancel</button>` : ""}</td></tr>`;
    }).join("")}</tbody></table></div>` : '<p class="muted">No scan jobs yet.</p>';
  $$("[data-cancel]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/scan/jobs/${b.dataset.cancel}/cancel`, { method: "POST" }); loadJobs();
  }));
}
const sevBadgeStatus = (s) => `<span class="badge ${s === "completed" ? "b-ok" : s === "running" ? "b-low" : s === "failed" ? "b-high" : ""}">${esc(s)}</span>`;

async function loadExcl() {
  const ex = await api("/api/exclusions");
  $("#excl-list").innerHTML = ex.length ? `<table><tbody>${ex.map((e) => `<tr><td class="mono">${esc(e.cidr)}</td>
    <td>${esc(e.reason || "")}</td><td><button data-del="${esc(e.cidr)}">Remove</button></td></tr>`).join("")}</tbody></table>`
    : '<p class="muted small">No custom exclusions.</p>';
  $$("[data-del]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/exclusions?cidr=${encodeURIComponent(b.dataset.del)}`, { method: "DELETE" }); loadExcl();
  }));
}
$("#scan-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#scan-err").textContent = "";
  try {
    await api("/api/scan/jobs", { method: "POST", body: JSON.stringify({
      targets: $("#scan-targets").value.split(/\s+/).filter(Boolean),
      ports: $("#scan-ports").value.split(/[,\s]+/).filter(Boolean).map(Number),
      rate: Number($("#scan-rate").value) || null,
      concurrency: Number($("#scan-conc").value) || null,
    }) });
    $("#scan-targets").value = "";
    loadJobs();
  } catch (err) { $("#scan-err").textContent = err.message; }
});
$("#recheck").addEventListener("click", async () => { await api("/api/scan/recheck", { method: "POST" }); loadJobs(); });
$("#excl-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  try {
    const r = await api("/api/exclusions", { method: "POST", body: JSON.stringify({ cidr: $("#excl-cidr").value, reason: $("#excl-reason").value }) });
    if (r.purged_servers) alert(`Excluded. Purged ${r.purged_servers} previously collected server(s).`);
    $("#excl-cidr").value = $("#excl-reason").value = "";
    loadExcl();
  } catch (err) { alert(err.message); }
});

// ------------------------------------------------------------------ server index
const srvState = { offset: 0, limit: 50, total: 0 };
function srvParams() {
  const p = new URLSearchParams();
  const add = (k, v) => v !== "" && v != null && p.set(k, v);
  add("q", $("#f-q").value.trim()); add("software", $("#f-software").value); add("version", $("#f-version").value.trim());
  add("online", $("#f-online").value); add("mod_loader", $("#f-mod").value); add("min_players", $("#f-minp").value);
  return p;
}
loaders.servers = async () => {
  const s = await api("/api/stats");
  const sel = $("#f-software"), cur = sel.value;
  sel.innerHTML = '<option value="">Any software</option>' + s.software.map((x) => `<option>${esc(x.label)}</option>`).join("");
  sel.value = cur;
  loadServers();
};
async function loadServers() {
  const p = srvParams(); p.set("sort", $("#f-sort").value); p.set("limit", srvState.limit); p.set("offset", srvState.offset);
  const r = await api(`/api/servers?${p}`);
  srvState.total = r.total;
  $("#srv-table tbody").innerHTML = r.items.length ? r.items.map((s) => `<tr class="click" data-sid="${esc(s.server_id)}">
    <td><strong>${esc(s.name)}</strong><div class="muted small">${esc((s.motd || "").split("\n").slice(1).join(" "))}</div></td>
    <td>${esc(s.version_name) || NA}</td><td>${esc(s.software || "Unknown")}${s.mod_loader ? ` <span class="badge">${esc(s.mod_loader)}</span>` : ""}</td>
    <td class="num">${s.players_online ?? "?"} / ${s.players_max ?? "?"}</td>
    <td><span class="dot ${s.online ? "on" : ""}"></span>${s.online ? "Online" : "Offline"}</td>
    <td>${ago(s.last_seen)}</td></tr>`).join("") : `<tr><td colspan="6" class="muted">No servers match. Run a discovery scan first.</td></tr>`;
  $("#pg-info").textContent = r.total ? `${srvState.offset + 1}–${Math.min(srvState.offset + srvState.limit, r.total)} of ${r.total}` : "";
  $$("#srv-table tr[data-sid]").forEach((tr) => tr.addEventListener("click", () => openServer(tr.dataset.sid)));
}
$("#srv-filter").addEventListener("submit", (e) => { e.preventDefault(); srvState.offset = 0; loadServers(); });
$("#pg-prev").addEventListener("click", () => { srvState.offset = Math.max(0, srvState.offset - srvState.limit); loadServers(); });
$("#pg-next").addEventListener("click", () => { if (srvState.offset + srvState.limit < srvState.total) { srvState.offset += srvState.limit; loadServers(); } });
$("#exp-csv").addEventListener("click", () => download(`/api/servers/export?format=csv&${srvParams()}`, "servers.csv"));
$("#exp-json").addEventListener("click", () => download(`/api/servers/export?format=json&${srvParams()}`, "servers.json"));

function sparkline(hist) {
  const pts = hist.filter((h) => h.online && h.players_online != null);
  if (pts.length < 2) return '<p class="muted small">Not enough history yet. Re-check servers to build a time series.</p>';
  const w = 500, h = 110, pad = 4;
  const t0 = pts[0].ts, t1 = pts[pts.length - 1].ts || t0 + 1;
  const max = Math.max(1, ...pts.map((p) => p.players_online));
  const x = (t) => pad + ((t - t0) / (t1 - t0 || 1)) * (w - 2 * pad);
  const y = (v) => h - pad - (v / max) * (h - 2 * pad);
  const d = pts.map((p, i) => `${i ? "L" : "M"}${x(p.ts).toFixed(1)},${y(p.players_online).toFixed(1)}`).join("");
  return `<svg viewBox="0 0 ${w} ${h}" width="100%" role="img" aria-label="Players online over time">
    <path d="${d}" fill="none" stroke="var(--bar)" stroke-width="2"/></svg>
    <div class="hist-axis"><span>${fmtTs(t0)}</span><span>peak ${max}</span><span>${fmtTs(t1)}</span></div>`;
}
async function openServer(id) {
  const s = await api(`/api/servers/${id}`);
  drawer(`<h3>${esc(s.name)}</h3><div class="motd">${esc(s.motd) || NA}</div>
    <dl class="kv">
      <dt>Server ID</dt><dd class="mono">${esc(s.server_id)}</dd>
      <dt>Connection</dt><dd class="unavail">Hidden by policy</dd>
      <dt>Status</dt><dd><span class="dot ${s.online ? "on" : ""}"></span>${s.online ? "Online" : "Offline"} (checked ${ago(s.last_checked)})</dd>
      <dt>Version</dt><dd>${esc(s.version_name) || NA} ${s.protocol != null ? `<span class="muted">(protocol ${s.protocol})</span>` : ""}</dd>
      <dt>Software</dt><dd>${esc(s.software || "Unknown")}</dd>
      <dt>Mods</dt><dd>${s.mod_loader ? `${esc(s.mod_loader)}${s.mods_count != null ? `, ${s.mods_count} mods advertised` : ""}` : "None advertised"}</dd>
      <dt>Players</dt><dd>${s.players_online ?? "?"} / ${s.players_max ?? "?"}<div class="muted small">${esc(s.player_sample_note)}</div></dd>
      <dt>Player list</dt><dd class="unavail">Not collected. Status samples are partial and names are discarded.</dd>
      <dt>Secure chat</dt><dd>${s.enforces_secure_chat == null ? NA : s.enforces_secure_chat ? "Enforced" : "Not enforced"}</dd>
      <dt>Latency</dt><dd>${s.latency_ms != null ? `${s.latency_ms} ms` : NA}</dd>
      <dt>Observed uptime</dt><dd>${s.observed_uptime != null ? `${Math.round(s.observed_uptime * 100)}% of ${s.history.length} checks` : NA}</dd>
      <dt>Peak players seen</dt><dd>${s.peak_players ?? NA}</dd>
      <dt>First / last seen</dt><dd>${fmtTs(s.first_seen)}<br>${fmtTs(s.last_seen)}</dd>
    </dl><h3>Players online over time</h3>${sparkline(s.history)}`);
}
function drawer(html) { $("#drawer-content").innerHTML = html; $("#drawer").hidden = false; }
$("#drawer-close").addEventListener("click", () => ($("#drawer").hidden = true));
$("#drawer").addEventListener("click", (e) => { if (e.target.id === "drawer") $("#drawer").hidden = true; });

// ------------------------------------------------------------------ verification rendering
function verificationCard(v) {
  const verdicts = {
    premium_name: ["b-ok", "Premium name registered"], no_premium_account: ["b-medium", "No premium account: offline-only name"],
    verified_premium: ["b-ok", "Verified premium account"], offline_identity: ["b-medium", "Offline-mode identity (unauthenticated)"],
    unregistered_v4: ["b-high", "Unregistered online-style UUID"], unverified: ["", "Could not verify (Mojang unavailable)"],
    invalid: ["b-high", "Invalid input"], unknown: ["", "Unknown"],
  };
  const [cls, label] = verdicts[v.verdict] || ["", v.verdict];
  const rows = [];
  if (v.username) rows.push(["Username", esc(v.username)]);
  if (v.uuid) rows.push(["UUID", `<span class="mono">${esc(v.uuid)}</span> <span class="badge">v${esc(v.uuid_version)} · ${esc(v.uuid_kind)}</span>`]);
  if (v.premium_uuid) rows.push(["Premium UUID", `<span class="mono">${esc(v.premium_uuid)}</span>`]);
  if (v.current_name) rows.push(["Current name", esc(v.current_name)]);
  if (v.offline_uuid) rows.push(["Offline UUID", `<span class="mono">${esc(v.offline_uuid)}</span>`]);
  if (v.offline_uuid_for_name) rows.push(["Offline clone UUID", `<span class="mono">${esc(v.offline_uuid_for_name)}</span>`]);
  return `<div class="result"><span class="badge ${cls}">${esc(label)}</span>
    <dl class="kv">${rows.map(([k, val]) => `<dt>${k}</dt><dd>${val}</dd>`).join("")}</dl>
    ${(v.checks || []).map((c) => `<div class="check">${c.result === "pass" ? "✓" : c.result === "fail" ? "✗" : "?"} ${esc(c.detail)}</div>`).join("")}</div>`;
}

// ------------------------------------------------------------------ player search
loaders.players = () => $("#player-q").focus();
$("#player-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const out = $("#player-out");
  out.innerHTML = '<p class="muted">Searching…</p>';
  try {
    const r = await api(`/api/players/search?q=${encodeURIComponent($("#player-q").value.trim())}`);
    const conf = r.results.filter((x) => x.match === "confirmed"), poss = r.results.filter((x) => x.match !== "confirmed");
    const block = (x) => `<div class="result"><div class="row" style="justify-content:space-between;align-items:center">
        <div><span class="badge ${x.match === "confirmed" ? "b-ok" : "b-medium"}">${esc(x.match)}</span>
          <span class="mono">${esc(x.uuid)}</span> <span class="badge">${esc(x.uuid_kind)}</span></div>
        <button data-uuid="${esc(x.uuid)}">Open profile</button></div>
      <p class="small muted">${esc(x.reason)}</p>
      ${x.servers.length ? `<table><thead><tr><th>Server</th><th>Status</th><th>Sessions</th><th>Names</th><th>Last seen</th></tr></thead><tbody>
        ${x.servers.map((s) => `<tr><td><strong>${esc(s.server)}</strong><div class="muted small">${esc(s.description || "")}</div></td>
          <td>${presence(s.status)}</td><td class="num">${s.sessions}</td><td>${esc(s.names.join(", "))}</td><td>${ago(s.last_seen)}</td></tr>`).join("")}
      </tbody></table>` : '<p class="muted small">Moderation records only, no sessions.</p>'}</div>`;
    out.innerHTML = `<div class="card"><h3>Identity verification</h3>${verificationCard(r.verification)}</div>
      <div class="card"><h3>Confirmed matches</h3>${conf.length ? conf.map(block).join("") : '<p class="muted">No confirmed records in participating servers.</p>'}</div>
      <div class="card"><h3>Possible matches <span class="muted small">(same name or derived identity, NOT confirmed as the same person)</span></h3>
        ${poss.length ? poss.map(block).join("") : '<p class="muted">None.</p>'}</div>
      <div class="card"><h3>Data sources</h3>
        <p><strong>Moderation federation:</strong> ${r.sources.federation.servers} participating server(s). ${esc(r.sources.federation.note)}</p>
        <p><strong>Public scan data:</strong> <span class="unavail">Data unavailable.</span> ${esc(r.sources.public_scan.note)}</p></div>`;
    bindUuidLinks(out);
  } catch (err) { out.innerHTML = `<p class="err">${esc(err.message)}</p>`; }
});
const presence = (s) => s === "online" ? '<span class="dot on"></span>Online' : s === "unknown"
  ? '<span class="dot unk"></span>Unknown <span class="muted small">(server not reporting)</span>' : '<span class="dot"></span>Offline';
function bindUuidLinks(root) { $$("[data-uuid]", root).forEach((b) => b.addEventListener("click", () => openProfile(b.dataset.uuid))); }

// ------------------------------------------------------------------ profile
let currentProfile = null;
async function openProfile(uuid) {
  show("profile");
  $("#prof-out").innerHTML = '<p class="muted">Loading…</p>';
  try {
    const p = await api(`/api/players/${uuid}/profile`);
    currentProfile = p.uuid;
    const st = p.stats, r = p.risk;
    $("#prof-title").textContent = p.names[0]?.name ? `${p.names[0].name}` : p.uuid;
    const maxH = Math.max(1, ...p.activity.hour_utc);
    const max30 = Math.max(1, ...p.activity.last30.map((d) => d.logins));
    $("#prof-out").innerHTML = `
      <div class="tiles">
        <div class="tile"><div class="v"><span class="badge ${r.level === "high" ? "b-high" : r.level === "elevated" ? "b-medium" : r.level === "low" ? "b-low" : "b-ok"}">${esc(r.level)}</span></div><div class="k">Risk (${r.score}/100)</div></div>
        <div class="tile"><div class="v">${esc(st.total_playtime) || "—"}</div><div class="k">Est. playtime</div></div>
        <div class="tile"><div class="v">${st.sessions}</div><div class="k">Sessions</div></div>
        <div class="tile"><div class="v">${esc(st.avg_session) || "—"}</div><div class="k">Avg session</div></div>
        <div class="tile"><div class="v">${st.logins_per_day ?? "—"}</div><div class="k">Logins / day</div></div>
        <div class="tile"><div class="v">${p.punishments.filter((x) => x.active).length}</div><div class="k">Active punishments</div></div>
      </div>
      <div class="card"><h3>Risk indicators</h3><p class="small muted">${esc(r.disclaimer)}</p>
        ${r.indicators.length ? r.indicators.map((i) => `<div class="ind ${esc(i.severity)}">
          <strong>${esc(i.title)}</strong> ${sevBadge(i.severity)} <span class="badge">confidence: ${esc(i.confidence)}</span>
          <span class="muted small mono">${esc(i.code)}</span>
          <ul>${i.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>${i.note ? `<div class="note">${esc(i.note)}</div>` : ""}</div>`).join("")
          : '<p class="muted">No indicators.</p>'}</div>
      <div class="grid2">
        <div class="card"><h3>Identity</h3>${verificationCard(p.verification)}
          <p class="small"><strong>Names used:</strong> ${p.names.map((n) => `${esc(n.name)} (${n.sessions})`).join(", ") || "—"}</p></div>
        <div class="card"><h3>Presence</h3>${p.presence.length ? `<table><tbody>${p.presence.map((s) => `<tr><td><strong>${esc(s.server)}</strong></td>
          <td>${presence(s.status)}</td><td>${ago(s.last_seen)}</td></tr>`).join("")}</tbody></table>` : NA}
          <p class="small muted">First seen ${fmtTs(st.first_seen)} · last seen ${fmtTs(st.last_seen)}</p></div>
      </div>
      <div class="grid2">
        <div class="card"><h3>Logins by hour (UTC)</h3>
          ${st.sessions ? `<div class="hist">${p.activity.hour_utc.map((n, h) => `<div title="${h}:00 UTC: ${n}" style="height:${(n / maxH) * 100}%"></div>`).join("")}</div>
          <div class="hist-axis"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>` : NA}</div>
        <div class="card"><h3>Logins, last 30 days</h3>
          <div class="hist">${p.activity.last30.map((d) => `<div title="${d.day}: ${d.logins}" style="height:${(d.logins / max30) * 100}%"></div>`).join("")}</div>
          <div class="hist-axis"><span>${esc(p.activity.last30[0].day)}</span><span>${esc(p.activity.last30[29].day)}</span></div></div>
      </div>
      <div class="card"><h3>Moderation history</h3>${p.punishments.length ? `<div class="table-wrap"><table><thead><tr><th>When</th><th>Type</th><th>Server</th><th>Reason</th><th>Status</th></tr></thead><tbody>
        ${p.punishments.map((x) => `<tr><td>${fmtTs(x.issued_ts)}</td><td><span class="badge ${x.kind === "ban" ? "b-high" : x.kind === "warn" ? "b-low" : "b-medium"}">${esc(x.kind)}</span></td>
          <td>${esc(x.server)}</td><td>${esc(x.reason || "—")}</td>
          <td>${x.active ? "Active" + (x.expires_ts ? ` until ${fmtTs(x.expires_ts)}` : "") : x.revoked_ts ? `Revoked ${fmtTs(x.revoked_ts)}` : "Inactive"}</td></tr>`).join("")}
        </tbody></table></div>` : '<p class="muted">No warnings, mutes, kicks or bans recorded by participating servers.</p>'}</div>
      <div class="card"><h3>Login / logout history</h3><p class="small muted">${esc(st.playtime_note)}</p>
        <div class="table-wrap"><table><thead><tr><th>Server</th><th>Name</th><th>Login</th><th>Logout</th><th>Duration</th></tr></thead><tbody>
        ${p.sessions.map((s) => `<tr><td>${esc(s.server)}</td><td>${esc(s.username)}</td><td>${fmtTs(s.login_ts)}</td>
          <td>${s.logout_ts ? fmtTs(s.logout_ts) + (s.clean_close ? "" : ' <span class="badge" title="No logout event; closed at next login or heartbeat">inferred</span>') : '<span class="badge b-low">open</span>'}</td>
          <td>${esc(s.duration || "—")}</td></tr>`).join("") || '<tr><td colspan="5" class="muted">No sessions.</td></tr>'}</tbody></table></div></div>`;
  } catch (err) { $("#prof-out").innerHTML = `<p class="err">${esc(err.message)}</p>`; }
}
$$("[data-report]").forEach((b) => b.addEventListener("click", () => currentProfile &&
  download(`/api/players/${currentProfile}/report?format=${b.dataset.report}`, `moderation-report-${currentProfile.slice(0, 8)}.${b.dataset.report}`)));

// ------------------------------------------------------------------ identity tools
$("#verify-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const p = new URLSearchParams({ q: $("#v-q").value.trim() });
  if ($("#v-name").value.trim()) p.set("name", $("#v-name").value.trim());
  try { $("#verify-out").innerHTML = verificationCard(await api(`/api/uuid/verify?${p}`)); }
  catch (err) { $("#verify-out").innerHTML = `<p class="err">${esc(err.message)}</p>`; }
});
$("#compare-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = $("#c-name").value.trim(), uuid = $("#c-uuid").value.trim().toLowerCase();
  try {
    const v = await api(`/api/uuid/verify?q=${encodeURIComponent(name)}`);
    const norm = (u) => (u || "").replace(/-/g, "");
    let verdict, cls;
    if (v.premium_uuid && norm(v.premium_uuid) === norm(uuid)) { verdict = "This is the genuine premium account for the name."; cls = "b-ok"; }
    else if (norm(v.offline_uuid) === norm(uuid)) {
      verdict = v.premium_uuid ? "This is the OFFLINE clone of a premium name. Anyone can produce it, so it is not proof of being the owner."
        : "Standard offline UUID for a name with no premium owner."; cls = v.premium_uuid ? "b-high" : "b-medium";
    } else if (v.verdict === "unverified") { verdict = "Mojang unavailable; only the offline derivation could be checked, and it does not match."; cls = ""; }
    else { verdict = "Matches neither the premium nor the standard offline UUID (custom auth plugin, renamed account, or spoofed)."; cls = "b-medium"; }
    $("#compare-out").innerHTML = `<div class="result"><span class="badge ${cls}">${esc(verdict)}</span></div>${verificationCard(v)}`;
  } catch (err) { $("#compare-out").innerHTML = `<p class="err">${esc(err.message)}</p>`; }
});

// ------------------------------------------------------------------ alerts
function alertList(list) {
  if (!list.length) return "";
  return `<div class="table-wrap"><table><thead><tr><th>When</th><th>Severity</th><th>Alert</th><th>Identities</th></tr></thead><tbody>
    ${list.map((a) => `<tr><td>${ago(a.ts)}</td><td>${sevBadge(a.severity)}</td><td>${esc(a.title)}</td>
      <td>${a.uuids.map((u) => `<button class="link mono" data-uuid="${esc(u)}">${esc(u.slice(0, 8))}…</button>`).join(" ")}</td></tr>`).join("")}
    </tbody></table></div>`;
}
loaders.alerts = async () => {
  const list = (await api(`/api/alerts?days=${$("#al-days").value}`)).filter((a) => !$("#al-type").value || a.type === $("#al-type").value);
  $("#alerts-out").innerHTML = alertList(list) || '<p class="muted">No alerts for this filter.</p>';
  bindUuidLinks($("#alerts-out"));
};
$("#al-type").addEventListener("change", () => loaders.alerts());
$("#al-days").addEventListener("change", () => loaders.alerts());

// ------------------------------------------------------------------ federation
loaders.federation = async () => {
  const r = await api("/api/federation/servers");
  $("#ingest-doc").textContent = `POST ${location.origin}/api/ingest/events
X-Api-Key: <participant key>

{"events": [
  {"type": "login",  "uuid": "...", "username": "Steve",
   "ip_hash": HMAC_SHA256(salt, player_ip)},
  {"type": "logout", "uuid": "..."},
  {"type": "ban",    "uuid": "...", "reason": "x-ray",
   "expires_ts": null},
  {"type": "unban",  "uuid": "..."},
  {"type": "heartbeat", "online_uuids": ["..."]}
]}
types: login logout heartbeat warn kick mute unmute ban unban
ts (unix seconds) is optional. Raw IPs are rejected.

Federation IP salt (share only with participants):
${r.ip_salt}`;
  $("#fed-table tbody").innerHTML = r.servers.length ? r.servers.map((f) => `<tr>
    <td><strong>${esc(f.name)}</strong><div class="muted small">${esc(f.description || "")}</div></td>
    <td>${f.online_mode == null ? "—" : f.online_mode ? "Online" : "Offline"}</td>
    <td class="num">${f.sessions}</td><td class="num">${f.punishments}</td><td class="num">${f.open_sessions}</td>
    <td>${ago(f.last_report)}</td>
    <td><button data-rotate="${esc(f.fed_id)}">Rotate key</button>
      <button data-active="${esc(f.fed_id)}" data-to="${f.active ? "false" : "true"}">${f.active ? "Disable" : "Enable"}</button></td></tr>`).join("")
    : '<tr><td colspan="7" class="muted">No participating servers yet.</td></tr>';
  $$("[data-rotate]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm("Rotate key? The old key stops working immediately.")) return;
    const k = await api(`/api/federation/servers/${b.dataset.rotate}/rotate`, { method: "POST" });
    $("#fed-secret").innerHTML = `<div class="secret"><strong>New API key (shown once):</strong><div class="mono">${esc(k.api_key)}</div></div>`;
  }));
  $$("[data-active]").forEach((b) => b.addEventListener("click", async () => {
    await api(`/api/federation/servers/${b.dataset.active}/active?active=${b.dataset.to}`, { method: "POST" }); loaders.federation();
  }));
};
$("#fed-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const mode = $("#fed-mode").value;
  const r = await api("/api/federation/servers", { method: "POST", body: JSON.stringify({
    name: $("#fed-name").value, description: $("#fed-desc").value, online_mode: mode === "" ? null : mode === "true" }) });
  $("#fed-secret").innerHTML = `<div class="secret"><strong>API key (shown once, store it now):</strong>
    <div class="mono">${esc(r.api_key)}</div><p class="small">IP-hash salt:</p><div class="mono">${esc(r.ip_salt)}</div></div>`;
  $("#fed-name").value = $("#fed-desc").value = "";
  loaders.federation();
});

// ------------------------------------------------------------------ boot
(async () => {
  if (!TOKEN) return showLogin();
  try { await api("/api/stats"); $("#app").hidden = false; show("overview"); } catch (_) { showLogin(); }
})();
