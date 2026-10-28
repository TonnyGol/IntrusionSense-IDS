"use strict";

const CLIENT_HEADERS = { "X-Requested-With": "IntrusionSense", "Content-Type": "application/json" };
const STATS_REFRESH_MS = 60_000;
const SEARCH_DEBOUNCE_MS = 300;
const TOAST_MS = 3_500;
const RECONNECT_MIN_MS = 1_000;
const RECONNECT_MAX_MS = 15_000;
const STRIP_WIDTH = 960;
const STRIP_HEIGHT = 140;
const STRIP_GAP = 6;
const STRIP_HOURS = 24;
const SENSOR_CONFIG_FILE_NAME = "sensor.conf";
const SEVERITIES = ["High", "Medium", "Low"];
const STATUS_LABELS = { active: "Open", acknowledged: "Acknowledged", false_positive: "False positive", resolved: "Resolved" };
const RULE_FIELDS = [
  "Source IP", "Dest IP", "Port", "Protocol", "Packet Count", "Payload Regex",
  "Connection Attempts / min", "Unique Ports Scanned / 10s", "Packets to Dest Port / 10s",
];
const RULE_ACTIONS = ["Alert High", "Alert Medium", "Alert Low", "Ignore (allowlist)"];
const ROLES = ["Admin", "Manager", "SOC Analyst"];
const VIEWS = [
  { id: "alerts", label: "Alerts" },
  { id: "rules", label: "Rules" },
  { id: "sensors", label: "Sensors" },
  { id: "users", label: "Users", needs: "manage_users" },
  { id: "activity", label: "Activity", needs: "view_audit" },
];

const state = { me: null, alerts: [], hasMore: false, selectedId: null, stats: null, socket: null, retryMs: RECONNECT_MIN_MS };
const byId = (id) => document.getElementById(id);

/* ---------- small helpers ---------- */

// Every node is built with textContent, never innerHTML: alert fields come from attacker-controlled traffic.
function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== false && value != null) node.setAttribute(key, value === true ? "" : value);
  }
  node.append(...children.flat(Infinity).filter((c) => c != null));
  return node;
}

function clear(node) { node.replaceChildren(); return node; }

function formatTime(iso) {
  return iso ? new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "never";
}

function relativeTime(iso) {
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return `${Math.floor(seconds / 86400)} d ago`;
}

function toast(message) {
  const node = byId("toast");
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, TOAST_MS);
}

class ApiError extends Error {}

function errorMessage(body, status) {
  const detail = body && body.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length) return detail.map((d) => d.msg).join(". ");
  return `Request failed (${status}).`;
}

async function api(method, path, body) {
  const response = await fetch(path, {
    method, headers: CLIENT_HEADERS, credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json().catch(() => null);
  if (response.status === 401 && state.me && path !== "/api/login") {
    showAuth("login");
    throw new ApiError("Your session ended. Sign in again.");
  }
  if (!response.ok) throw new ApiError(errorMessage(payload, response.status));
  return payload;
}

const can = (permission) => state.me && state.me.permissions.includes(permission);

/* ---------- dialog ---------- */

function field(spec) {
  const id = `field-${spec.name}`;
  let input;
  if (spec.options) {
    input = el("select", { id, name: spec.name }, spec.options.map((o) => el("option", { value: o }, o)));
    input.value = spec.value ?? spec.options[0];
  } else if (spec.check) {
    input = el("input", { id, name: spec.name, type: "checkbox" });
    input.checked = Boolean(spec.value);
    return el("label", { class: "check", for: id }, input, spec.label);
  } else {
    input = el("input", { id, name: spec.name, type: spec.type || "text", maxlength: spec.max || 200,
      required: spec.required !== false, autocomplete: spec.type === "password" ? "new-password" : "off" });
    input.value = spec.value ?? "";
  }
  const hint = spec.hint ? el("p", { class: "muted small" }, spec.hint) : null;
  return el("div", {}, el("label", { for: id }, spec.label), input, hint);
}

function readValues(fields) {
  return Object.fromEntries(fields.map((spec) => {
    const input = byId(`field-${spec.name}`);
    return [spec.name, spec.check ? input.checked : input.value];
  }));
}

function openForm({ title, fields, submitLabel, onSubmit }) {
  const dialog = byId("form-dialog");
  const errorBox = byId("dialog-error");
  byId("dialog-title").textContent = title;
  byId("dialog-submit").textContent = submitLabel;
  errorBox.hidden = true;
  clear(byId("dialog-fields")).append(...fields.map(field));
  byId("dialog-form").onsubmit = async (event) => {
    event.preventDefault();
    try {
      await onSubmit(readValues(fields));
      dialog.close();
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.hidden = false;
    }
  };
  byId("dialog-cancel").onclick = () => dialog.close();
  dialog.showModal();
}

function confirmAction({ title, message, label, onConfirm }) {
  openForm({ title, fields: [], submitLabel: label, onSubmit: onConfirm });
  byId("dialog-fields").append(el("p", {}, message));
}

/* ---------- sign-in and first run ---------- */

function showAuth(mode) {
  closeSocket();
  state.me = null;
  byId("app").hidden = true;
  byId("screen-auth").hidden = false;
  const isSetup = mode === "setup";
  byId("auth-intro").textContent = isSetup ? "Create the first admin account to get started." : "Sign in to continue.";
  byId("auth-submit").textContent = isSetup ? "Create account" : "Sign in";
  byId("auth-password").autocomplete = isSetup ? "new-password" : "current-password";
  const hint = byId("auth-hint");
  hint.hidden = !isSetup;
  hint.textContent = "Use at least 12 characters.";
  byId("auth-form").dataset.mode = mode;
  byId("auth-password").value = "";
  byId("auth-error").hidden = true;
  byId("auth-username").focus();
}

async function submitAuth(event) {
  event.preventDefault();
  const form = byId("auth-form");
  const credentials = { username: byId("auth-username").value.trim(), password: byId("auth-password").value };
  const errorBox = byId("auth-error");
  errorBox.hidden = true;
  try {
    if (form.dataset.mode === "setup") await api("POST", "/api/setup", credentials);
    await api("POST", "/api/login", credentials);
    await start();
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.hidden = false;
  }
}

async function signOut() {
  await api("POST", "/api/logout").catch(() => {});
  showAuth("login");
}

/* ---------- navigation ---------- */

function buildNav() {
  const items = VIEWS.filter((v) => !v.needs || can(v.needs));
  clear(byId("nav")).append(...items.map((v) =>
    el("li", {}, el("button", { type: "button", "data-view": v.id, onclick: () => navigate(v.id) }, v.label))));
}

function navigate(viewId) {
  const allowed = VIEWS.some((v) => v.id === viewId && (!v.needs || can(v.needs)));
  const target = allowed ? viewId : "alerts";
  for (const v of VIEWS) byId(`view-${v.id}`).hidden = v.id !== target;
  for (const button of byId("nav").querySelectorAll("button")) {
    if (button.dataset.view === target) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  history.replaceState(null, "", `#${target}`);
  const loaders = { alerts: loadAlerts, rules: loadRules, sensors: loadSensors, users: loadUsers, activity: loadActivity };
  loaders[target]().catch((error) => toast(error.message));
}

/* ---------- alerts ---------- */

function alertFilters() {
  const params = new URLSearchParams();
  const status = byId("f-status").value, severity = byId("f-severity").value, search = byId("f-search").value.trim();
  if (status) params.set("status", status);
  if (severity) params.set("severity", severity);
  if (search) params.set("search", search);
  return params;
}

function matchesFilters(alert) {
  const status = byId("f-status").value, severity = byId("f-severity").value;
  const search = byId("f-search").value.trim().toLowerCase();
  if (status && alert.status !== status) return false;
  if (severity && alert.severity !== severity) return false;
  if (!search) return true;
  return [alert.attack_type, alert.src_ip, alert.dst_ip].some((v) => v.toLowerCase().includes(search));
}

async function loadAlerts(append = false) {
  const params = alertFilters();
  if (append && state.alerts.length) params.set("before_id", state.alerts[state.alerts.length - 1].id);
  const page = await api("GET", `/api/alerts?${params}`);
  state.alerts = append ? state.alerts.concat(page.alerts) : page.alerts;
  state.hasMore = page.has_more;
  renderAlerts();
  loadStats().catch(() => {});
}

function describeDetection(alert) {
  if (alert.detection === "rule") return "Matched a rule";
  if (alert.detection === "engine_error") return "Engine could not judge this flow";
  return `Model, ${Math.round(alert.confidence * 100)}% sure`;
}

function alertRow(alert) {
  const closed = alert.status !== "active";
  const attack = el("td", {}, el("div", {}, alert.attack_type),
    el("div", { class: "muted small" }, closed ? `${STATUS_LABELS[alert.status] ?? alert.status}. ` : "", describeDetection(alert)));
  const row = el("tr", { class: `is-clickable${alert.id === state.selectedId ? " is-selected" : ""}`, tabindex: "0",
    "aria-label": `${alert.severity} alert: ${alert.attack_type}`, onclick: () => selectAlert(alert.id),
    onkeydown: (event) => { if (event.key === "Enter") selectAlert(alert.id); } },
    el("td", { class: `sev sev-${alert.severity}` }, alert.severity),
    attack,
    el("td", { class: "ip" }, `${alert.src_ip}:${alert.src_port}`),
    el("td", { class: "ip" }, `${alert.dst_ip}:${alert.dst_port}`),
    el("td", { class: "num" }, alert.repeat_count),
    el("td", { title: formatTime(alert.last_seen) }, relativeTime(alert.last_seen)));
  return row;
}

function renderAlerts() {
  clear(byId("alert-rows")).append(...state.alerts.map(alertRow));
  const empty = byId("alerts-empty");
  empty.hidden = state.alerts.length > 0;
  const filtered = alertFilters().toString() !== "";
  empty.textContent = filtered ? "No alerts match these filters." : "No alerts yet. They appear here as soon as a sensor reports an attack.";
  byId("load-more").hidden = !state.hasMore;
}

async function selectAlert(id) {
  state.selectedId = id;
  renderAlerts();
  const detail = await api("GET", `/api/alerts/${id}`).catch((error) => { toast(error.message); return null; });
  if (detail) renderDrawer(detail);
}

function closeDrawer() {
  state.selectedId = null;
  byId("drawer").hidden = true;
  document.querySelector("#view-alerts .split").classList.remove("has-drawer");
  renderAlerts();
}

function drawerFacts(alert) {
  const facts = [
    ["Status", STATUS_LABELS[alert.status] ?? alert.status],
    ["Detected by", describeDetection(alert)],
    ["From", `${alert.src_ip}:${alert.src_port}`],
    ["To", `${alert.dst_ip}:${alert.dst_port} (${alert.protocol})`],
    ["Packets", `${alert.packet_count}, about ${alert.avg_packet_size} bytes each`],
    ["Seen", `${alert.repeat_count} time${alert.repeat_count === 1 ? "" : "s"}`],
    ["First", formatTime(alert.time)],
    ["Latest", formatTime(alert.last_seen)],
    ["Sensor", alert.sensor ?? "unknown"],
  ];
  if (alert.error) facts.push(["Error", alert.error]);
  return el("dl", {}, facts.map(([name, value]) => [el("dt", {}, name), el("dd", {}, String(value))]));
}

function triageButtons(alert) {
  if (!can("triage_alerts")) return null;
  const choices = [["acknowledged", "Acknowledge"], ["false_positive", "Mark as false positive"], ["resolved", "Resolve"], ["active", "Reopen"]];
  return el("div", { class: "triage" }, choices.filter(([value]) => value !== alert.status).map(([value, label]) =>
    el("button", { type: "button", class: "secondary small", onclick: () => setAlertStatus(alert.id, value) }, label)));
}

function renderDrawer(alert) {
  const drawer = clear(byId("drawer"));
  const payloads = (alert.payloads || []).filter(Boolean);
  const parts = [
    el("button", { type: "button", class: "link close", onclick: closeDrawer }, "Close"),
    el("h3", {}, alert.attack_type),
    el("p", { class: `sev-${alert.severity}` }, `${alert.severity} severity`),
    drawerFacts(alert),
    payloads.length ? el("div", {}, el("strong", {}, "Captured request data"), payloads.map((p) => el("pre", {}, p))) : null,
    triageButtons(alert),
  ];
  drawer.append(...parts.filter((part) => part !== null));
  drawer.hidden = false;
  document.querySelector("#view-alerts .split").classList.add("has-drawer");
}

async function setAlertStatus(id, status) {
  await api("PATCH", `/api/alerts/${id}`, { status });
  toast(`Alert ${id} marked ${STATUS_LABELS[status].toLowerCase()}.`);
  await loadStats();
}

function applyAlertUpdate(alert, isNew) {
  const index = state.alerts.findIndex((a) => a.id === alert.id);
  if (index >= 0) state.alerts[index] = alert;
  else if (isNew && matchesFilters(alert)) state.alerts.unshift(alert);
  renderAlerts();
  if (alert.id === state.selectedId) selectAlert(alert.id);
  if (isNew) bumpStrip(alert.severity);
}

/* ---------- the 24-hour strip ---------- */

async function loadStats() {
  state.stats = await api("GET", "/api/stats");
  renderOpenCounts();
  renderStrip();
}

function renderOpenCounts() {
  clear(byId("open-counts")).append(...SEVERITIES.map((s) =>
    el("div", { class: `open-count sev-${s}` }, el("strong", {}, String(state.stats.open_by_severity[s])), el("span", { class: "muted" }, `open ${s.toLowerCase()}`))));
}

function bumpStrip(severity) {
  if (!state.stats) return;
  state.stats.hours[STRIP_HOURS - 1][severity] += 1;
  state.stats.open_by_severity[severity] += 1;
  renderOpenCounts();
  renderStrip(true);
}

const svgNode = (tag, attrs) => {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
};

function renderStrip(flashLast = false) {
  const svg = clear(byId("strip"));
  svg.setAttribute("viewBox", `0 0 ${STRIP_WIDTH} ${STRIP_HEIGHT}`);
  svg.setAttribute("preserveAspectRatio", "none");
  const hours = state.stats.hours;
  const totals = hours.map((h) => SEVERITIES.reduce((sum, s) => sum + h[s], 0));
  const scale = (STRIP_HEIGHT - 8) / Math.max(1, ...totals);
  const slot = STRIP_WIDTH / hours.length;
  svg.append(svgNode("line", { class: "axis", x1: 0, x2: STRIP_WIDTH, y1: STRIP_HEIGHT - 0.5, y2: STRIP_HEIGHT - 0.5 }));
  hours.forEach((hour, i) => {
    const group = svgNode("g", flashLast && i === hours.length - 1 ? { class: "hour-flash" } : {});
    const title = svgNode("title", {});
    title.textContent = `${new Date(hour.start).toLocaleTimeString([], { hour: "numeric" })}: ${SEVERITIES.map((s) => `${hour[s]} ${s.toLowerCase()}`).join(", ")}`;
    group.append(title);
    let y = STRIP_HEIGHT - 1;
    for (const severity of SEVERITIES) {
      const height = hour[severity] * scale;
      if (!height) continue;
      y -= height;
      group.append(svgNode("rect", { class: `bar-${severity}`, x: i * slot + STRIP_GAP / 2, y, width: slot - STRIP_GAP, height }));
    }
    svg.append(group);
  });
  const total = totals.reduce((a, b) => a + b, 0);
  byId("strip-caption").textContent = total
    ? `${total} alert${total === 1 ? "" : "s"} in the last 24 hours, one bar per hour. Taller bars are busier hours.`
    : "No alerts in the last 24 hours.";
}

/* ---------- rules ---------- */

async function loadRules() {
  const rules = await api("GET", "/api/rules");
  byId("new-rule").hidden = !can("manage_rules");
  clear(byId("rule-rows")).append(...rules.map(ruleRow));
}

function ruleRow(rule) {
  const actions = can("manage_rules") ? el("td", { class: "actions" },
    el("button", { type: "button", class: "secondary small", onclick: () => ruleForm(rule) }, "Edit"),
    el("button", { type: "button", class: "secondary small", onclick: () => toggleRule(rule) }, rule.active ? "Pause" : "Resume"),
    el("button", { type: "button", class: "danger small", onclick: () => deleteRule(rule) }, "Delete")) : el("td");
  return el("tr", {},
    el("td", {}, el("div", {}, rule.name), el("div", { class: "muted small" }, rule.description || "")),
    el("td", { class: "ip" }, rule.condition), el("td", {}, rule.action),
    el("td", {}, rule.active ? "Active" : "Paused"), actions);
}

function splitCondition(condition) {
  const fieldName = RULE_FIELDS.find((f) => condition.startsWith(f)) ?? RULE_FIELDS[0];
  return { fieldName, value: condition.slice(fieldName.length).trim() };
}

function ruleForm(rule) {
  const parts = rule ? splitCondition(rule.condition) : { fieldName: RULE_FIELDS[0], value: "" };
  openForm({
    title: rule ? "Edit rule" : "Add rule", submitLabel: "Save rule",
    fields: [
      { name: "name", label: "Name", value: rule?.name, max: 100 },
      { name: "description", label: "Description", value: rule?.description, required: false, max: 1000 },
      { name: "field", label: "Look at", options: RULE_FIELDS, value: parts.fieldName },
      { name: "value", label: "Value", value: parts.value, max: 900,
        hint: "An address, port, protocol or number. Payload Regex takes a regular expression." },
      { name: "action", label: "When it matches", options: RULE_ACTIONS, value: rule?.action },
      { name: "active", label: "Rule is active", check: true, value: rule ? rule.active : true },
    ],
    onSubmit: async (v) => {
      const body = { name: v.name, description: v.description, condition: `${v.field} ${v.value}`.trim(), action: v.action, active: v.active };
      await (rule ? api("PUT", `/api/rules/${rule.id}`, body) : api("POST", "/api/rules", body));
      toast("Rule saved."); await loadRules();
    },
  });
}

async function toggleRule(rule) {
  await api("PUT", `/api/rules/${rule.id}`, { name: rule.name, description: rule.description || "", condition: rule.condition, action: rule.action, active: !rule.active });
  await loadRules();
}

function deleteRule(rule) {
  confirmAction({ title: "Delete rule", message: `Delete "${rule.name}"? Alerts it already raised stay.`, label: "Delete rule",
    onConfirm: async () => { await api("DELETE", `/api/rules/${rule.id}`); toast("Rule deleted."); await loadRules(); } });
}

/* ---------- sensors ---------- */

async function loadSensors() {
  const sensors = await api("GET", "/api/sensors");
  byId("new-sensor").hidden = !can("manage_sensors");
  byId("sensors-empty").hidden = sensors.length > 0;
  clear(byId("sensor-rows")).append(...sensors.map((s) => el("tr", {},
    el("td", {}, s.name),
    el("td", {}, !s.active ? "Revoked" : s.online ? "Online" : "Offline"),
    el("td", {}, s.last_seen ? relativeTime(s.last_seen) : "never"),
    el("td", { class: "actions" }, can("manage_sensors") && s.active
      ? el("button", { type: "button", class: "danger small", onclick: () => revokeSensor(s) }, "Revoke") : null))));
}

function registerSensor() {
  openForm({ title: "Register sensor", submitLabel: "Register", fields: [{ name: "name", label: "Name", max: 100, hint: "For example the machine it runs on." }],
    onSubmit: async ({ name }) => { const created = await api("POST", "/api/sensors", { name }); showToken(created); await loadSensors(); } });
}

function downloadSensorConfig(token) {
  const file = new Blob([`server=${location.origin}\ntoken=${token}\n`], { type: "text/plain" });
  const link = el("a", { href: URL.createObjectURL(file), download: SENSOR_CONFIG_FILE_NAME });
  link.click();
  URL.revokeObjectURL(link.href);
}

function showToken({ name, token }) {
  const windowsCommand = `$env:INTRUSIONSENSE_SENSOR_TOKEN = "${token}"; .\\intrusionsense-sensor-windows-x64.exe --server ${location.origin}`;
  const linuxCommand = `INTRUSIONSENSE_SENSOR_TOKEN=${token} intrusionsense sensor --server ${location.origin}`;
  const copyButton = (label, command) => el("button", { type: "button", class: "secondary small", onclick: () => navigator.clipboard.writeText(command).then(() => toast("Copied.")) }, label);
  const box = clear(byId("sensor-token"));
  box.hidden = false;
  box.append(el("strong", {}, `Sensor "${name}" is registered.`),
    el("p", {}, "The token is shown only once. Easiest on Windows: download the file, save it in the same folder as the sensor program, then double-click the program."),
    el("button", { type: "button", onclick: () => downloadSensorConfig(token) }, `Download ${SENSOR_CONFIG_FILE_NAME}`),
    el("p", {}, "Or run it from a terminal. Windows PowerShell:"),
    el("pre", {}, windowsCommand), copyButton("Copy Windows command", windowsCommand),
    el("p", {}, "Linux or macOS:"),
    el("pre", {}, linuxCommand), copyButton("Copy Linux command", linuxCommand));
}

function revokeSensor(sensor) {
  confirmAction({ title: "Revoke sensor", message: `"${sensor.name}" will stop being accepted. This cannot be undone.`, label: "Revoke",
    onConfirm: async () => { await api("DELETE", `/api/sensors/${sensor.id}`); await loadSensors(); } });
}

/* ---------- users ---------- */

async function loadUsers() {
  const users = await api("GET", "/api/users");
  clear(byId("user-rows")).append(...users.map((u) => el("tr", {},
    el("td", {}, u.username), el("td", {}, u.role), el("td", {}, formatTime(u.created)),
    el("td", { class: "actions" },
      el("button", { type: "button", class: "secondary small", onclick: () => changeRole(u) }, "Change role"),
      el("button", { type: "button", class: "secondary small", onclick: () => resetPassword(u) }, "Reset password"),
      u.id === state.me.id ? null : el("button", { type: "button", class: "danger small", onclick: () => deleteUser(u) }, "Delete")))));
}

function addUser() {
  openForm({ title: "Add user", submitLabel: "Add user", fields: [
    { name: "username", label: "Username", max: 50 },
    { name: "password", label: "Password", type: "password", max: 256, hint: "At least 12 characters." },
    { name: "role", label: "Role", options: ROLES, value: "SOC Analyst" }],
  onSubmit: async (v) => { await api("POST", "/api/users", v); toast("User added."); await loadUsers(); } });
}

function changeRole(user) {
  openForm({ title: `Change role for ${user.username}`, submitLabel: "Save role", fields: [{ name: "role", label: "Role", options: ROLES, value: user.role }],
    onSubmit: async (v) => { await api("PATCH", `/api/users/${user.id}`, v); await loadUsers(); } });
}

function resetPassword(user) {
  openForm({ title: `Reset password for ${user.username}`, submitLabel: "Reset password", fields: [
    { name: "password", label: "New password", type: "password", max: 256, hint: "At least 12 characters." }],
  onSubmit: async (v) => { await api("PATCH", `/api/users/${user.id}`, v); toast("Password reset."); } });
}

function deleteUser(user) {
  confirmAction({ title: "Delete user", message: `Delete ${user.username}? They can no longer sign in.`, label: "Delete user",
    onConfirm: async () => { await api("DELETE", `/api/users/${user.id}`); await loadUsers(); } });
}

/* ---------- activity ---------- */

async function loadActivity() {
  const entries = await api("GET", "/api/audit");
  clear(byId("activity-rows")).append(...entries.map((e) => el("tr", {},
    el("td", {}, formatTime(e.time)), el("td", {}, e.user ?? "unknown"), el("td", {}, e.action.replaceAll("_", " ")),
    el("td", {}, e.detail || ""), el("td", { class: "ip" }, e.ip || ""))));
}

/* ---------- live updates ---------- */

function setLive(text, className) {
  byId("live-text").textContent = text;
  byId("live-status").className = `live ${className}`;
}

function closeSocket() {
  if (state.socket) { state.socket.onclose = null; state.socket.close(); state.socket = null; }
}

function connectSocket() {
  closeSocket();
  const scheme = location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${scheme}://${location.host}/ws`);
  state.socket = socket;
  socket.onopen = () => { state.retryMs = RECONNECT_MIN_MS; setLive("Live", "is-live"); loadAlerts().catch(() => {}); };
  socket.onmessage = (message) => {
    const event = JSON.parse(message.data);
    if (event.type === "alert" || event.type === "alert_updated") applyAlertUpdate(event.alert, event.type === "alert");
  };
  socket.onclose = () => {
    setLive("Reconnecting", "is-down");
    setTimeout(() => { if (state.me) connectSocket(); }, state.retryMs);
    state.retryMs = Math.min(state.retryMs * 2, RECONNECT_MAX_MS);
  };
}

/* ---------- start ---------- */

async function start() {
  state.me = await api("GET", "/api/me");
  byId("screen-auth").hidden = true;
  byId("app").hidden = false;
  byId("whoami").textContent = `${state.me.username}, ${state.me.role}`;
  buildNav();
  navigate(location.hash.slice(1) || "alerts");
  connectSocket();
}

async function boot() {
  byId("auth-form").addEventListener("submit", submitAuth);
  byId("sign-out").addEventListener("click", signOut);
  byId("new-rule").addEventListener("click", () => ruleForm(null));
  byId("new-sensor").addEventListener("click", registerSensor);
  byId("new-user").addEventListener("click", addUser);
  byId("load-more").addEventListener("click", () => loadAlerts(true).catch((e) => toast(e.message)));
  let searchTimer;
  byId("f-search").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(() => loadAlerts(), SEARCH_DEBOUNCE_MS); });
  for (const id of ["f-status", "f-severity"]) byId(id).addEventListener("change", () => loadAlerts());
  setInterval(() => { if (state.me) loadStats().catch(() => {}); }, STATS_REFRESH_MS);

  const setup = await api("GET", "/api/setup");
  if (setup.needed) return showAuth("setup");
  try { await start(); } catch { showAuth("login"); }
}

document.addEventListener("DOMContentLoaded", boot);
