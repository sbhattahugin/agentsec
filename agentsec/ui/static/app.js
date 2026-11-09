/* AgentSec console. Plain JS, no dependencies. All text goes through textContent (agent output is untrusted). */
"use strict";

const $ = (sel) => document.querySelector(sel);
const SVGNS = "http://www.w3.org/2000/svg";

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
function s(tag, attrs, text) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, v);
  if (text !== undefined) el.textContent = text;
  return el;
}
const sev = (x) => h("span", { class: `sev ${x}` }, x);
const chip = (text, color) => h("span", { class: `chip ${color || ""}` }, text);
const trunc = (t, n) => (t && t.length > n ? t.slice(0, n) + ` … (${t.length} chars)` : t || "");
const fmt = (v) => (typeof v === "object" && v !== null ? JSON.stringify(v) : String(v));

const state = {
  targets: [], selected: null, phases: [], running: false, es: null,
  run: null, sections: {}, tests: {}, wireCount: 0, history: [], replaying: false,
};

/* ------------------------------------------------------------------ tabs */
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => {
  document.querySelectorAll(".tabs button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.id === `tab-${b.dataset.tab}`));
}));

/* ------------------------------------------------------------------ targets */
async function loadTargets() {
  const data = await (await fetch("/api/targets")).json();
  state.targets = data.targets;
  const box = $("#targets");
  box.replaceChildren();
  if (!data.targets.length) {
    box.append(h("p", { class: "hint" }, `No target YAML files in ${data.targetsDir}.`));
    return;
  }
  const groups = {};
  for (const t of data.targets) (groups[t.labels?.lab ? "Dummy agents (lab)" : "Your targets"] ||= []).push(t);
  for (const [label, items] of Object.entries(groups)) {
    box.append(h("div", { class: "group-label" }, label));
    for (const t of items) {
      if (t.error) { box.append(h("div", { class: "target" }, t.file, h("div", { class: "t-desc" }, t.error))); continue; }
      const mode = t.labels?.mode;
      const el = h("div", { class: "target", onclick: () => selectTarget(t, el) },
        h("div", { class: "t-name" }, t.name, mode ? h("span", { class: `badge ${mode}` }, mode) : h("span", { class: "badge other" }, t.environment || "")),
        h("div", { class: "t-desc" }, t.description || t.file));
      box.append(el);
    }
  }
}
function selectTarget(t, el) {
  state.selected = t;
  document.querySelectorAll(".target").forEach((x) => x.classList.toggle("selected", x === el));
  $("#target-yaml").textContent = t.yaml;
  $("#yaml-box").open = true;
  $("#run").disabled = state.running;
}

/* ------------------------------------------------------------------ run */
$("#run").addEventListener("click", () => startScan());

function startScan() {
  if (!state.selected || state.running) return;
  const pace = $("#pace").value;
  resetView();
  state.running = true;
  $("#run").disabled = true;
  $("#run").textContent = "Scanning…";
  const events = [];
  const es = new EventSource(`/api/scan?target=${encodeURIComponent(state.selected.file)}&pace=${pace}`);
  state.es = es;
  const names = ["run", "phase", "target", "log", "http", "discovered", "graph", "static_findings", "tests_selected",
    "test_start", "test_response", "test_telemetry", "test_result", "attack_paths", "policy_results", "risk",
    "summary", "done", "error"];
  for (const n of names) {
    es.addEventListener(n, (e) => {
      const data = JSON.parse(e.data);
      events.push([n, data]);
      handle(n, data);
      if (n === "done" || n === "error") finish(es, events, n === "done" ? data : null);
    });
  }
  es.onerror = () => { if (state.running) { handle("error", { message: "Connection to console lost." }); finish(es, events, null); } };
}

function finish(es, events, done) {
  es.close();
  state.running = false;
  $("#run").disabled = !state.selected;
  $("#run").textContent = "▶ Run AgentSec scan";
  if (done) {
    state.history.unshift({ target: state.selected.name, mode: state.selected.labels?.mode, result: done.result,
      events, time: new Date().toLocaleTimeString() });
    renderHistory();
  }
}

function renderHistory() {
  const box = $("#history");
  box.replaceChildren(...state.history.map((r) => h("div", { class: "h-item", title: "Replay this run",
    onclick: () => replay(r) },
    h("span", {}, `${r.time} ${r.target}${r.mode ? " · " + r.mode : ""}`),
    h("b", { style: `color: var(--${r.result === "PASS" ? "green" : "red"})` }, r.result))));
}

function replay(r) {
  if (state.running) return;
  resetView();
  state.replaying = true;
  for (const [n, d] of r.events) handle(n, d);
  state.replaying = false;
}

function resetView() {
  state.sections = {}; state.tests = {}; state.wireCount = 0; state.graph = null; state.highlight = null;
  $("#timeline").replaceChildren();
  $("#wire").replaceChildren();
  $("#wire-count").textContent = "";
  $("#gate-banner").className = "gate-banner hidden";
  $("#graph").replaceChildren(h("p", { class: "hint" }, "Populated during discovery."));
  $("#graph-stage").textContent = "";
  setNow("Starting…", "", "", "");
}

/* ------------------------------------------------------------------ inspector */
function setNow(title, what, how, activity) {
  if (title !== null) $("#now-phase").textContent = title;
  if (what !== null) $("#now-what").textContent = what;
  if (how !== null) $("#now-how").textContent = how;
  if (activity !== null) $("#now-activity").textContent = activity;
}

function wire(ev) {
  state.wireCount++;
  $("#wire-count").textContent = `(${state.wireCount} calls)`;
  const u = new URL(ev.url);
  const cls = `s${String(ev.status)[0]}`;
  const row = h("div", { class: "w", onclick: () => row.classList.toggle("open") },
    h("span", { class: "m" }, ev.method.padEnd(5)), " ",
    h("span", { class: cls }, String(ev.status || "ERR")), " ",
    `${u.host}${u.pathname}${u.search}`, " ",
    h("span", { class: "muted" }, `${ev.ms}ms`),
    ev.trace ? h("span", { class: "tr" }, ` ⟵ ${ev.trace}`) : null,
    h("pre", {}, (ev.request ? `→ ${ev.request}\n` : "") + `← ${ev.response}`));
  const box = $("#wire");
  box.append(row);
  while (box.children.length > 400) box.firstChild.remove();
  box.scrollTop = box.scrollHeight;
  setNow(null, null, null, `${ev.method} ${u.pathname} → ${ev.status}`);
}

/* ------------------------------------------------------------------ stepper & sections */
function buildStepper(phases) {
  state.phases = phases;
  $("#stepper").replaceChildren(...phases.map((p, i) => h("li", { id: `step-${p.id}`,
    onclick: () => state.sections[p.id]?.el.scrollIntoView({ behavior: "smooth", block: "start" }) },
    h("span", { class: "n" }, i + 1), p.title)));
}

function section(id) {
  if (state.sections[id]) return state.sections[id];
  const i = state.phases.findIndex((p) => p.id === id);
  const p = state.phases[i];
  const body = h("div", { class: "body" });
  const el = h("section", { class: "phase running", id: `sec-${id}` },
    h("header", {}, h("span", { class: "num" }, `${i + 1}`), h("span", { class: "title" }, p.title),
      h("span", { class: "what" }, p.what), h("span", { class: "state" })),
    h("div", { class: "how" }, h("b", {}, "How: "), p.how), body);
  $("#timeline").append(el);
  state.sections[id] = { el, body };
  return state.sections[id];
}
const body = (id) => section(id).body;
let currentPhase = null;
function scrollTo(el) { if (!state.replaying) el.scrollIntoView({ behavior: "smooth", block: "nearest" }); }

/* ------------------------------------------------------------------ event handlers */
function handle(n, d) {
  const fn = HANDLERS[n];
  if (fn) fn(d);
}

const HANDLERS = {
  run(d) { buildStepper(d.phases); },

  phase(d) {
    const step = $(`#step-${d.id}`);
    const p = state.phases.find((x) => x.id === d.id);
    if (d.status === "start") {
      currentPhase = d.id;
      const sec = section(d.id);
      step?.classList.add("active");
      setNow(p.title, p.what, p.how, "");
      scrollTo(sec.el);
    } else {
      step?.classList.remove("active");
      step?.classList.add(d.skipped ? "skipped" : "done");
      section(d.id).el.classList.replace("running", "done");
    }
  },

  log(d) { body(currentPhase || "register").append(h("div", { class: "logline" }, d.message.trim())); },

  http: wire,

  target(d) {
    const conns = d.connections.map((c) => h("div", {}, chip(c.type, "blue"), " ", c.endpoint,
      c.telemetry ? h("span", { class: "muted" }, `  (telemetry: ${c.telemetry})`) : null));
    body("register").append(
      h("div", { class: "kv" },
        h("span", { class: "k" }, "Target"), h("b", {}, `${d.name} (${d.environment || "n/a"})`),
        d.description ? [h("span", { class: "k" }, "Description"), h("span", {}, d.description)] : null,
        h("span", { class: "k" }, "Agent endpoint"), h("code", {}, d.agent),
        h("span", { class: "k" }, "Connections"), h("div", {}, conns),
        h("span", { class: "k" }, "Authentication"), h("span", {}, `${d.authentication || "none"}${d.identity ? ` · client ${d.identity}` : ""}`),
        d.testData ? [h("span", { class: "k" }, "Test data"), h("code", {}, JSON.stringify(d.testData))] : null),
      h("div", { class: "callout" }, "That's all the developer provided. Tools, APIs, permissions and data classification are discovered next."));
  },

  discovered(d) {
    const boxes = [];
    if (d.identity) boxes.push(h("div", { class: "box" }, h("h4", {}, "Identity adapter ", h("span", { class: "muted" }, "OAuth2 introspection")),
      h("div", {}, "Subject ", h("b", {}, d.identity.subject)),
      h("div", {}, "Granted scopes: ", d.identity.scopes.map((x) => chip(x, /write|export|delete|admin/.test(x) ? "orange" : "")))));
    for (const m of d.mcp) boxes.push(h("div", { class: "box" }, h("h4", {}, "MCP adapter ", h("span", { class: "muted" }, `${m.server.name || ""} · tools/list`)),
      m.tools.map((t) => h("div", {}, h("span", { style: "color:var(--green)" }, "✓ "), h("b", {}, t.name), h("span", { class: "muted" }, ` — ${t.description}`),
        t.meta?.requiresApproval ? chip("requires approval", "green") : null, t.annotations?.destructiveHint ? chip("destructive", "orange") : null))));
    for (const a of d.apis) boxes.push(h("div", { class: "box" }, h("h4", {}, "OpenAPI adapter ", h("span", { class: "muted" }, a.title)),
      h("table", {}, h("tr", {}, h("th", {}, "operation"), h("th", {}, "scope"), h("th", {}, "data")),
        Object.entries(a.operations).map(([id, o]) => h("tr", {}, h("td", {}, h("code", {}, id), h("div", { class: "muted" }, `${o.method} ${o.path}`)),
          h("td", {}, o.scopes.join(", ")), h("td", {}, o.dataClassification, o.bulk ? chip("bulk", "red") : null))))));
    body("discover").append(h("div", { class: "grid2" }, boxes));
  },

  graph(d) {
    state.graph = d.graph;
    $("#graph-stage").textContent = d.stage === "observed" ? "· with runtime evidence" : "· discovered";
    drawGraph();
    if (d.stage !== "normalized") return;
    const rows = d.capabilities.map((c) => h("tr", {},
      h("td", {}, h("b", {}, c.tool)), h("td", {}, c.operation),
      h("td", {}, c.bulkAccess ? chip("bulk", "red") : "—"),
      h("td", {}, chip(c.dataClassification, ["confidential", "restricted"].includes(c.dataClassification) ? "orange" : "")),
      h("td", { class: c.humanApproval ? "ok" : "bad" }, c.humanApproval ? "required" : "none"),
      h("td", {}, c.destructive ? chip("destructive", "orange") : "—"),
      h("td", {}, c.requiredPermissions.join(", ")),
      h("td", { class: c.effective ? "" : "ok" }, c.effective ? "yes" : "no (identity lacks scope)")));
    body("normalize").append(
      h("table", {}, h("tr", {}, ["Tool", "Operation", "Bulk", "Data", "Human approval", "Destructive", "Requires", "Effective"].map((x) => h("th", {}, x))), rows),
      h("div", { class: "callout" }, `Generic model populated automatically: ${d.graph.nodes.length} nodes, ${d.graph.edges.length} edges (see graph →).`));
  },

  static_findings(d) {
    const b = body("static");
    if (!d.findings.length) b.append(h("div", { class: "callout" }, "No static policy violations in the discovered configuration."));
    for (const f of d.findings) b.append(findingCard(f));
  },

  tests_selected(d) {
    const b = body("attack");
    b.append(h("div", { class: "callout" }, `${d.tests.length} tests selected from the attack library because a matching capability was discovered; ${d.skipped.length} skipped.`));
    if (d.skipped.length) b.append(h("details", {}, h("summary", { class: "muted" }, "Skipped tests"),
      h("table", {}, d.skipped.map((x) => h("tr", {}, h("td", {}, h("code", {}, x.id)), h("td", {}, x.name), h("td", { class: "muted" }, x.reason))))));
  },

  test_start(d) {
    const verdict = h("span", { class: "verdict running" }, "running");
    const tbody = h("div", { class: "t-body" });
    const card = h("div", { class: "test" },
      h("div", { class: "t-head" }, h("span", { class: "t-id" }, d.id), h("span", { class: "t-title" }, d.name),
        chip(d.category), chip(d.technique), d.tool ? chip(`target: ${d.tool}`, "orange") : null, verdict),
      tbody);
    tbody.append(
      h("div", { class: "oracle" }, "Oracle: ", JSON.stringify(d.oracle), "  ·  trace ", h("code", {}, d.traceId)),
      h("div", { class: "bubble attacker" }, h("div", { class: "who" }, `AgentSec → agent (${d.source})`),
        h("pre", {}, d.message),
        d.documents.map((doc) => h("div", { class: "docblk" }, h("div", { class: "doc-name" }, `📄 attached: ${doc.name}`), h("pre", {}, doc.content)))));
    body("attack").append(card);
    state.tests[d.id] = { card, tbody, verdict };
    state.highlight = d.tool;
    drawGraph();
    setNow(null, null, null, `${d.id}: sending payload to agent…`);
    scrollTo(card);
  },

  test_response(d) {
    const t = state.tests[d.id];
    t.tbody.append(h("div", { class: "bubble agent" }, h("div", { class: "who" }, `Agent replied (HTTP ${d.status})`), h("pre", {}, trunc(d.response, 700))));
    setNow(null, null, null, `${d.id}: collecting MCP telemetry for this trace…`);
  },

  test_telemetry(d) {
    const t = state.tests[d.id];
    const box = h("div", { class: "telemetry" }, h("h5", {}, `Runtime telemetry (what really happened downstream) · ${d.events.length} tool calls`));
    if (!d.events.length) box.append(h("div", { class: "muted" }, "No tool invocations observed."));
    else {
      const agg = {};
      for (const e of d.events) {
        const k = `${e.tool}|${e.status}|${e.humanApproval}`;
        (agg[k] ||= { ...e, calls: 0, records: 0 }).calls++;
        agg[k].records += e.recordsReturned || 0;
      }
      box.append(h("table", {}, h("tr", {}, ["Tool", "Action", "Identity", "Approval", "Status", "Calls", "Records"].map((x) => h("th", {}, x))),
        Object.values(agg).map((a) => h("tr", {}, h("td", {}, h("b", {}, a.tool)), h("td", {}, a.action), h("td", {}, a.identity),
          h("td", {}, String(a.humanApproval)), h("td", { class: a.status === "success" ? "bad" : "ok" }, a.status),
          h("td", {}, a.calls), h("td", {}, a.records)))),
      h("details", {}, h("summary", { class: "muted" }, "raw event"), h("pre", {}, JSON.stringify(d.events[0], null, 2))));
    }
    t.tbody.append(box);
  },

  test_result(d) {
    const t = state.tests[d.id];
    t.card.classList.add(d.verdict);
    t.verdict.className = `verdict ${d.verdict}`;
    t.verdict.textContent = d.verdict;
    t.tbody.append(h("div", { class: "reasons" }, h("h5", {}, "Verdict reasoning"), h("ul", {}, d.reasons.map((r) => h("li", {}, r)))));
    setNow(null, null, null, `${d.id}: ${d.verdict}`);
  },

  attack_paths(d) {
    const b = body("correlate");
    if (!d.paths.length) { b.append(h("div", { class: "callout" }, "No exploitable attack paths: nothing reached data without a control stopping it.")); return; }
    for (const p of d.paths) {
      const parts = [];
      p.steps.forEach((st, i) => {
        if (i) parts.push(h("span", { class: "parrow" }, st.via || ""));
        parts.push(h("span", { class: `pnode ${st.type}` }, h("span", { class: "ptype" }, st.type), st.name));
      });
      b.append(h("div", { class: "path" }, h("div", { class: "p-head" }, sev(p.severity), h("code", {}, p.finding), h("span", {}, p.title),
        chip(p.kind === "dynamic" ? "proven at runtime" : "possible (static)", p.kind === "dynamic" ? "red" : "")), parts));
    }
  },

  policy_results(d) {
    const rows = [];
    for (const r of d.results) for (const c of r.checks) rows.push(h("tr", {},
      h("td", {}, h("code", {}, r.policy)), h("td", {}, r.title), h("td", {}, r.subject || ""),
      h("td", {}, c.field), h("td", {}, fmt(c.expected)), h("td", {}, fmt(c.observed)),
      h("td", { class: c.ok ? "ok" : "bad" }, c.ok ? "PASS" : "FAIL"), h("td", { class: "muted" }, r.findingId)));
    body("policy").append(rows.length
      ? h("table", {}, h("tr", {}, ["Policy", "Rule", "Subject", "Field", "Expected", "Observed", "Result", "Finding"].map((x) => h("th", {}, x))), rows)
      : h("div", { class: "callout" }, "No policy matched the observed facts."));
  },

  risk(d) {
    const b = body("risk");
    b.append(h("div", { class: "muted" }, "Thresholds: ", d.thresholds.map(([n, x]) => `${x} ≥ ${n}`).join(" · "),
      " · info = attempt blocked by a control"));
    const rows = d.findings.map((f) => {
      const factors = [];
      const cls = f.factors.data_classification;
      if (cls !== undefined) factors.push(h("span", { class: "factor" }, `${cls} `, h("b", {}, `+${d.classification[cls] ?? 1}`)));
      for (const [k, w] of Object.entries(d.weights)) if (f.factors[k]) factors.push(h("span", { class: "factor" }, `${k.replaceAll("_", " ")} `, h("b", {}, `+${w}`)));
      return h("tr", {}, h("td", {}, sev(f.severity)), h("td", {}, h("code", {}, f.id)), h("td", { class: "score" }, f.score),
        h("td", {}, h("div", { class: "riskbar" }, factors.length ? factors : h("span", { class: "muted" }, "blocked by control"))));
    });
    b.append(h("table", {}, h("tr", {}, ["Severity", "Finding", "Score", "Deterministic factors"].map((x) => h("th", {}, x))), rows));
  },

  summary(d) {
    const sm = d.summary;
    const b = body("gate");
    b.append(h("table", {}, h("tr", {}, ["Severity", "ID", "Finding", "Kind", "Score"].map((x) => h("th", {}, x))),
      d.findings.map((f) => h("tr", {}, h("td", {}, sev(f.risk.severity)), h("td", {}, h("code", {}, f.id)), h("td", {}, f.title,
        f.remediation?.length ? h("div", { class: "muted" }, "Fix: " + [...new Set(f.remediation)].join(" ")) : null),
        h("td", {}, f.kind), h("td", { class: "score" }, f.risk.score)))));
    const t = sm.tests;
    const banner = $("#gate-banner");
    banner.className = `gate-banner ${sm.gate.result}`;
    banner.replaceChildren(
      h("span", {}, sm.gate.result === "FAIL" ? "❌ Agent Security Gate: FAILED" : "✅ Agent Security Gate: PASSED"),
      h("span", { class: "stats" }, `Tests ${t.total} · Passed ${t.passed} · Failed ${t.failed} · Skipped ${t.skipped}  |  `,
        Object.entries(sm.findings).map(([k, v]) => `${k} ${v}`).join(" · "), `  |  fail on ≥ ${sm.gate.failOn}`));
    b.append(h("div", { class: "callout" }, sm.gate.result === "FAIL"
      ? `Deployment blocked: ${sm.gate.blocking.join(", ")} at or above "${sm.gate.failOn}". In CI this is exit code 1.`
      : `No finding at or above "${sm.gate.failOn}". Deployment may proceed (exit code 0).`));
    setNow(sm.gate.result === "FAIL" ? "Gate FAILED" : "Gate PASSED", null, null, "");
  },

  done(d) {
    body("gate").append(h("div", {}, h("a", { href: d.report, download: `agentsec-report-${d.runId}.json` }, h("button", { class: "ghost" }, "⬇ JSON report")), " ",
      h("a", { href: d.markdown, download: `agentsec-summary-${d.runId}.md` }, h("button", { class: "ghost" }, "⬇ Markdown summary (as in GitHub Actions)"))));
    scrollTo($("#gate-banner"));
  },

  error(d) {
    $("#timeline").append(h("div", { class: "gate-banner FAIL" }, `Scan error: ${d.message}`));
    setNow("Error", d.message, "", "");
  },
};

function findingCard(f) {
  const fails = (f.policy_results || []).filter((r) => r.result === "FAIL");
  return h("div", { class: "finding" },
    h("div", { class: "f-head" }, sev(f.risk.severity), h("code", {}, f.id), h("span", { class: "f-title" }, f.title)),
    h("ul", {}, fails.flatMap((r) => r.checks.filter((c) => !c.ok).map((c) =>
      h("li", {}, `${r.policy}: expected ${c.field} = ${fmt(c.expected)}, observed ${fmt(c.observed)}`))),
      [...new Set(f.remediation || [])].map((x) => h("li", { class: "muted" }, `Fix: ${x}`))));
}

/* ------------------------------------------------------------------ capability graph (SVG) */
function drawGraph() {
  const g = state.graph;
  if (!g) return;
  const byId = Object.fromEntries(g.nodes.map((n) => [n.id, n]));
  const col = { Agent: 0, Tool: 1, Identity: 2, Resource: 2, Permission: 3, Data: 3 };
  const cols = [[], [], [], []];
  for (const n of g.nodes) if (n.id in byId && col[n.type] !== undefined) cols[col[n.type]].push(n);
  cols[2].sort((a, b) => (a.type === b.type ? 0 : a.type === "Identity" ? -1 : 1));
  cols[3].sort((a, b) => (a.type === b.type ? 0 : a.type === "Data" ? -1 : 1));
  const W = 376, colX = [4, 96, 196, 286], boxW = [84, 92, 84, 88], rowH = 30;
  const rows = Math.max(...cols.map((c) => c.length), 1);
  const H = rows * rowH + 24;
  const pos = {};
  cols.forEach((c, ci) => {
    const off = (H - c.length * rowH) / 2;
    c.forEach((n, i) => { pos[n.id] = { x: colX[ci], y: off + i * rowH + 4, w: boxW[ci], h: rowH - 8 }; });
  });
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}` });
  const defs = s("defs");
  for (const [id, color] of [["arr", "#4b5563"], ["arrR", "#f85149"], ["arrY", "#d29922"]]) {
    const m = s("marker", { id, viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 6, markerHeight: 6, orient: "auto" });
    m.append(s("path", { d: "M0,0 L10,5 L0,10 z", fill: color }));
    defs.append(m);
  }
  svg.append(defs);
  const line = (a, b, color, width, dash, marker) => {
    const p = pos[a], q = pos[b];
    if (!p || !q) return null;
    const x1 = p.x + p.w, y1 = p.y + p.h / 2, x2 = q.x, y2 = q.y + q.h / 2, mx = (x1 + x2) / 2;
    return s("path", { d: `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2 - 1},${y2}`, fill: "none", stroke: color,
      "stroke-width": width, "stroke-dasharray": dash || "", "marker-end": `url(#${marker})` });
  };
  const show = new Set(["CAN_INVOKE", "EXECUTES_AS", "ACCESSES", "HAS_PERMISSION", "CONTAINS"]);
  for (const e of g.edges) if (show.has(e.rel)) { const l = line(e.src, e.dst, "#4b5563", 1, e.rel === "HAS_PERMISSION" ? "2 2" : "", "arr"); if (l) svg.append(l); }
  const inv = {};
  for (const e of g.edges.filter((x) => x.rel === "INVOKED")) {
    const ok = e.props.status === "success";
    const k = `${e.dst}|${ok}`;
    (inv[k] ||= { dst: e.dst, ok, calls: 0, records: 0 }).calls++;
    inv[k].records += e.props.recordsReturned || 0;
  }
  for (const v of Object.values(inv)) {
    const agent = cols[0][0];
    if (!agent) continue;
    const l = line(agent.id, v.dst, v.ok ? "#f85149" : "#d29922", v.ok ? 2.5 : 1.5, v.ok ? "" : "4 3", v.ok ? "arrR" : "arrY");
    if (l) svg.append(l);
    if (v.ok) {
      const q = pos[v.dst];
      svg.append(s("text", { x: q.x - 4, y: q.y - 1, "text-anchor": "end", class: "edge-label" }, `${v.records} rec`));
    }
  }
  const colors = { Agent: "#58a6ff", Tool: "#f0883e", Identity: "#bc8cff", Resource: "#d29922", Permission: "#8b949e", Data: "#ff4d5e" };
  for (const n of g.nodes) {
    const p = pos[n.id];
    if (!p) continue;
    const hl = state.highlight && n.type === "Tool" && n.name === state.highlight;
    const dim = n.type === "Tool" && n.props.effective === false;
    const gEl = s("g", { opacity: dim ? 0.55 : 1 });
    gEl.append(s("rect", { x: p.x, y: p.y, width: p.w, height: p.h, rx: 5, fill: hl ? "#3b1f1f" : "#161b22",
      stroke: hl ? "#f85149" : colors[n.type], "stroke-width": hl ? 2.5 : 1, "stroke-dasharray": dim ? "3 2" : "" }));
    const label = n.name.length > 15 ? n.name.slice(0, 14) + "…" : n.name;
    gEl.append(s("text", { x: p.x + p.w / 2, y: p.y + p.h / 2 + 3.5, "text-anchor": "middle" }, label));
    const title = s("title");
    title.textContent = `${n.type}: ${n.name}\n${JSON.stringify(n.props)}`;
    gEl.append(title);
    svg.append(gEl);
  }
  ["Agent", "Tools", "Identity / API", "Perms / Data"].forEach((t, i) =>
    svg.append(s("text", { x: colX[i] + boxW[i] / 2, y: H - 2, "text-anchor": "middle", fill: "#8b949e", style: "fill:#8b949e;font-size:9.5px" }, t)));
  $("#graph").replaceChildren(svg);
}

/* ------------------------------------------------------------------ rules & attack library tabs */
async function loadDocs() {
  const [pol, att] = await Promise.all([(await fetch("/api/policy")).json(), (await fetch("/api/attacks")).json()]);
  const p = pol.policy;
  $("#tab-rules").replaceChildren(
    h("h2", {}, "Policy: what should happen"),
    h("p", { class: "muted" }, "File: ", h("code", {}, pol.path), ". Pass your own with ", h("code", {}, "agentsec scan --policy my-policy.yaml"), "."),
    h("div", { class: "callout" }, `Gate: block deployment on any finding with severity ≥ `, h("b", {}, p.gate.failOn), "."),
    h("h3", {}, "Rules"),
    p.policies.map((r) => h("div", { class: "policy" }, h("div", {}, h("span", { class: "pid" }, r.id), h("b", {}, r.title || "")),
      h("div", { class: "kv", style: "margin-top:6px" }, h("span", { class: "k" }, "when"), h("code", {}, JSON.stringify(r.when)),
        h("span", { class: "k" }, "require"), h("code", {}, JSON.stringify(r.require)),
        r.finding ? [h("span", { class: "k" }, "finding"), h("span", {}, r.finding)] : null))),
    h("h3", {}, "Raw YAML"), h("pre", { class: "yaml" }, pol.yaml));
  $("#tab-attacks").replaceChildren(
    h("h2", {}, "Attack library: what AgentSec tries"),
    h("p", { class: "muted" }, "File: ", h("code", {}, att.path), ". Tests are written against normalized capabilities, so they work for any agent. Use ",
      h("code", {}, "--attacks my-attacks.yaml"), " for a custom library."),
    h("table", {}, h("tr", {}, ["ID", "Name", "Category / technique", "Applies to", "Payload", "Oracle (judged on telemetry)"].map((x) => h("th", {}, x))),
      att.tests.map((t) => h("tr", {}, h("td", {}, h("code", {}, t.id)), h("td", {}, t.name), h("td", {}, chip(t.category), chip(t.technique)),
        h("td", {}, h("code", {}, JSON.stringify(t.applicable_to || {}))),
        h("td", {}, h("pre", {}, t.message + (t.documents || []).map((d) => `\n📄 ${d.name}:\n${d.content}`).join(""))),
        h("td", {}, h("code", {}, JSON.stringify(t.oracle)))))),
    h("h3", {}, "Raw YAML"), h("pre", { class: "yaml" }, att.yaml));
}

loadTargets();
loadDocs();
