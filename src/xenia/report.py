from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import readonly

class Report:
    def __init__(self, db_path=None, host: str = "127.0.0.1") -> None:
        self.db_path = db_path
        self.host = host
        self.token = secrets.token_urlsafe(24)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self._server.server_address[1] if self._server else 0

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}/?t={self.token}"

    def start(self) -> str:
        report = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def _send(self, code: int, body: bytes, content_type: str) -> None:
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy",
                                 "default-src 'none'; style-src 'unsafe-inline'; "
                                 "script-src 'unsafe-inline'; connect-src 'self'")
                self.send_header("Referrer-Policy", "no-referrer")
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)

                if not secrets.compare_digest(
                    (query.get("t") or [""])[0], report.token
                ):
                    self._send(403, b"forbidden", "text/plain; charset=utf-8")
                    return

                if parsed.path == "/":
                    self._send(200, _PAGE.encode(), "text/html; charset=utf-8")
                    return

                if parsed.path.startswith("/api/"):
                    try:
                        payload = report.api(parsed.path, query)
                    except Exception as exc:
                        payload = {"error": f"{type(exc).__name__}: {exc}"}
                    self._send(200, json.dumps(payload, default=str).encode(),
                               "application/json; charset=utf-8")
                    return

                self._send(404, b"not found", "text/plain; charset=utf-8")

        self._server = ThreadingHTTPServer((self.host, 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True, name="xenia-report")
        self._thread.start()
        return self.url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def api(self, path: str, query: dict) -> dict:
        def one(name, default=None):
            value = (query.get(name) or [default])[0]
            return value or None

        conn = readonly.connect(self.db_path)
        try:
            readonly.require_current(conn)
            if path == "/api/summary":
                return readonly.summary(conn, since=one("since"))
            if path == "/api/tasks":
                return {"rows": readonly.tasks(
                    conn, since=one("since"), repo=one("repo"),
                    status=one("status"), source=one("source"),
                    agent=one("agent"), search=one("q"),
                    order=one("order", "significance") or "significance",
                    overstated_only=one("overstated") == "1")}
            if path == "/api/friction":
                return {"rows": readonly.friction(
                    conn, since=one("since"), repo=one("repo"),
                    search=one("q"), group_by=one("by", "signature") or "signature",
                    min_failures=int(one("min") or 2))}
            if path == "/api/interactions":
                return {"rows": readonly.interactions(
                    conn,
                    since=one("since"), repo=one("repo"), kind=one("kind"),
                    status=one("status"), agent=one("agent"),
                    environment=one("environment"), search=one("q"),
                    tool=one("tool"), via=one("via"), channel=one("channel"),
                    signature=one("signature"), session=one("session"),
                    goal=int(one("goal") or 0) or None,
                    task=int(one("task") or 0) or None,
                    order=one("order", "at") or "at",
                    descending=(one("dir", "desc") or "desc") == "desc",
                    limit=int(one("limit", "200") or 200),
                )}
            if path == "/api/goals":
                return {"rows": readonly.goals(
                    conn, since=one("since"), repo=one("repo"),
                    status=one("status"))}
            if path == "/api/disk":
                return {"rows": readonly.disk_churn(
                    conn, since=one("since"), repo=one("repo"),
                    group_by=one("by", "path") or "path")}
            return {"error": "unknown endpoint"}
        finally:
            conn.close()

_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>xenia</title>
<style>
  :root{color-scheme:light dark;
    --bg:#fbfbfc;--fg:#1b1f24;--muted:#666e78;--line:#e2e5e9;--card:#fff;
    --crit:#c62828;--elev:#b26a00;--ok:#2e7d32;--accent:#4caf50}
  @media (prefers-color-scheme:dark){:root{
    --bg:#15181c;--fg:#e6e9ed;--muted:#9aa3ad;--line:#2a2f36;--card:#1b1f24;
    --crit:#ef5350;--elev:#ffb300;--ok:#66bb6a}}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
    font:14px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
  header{padding:12px 18px 0;border-bottom:1px solid var(--line);
    position:sticky;top:0;background:var(--bg);z-index:3}
  .top{display:flex;align-items:center;gap:16px;flex-wrap:wrap}
  h1{margin:0;font-size:16px;letter-spacing:.02em;font-weight:700}
  .stats{display:flex;gap:14px;flex-wrap:wrap;margin-left:auto;
    font-variant-numeric:tabular-nums;font-size:13px}
  .stat b{font-weight:600}.stat i{font-style:normal;color:var(--muted)}
  .tabs{display:flex;gap:4px;margin-top:10px}
  .tabs button{background:none;border:none;border-bottom:3px solid transparent;
    color:var(--muted);font:inherit;font-size:16px;font-weight:600;
    padding:8px 18px;cursor:pointer;letter-spacing:.01em}
  .tabs button:hover{color:var(--fg)}
  .tabs button.on{color:var(--fg);border-bottom-color:var(--accent)}
  .tabs button .n{font-size:12px;color:var(--muted);font-weight:500;
    margin-left:6px;font-variant-numeric:tabular-nums}
  .bar{display:flex;gap:8px;padding:10px 18px;flex-wrap:wrap;
    border-bottom:1px solid var(--line);align-items:center;
    background:var(--bg)}
  input,select{background:var(--card);color:var(--fg);border:1px solid var(--line);
    border-radius:6px;padding:5px 8px;font:inherit;font-size:13px}
  input[type=search]{min-width:240px;flex:1}
  .wrap{overflow-x:auto}
  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);
    vertical-align:top;white-space:nowrap}
  th{position:sticky;top:0;background:var(--card);cursor:pointer;
    user-select:none;font-weight:600;font-size:12px;letter-spacing:.03em;
    text-transform:uppercase;color:var(--muted)}
  th:hover{color:var(--fg)}
  th .ar{opacity:.45;font-size:10px}
  td.detail{white-space:normal;word-break:break-word;max-width:460px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  td.goal{white-space:normal;max-width:280px;color:var(--muted);font-size:12px}
  td.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}
  tr:hover td{background:color-mix(in srgb,var(--accent) 7%,transparent)}
  .pill{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;
    font-weight:600;letter-spacing:.02em}
  .critical{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}
  .elevated,.warn{background:color-mix(in srgb,var(--elev) 20%,transparent);color:var(--elev)}
  .normal{color:var(--muted)}
  .achieved{background:color-mix(in srgb,var(--ok) 18%,transparent);color:var(--ok)}
  .partial{background:color-mix(in srgb,var(--elev) 20%,transparent);color:var(--elev)}
  .failed,.abandoned{background:color-mix(in srgb,var(--crit) 18%,transparent);color:var(--crit)}
  .no_action,.open{color:var(--muted)}
  .st-ok{color:var(--ok)}.st-error{color:var(--crit)}
  .st-blocked{color:var(--elev)}.st-started{color:var(--muted)}
  button.act{background:var(--card);color:var(--muted);border:1px solid var(--line);
    border-radius:6px;padding:2px 9px;font:inherit;font-size:12px;cursor:pointer;
    white-space:nowrap}
  button.act:hover{color:var(--fg);border-color:var(--muted)}
  .chip{display:inline-flex;align-items:center;gap:8px;background:var(--card);
    border:1px solid var(--line);border-radius:999px;padding:3px 6px 3px 12px;
    font-size:12px;max-width:520px}
  .chip span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .empty{padding:34px 18px;color:var(--muted)}
  footer{padding:10px 18px;color:var(--muted);font-size:12px;
    border-top:1px solid var(--line)}
</style></head><body>
<header>
  <div class="top">
    <h1>xenia</h1>
    <div class="stats" id="stats"></div>
  </div>
  <nav class="tabs">
    <button id="tab-tasks" class="on">Tasks<span class="n" id="n-tasks"></span></button><button id="tab-friction">Failed</button><button id="tab-goals">Instructions</button>
  </nav>
</header>
<div class="bar">
  <input type="search" id="q" placeholder="Search…">
  <select id="since">
    <option value="24h">last 24 hours</option>
    <option value="7d">last 7 days</option>
    <option value="30d">last 30 days</option>
    <option value="">all time</option>
  </select>
  <select id="repo"><option value="">all repos</option></select>
  <select id="kind">
    <option value="">all kinds</option><option>remote_call</option>
    <option>fs_change</option><option>fs_read</option>
    <option>exec</option><option>other</option>
  </select>
  <select id="status">
    <option value="">any status</option><option>ok</option>
    <option>error</option><option>blocked</option>
  </select>
  <select id="tstatus">
    <option value="">any outcome</option><option>achieved</option>
    <option>partial</option><option>failed</option><option>abandoned</option>
    <option>no_action</option><option>open</option>
  </select>
  <select id="source">
    <option value="">any source</option>
    <option value="plan">from its own plan</option>
    <option value="intent">from what it said</option>
    <option value="signature">from the work itself</option>
  </select>
  <label style="color:var(--muted);font-size:12px" id="overstatedWrap">
    <input type="checkbox" id="overstated" style="min-width:auto"> called done, wasn't
  </label>
  <span id="goalChip" hidden></span>
  <span id="taskChip" hidden></span>
  <label style="color:var(--muted);font-size:12px">
    <input type="checkbox" id="live" checked style="min-width:auto"> live
  </label>
</div>
<div class="wrap"><table>
  <thead><tr id="head"></tr></thead>
  <tbody id="rows"></tbody>
</table></div>
<div class="empty" id="empty" hidden>Nothing here for these filters.</div>
<footer id="foot"></footer>
<script>
const T = new URLSearchParams(location.search).get('t');
const HASH_TAB = (location.hash||'').replace(/^#(tab=)?/,'');

const COLS = [
  ['at','Time'],['repo','Repo'],['tool','Tool'],['kind','Kind'],
  ['status','Status'],['detail','What it did'],
  ['goal','Trying to accomplish']
];
const TCOLS = ['Started','Repo','What it was trying to do','Written','Outcome',''];
const XCOLS = ['Kind of work','Failed','Recovered','Sessions','Worst run','Example',''];
const GCOLS = ['Started','Repo','Outcome','Actions','Instruction',''];
let order = 'at', dir = 'desc', timer = null, tab = 'tasks';
let goalFilter = null, taskFilter = null;

function el(id){ return document.getElementById(id); }
function esc(s){ return (s==null?'':String(s)).replace(/[&<>"]/g,
  c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function timeOf(s){
  if(!s) return '';
  const d = new Date(s);
  return isNaN(d) ? s.slice(0,19).replace('T',' ')
    : d.toLocaleString(undefined,{month:'short',day:'2-digit',
        hour:'2-digit',minute:'2-digit',second:'2-digit'});
}
function bytes(n){
  n = Number(n||0);
  if(n < 1024) return n + ' B';
  const units = ['kB','MB','GB','TB'];
  let i = -1;
  do { n /= 1024; i++; } while(n >= 1024 && i < units.length-1);
  return (n < 10 ? n.toFixed(1) : Math.round(n)) + ' ' + units[i];
}

function head(){
  const fixed = {tasks:TCOLS, friction:XCOLS, goals:GCOLS}[tab];
  if(fixed){ el('head').innerHTML = fixed.map(l=>`<th>${l}</th>`).join(''); return; }
  el('head').innerHTML = COLS.map(([k,label])=>{
    const on = k===order, sortable = k!=='detail' && k!=='goal';
    return `<th data-k="${k}" ${sortable?'':'style="cursor:default"'}>${label}` +
      (on?` <span class="ar">${dir==='desc'?'▼':'▲'}</span>`:'') + `</th>`;
  }).join('');
  el('head').querySelectorAll('th').forEach(th=>{
    if(!th.dataset.k || th.dataset.k==='detail' || th.dataset.k==='goal') return;
    th.onclick = ()=>{
      const k = th.dataset.k;
      if(k===order){ dir = dir==='desc'?'asc':'desc'; } else { order=k; dir='desc'; }
      head(); load();
    };
  });
}

function filters(extra){
  const p = new URLSearchParams({t:T, ...(extra||{})});
  for(const id of ['since','repo','kind','status']){
    const v = el(id).value; if(v) p.set(id, v);
  }
  return p;
}

async function rowsFrom(path, params){
  const r = await fetch(path + '?' + params);
  return ((await r.json()).rows) || [];
}

async function loadTasks(){
  const p = filters();
  const q = el('q').value.trim(); if(q) p.set('q', q);
  p.delete('status');
  if(el('tstatus').value) p.set('status', el('tstatus').value);
  if(el('source').value) p.set('source', el('source').value);
  if(el('overstated').checked) p.set('overstated','1');
  const rows = await rowsFrom('/api/tasks', p);

  el('rows').innerHTML = rows.map(t=>{
    const lie = t.overstated
      ? ` <span class="pill critical" title="${esc(t.note||'')}">called done</span>` : '';
    const retries = t.attempts > 1
      ? ` <span class="pill elevated">${t.attempts} attempts</span>` : '';
    const fixed = t.failures && t.failures_fixed
      ? ` <span class="pill normal">${t.failures_fixed}/${t.failures} recovered</span>` : '';
    const partial = t.writes > t.sized_writes
      ? ` title="${t.sized_writes} of ${t.writes} writes had a measurable size"` : '';
    const written = t.bytes_written
      ? `${bytes(t.bytes_written)}${t.writes > t.sized_writes ? '+' : ''}`
      : (t.writes ? '?' : '');
    return `<tr>
      <td class="mono">${esc(timeOf(t.at))}</td>
      <td>${esc(t.repo||'')}</td>
      <td class="detail">${esc(t.label||'')}${lie}${retries}${fixed}
        ${t.goal_summary?`<br><i style="opacity:.6">under: ${esc(t.goal_summary.slice(0,90))}</i>`:''}</td>
      <td class="mono"${partial}>${written}</td>
      <td><span class="pill ${esc(t.status)}" title="${esc(t.note||'')}">${esc(t.status)}</span></td>
      <td><button class="act" data-t="${t.task_id}" data-l="${esc((t.label||'').slice(0,70))}">see actions</button></td>
    </tr>`;
  }).join('');

  el('rows').querySelectorAll('button.act').forEach(b=>{
    b.onclick = ()=>{ taskFilter = {id:b.dataset.t, text:b.dataset.l};
                      goalFilter = null; setTab('activity'); };
  });

  const done = rows.filter(t=>t.status==='achieved').length;
  const lied = rows.filter(t=>t.overstated).length;
  el('empty').hidden = rows.length > 0;
  el('foot').textContent = `${rows.length} task${rows.length===1?'':'s'}`
    + ` · ${done} achieved`
    + (lied?` · ${lied} the agent called finished that the actions say were not`:'')
    + ` · outcomes are read from the calls, not from what the agent claimed`;
}

async function loadFriction(){
  const rows = await rowsFrom('/api/friction', filters());

  el('rows').innerHTML = rows.map(f=>{
    const stuck = f.failures - (f.recovered||0);
    return `<tr>
      <td class="mono">${esc(f.example_task || f.signature)}</td>
      <td class="mono"><span class="pill ${stuck?'critical':'warn'}">${f.failures}</span></td>
      <td class="mono">${f.recovered||0}</td>
      <td class="mono">${f.sessions||0}</td>
      <td class="mono">${f.worst_attempt||1}</td>
      <td class="detail">${esc((f.example||'').slice(0,150))}
        ${f.example_error?`<br><i style="color:var(--crit)">${esc(f.example_error.slice(0,110))}</i>`:''}</td>
      <td><button class="act" data-q="${esc((f.example||'').slice(0,60))}">see actions</button></td>
    </tr>`;
  }).join('');

  el('rows').querySelectorAll('button.act').forEach(b=>{
    b.onclick = ()=>{ el('q').value = b.dataset.q; el('status').value = '';
                      taskFilter = null; goalFilter = null; setTab('activity'); };
  });

  el('empty').hidden = rows.length > 0;
  el('foot').textContent = `${rows.length} kind${rows.length===1?'':'s'} of work that`
    + ` failed more than once · sorted by what was never recovered from`
    + ` · a high count that never recovers is a gap in the environment or the`
    + ` instructions, not bad luck`;
}

async function load(){
  const p = filters({order, dir, limit:'400'});
  const q = el('q').value.trim(); if(q) p.set('q', q);
  if(goalFilter) p.set('goal', goalFilter.id);
  if(taskFilter) p.set('task', taskFilter.id);
  const rows = await rowsFrom('/api/interactions', p);

  el('rows').innerHTML = rows.map(x=>{
    const detail = x.detail || x.paths || x.error || '';
    const extra = x.mutating ? ' <span class="pill elevated">writes</span>' : '';
    const sens = x.sensitivity && x.sensitivity!=='normal'
      ? ` <span class="pill ${x.sensitivity==='guardrail'?'critical':'elevated'}">${esc(x.sensitivity)}</span>` : '';
    const head = x.task || x.intent;
    const goal = (head ? `<b>${esc(head)}</b>` : '')
      + (x.goal_summary ? `${head?'<br>':''}${esc(x.goal_summary.slice(0,110))}` : '');
    return `<tr>
      <td class="mono">${esc(timeOf(x.at))}</td>
      <td>${esc(x.repo||'')}</td>
      <td class="mono">${esc(x.tool||'')}</td>
      <td>${esc(x.kind||'')}</td>
      <td class="st-${esc(x.status)}">${esc(x.status)}</td>
      <td class="detail">${esc(detail)}${extra}${sens}</td>
      <td class="goal">${goal}</td></tr>`;
  }).join('');
  el('empty').hidden = rows.length > 0;
  el('foot').textContent = `${rows.length} interaction${rows.length===1?'':'s'}`
    + ` · sorted by ${order} ${dir}`
    + (goalFilter?` · filtered to one instruction`:'')
    + (taskFilter?` · filtered to one task`:'')
    + ` · secrets redacted at capture`;
}

async function loadGoals(){
  const rows = await rowsFrom('/api/goals', filters());

  el('rows').innerHTML = rows.map(g=>`<tr>
      <td class="mono">${esc(timeOf(g.at))}</td>
      <td>${esc(g.repo||'')}</td>
      <td><span class="pill ${esc(g.status)}">${esc(g.status)}</span></td>
      <td class="mono">${g.actions||0}${g.failures?` <span class="pill warn">${g.failures} failed</span>`:''}</td>
      <td class="detail">${esc((g.prompt||'').slice(0,240))}</td>
      <td><button class="act" data-g="${g.goal_id}" data-t="${esc((g.prompt||'').slice(0,70))}">see actions</button></td>
    </tr>`).join('');

  el('rows').querySelectorAll('button.act').forEach(b=>{
    b.onclick = ()=>{ goalFilter = {id:b.dataset.g, text:b.dataset.t}; setTab('activity'); };
  });

  el('empty').hidden = rows.length > 0;
  el('foot').textContent = `${rows.length} instruction${rows.length===1?'':'s'}`
    + ` · each one scored from the actions taken under it`;
}

function chip(box, filter, label, clear){
  box.hidden = !(filter && tab==='activity');
  if(box.hidden) return;
  box.innerHTML = `<span class="chip"><span>${label}: ${esc(filter.text)}</span>`
    + `<button class="act" data-clear="1">clear</button></span>`;
  box.querySelector('button').onclick = ()=>{
    clear(); drawChip();
    if(tab==='activity' && !goalFilter && !taskFilter){ setTab('tasks'); return; }
    load();
  };
}

function drawChip(){
  chip(el('goalChip'), goalFilter, 'instruction', ()=>{ goalFilter = null; });
  chip(el('taskChip'), taskFilter, 'task', ()=>{ taskFilter = null; });
}

const TABS = ['tasks','friction','goals'];
const VIEWS = TABS.concat(['activity']);

function setTab(name){
  tab = name;
  for(const t of TABS) el('tab-'+t).className = (t===name) ? 'on' : '';
  for(const id of ['kind','status']) el(id).hidden = name!=='activity';
  for(const id of ['tstatus','source']) el(id).hidden = name!=='tasks';
  el('overstatedWrap').hidden = name!=='tasks';
  el('q').hidden = !(name==='activity' || name==='tasks');
  drawChip(); head(); refresh();
}

function refresh(){
  stats();
  ({tasks:loadTasks, friction:loadFriction, goals:loadGoals,
    activity:load}[tab] || load)();
}

async function stats(){
  const s = await (await fetch('/api/summary?'+filters())).json();
  el('stats').innerHTML = [
    ['tasks', s.tasks],['achieved', s.tasks_achieved],
    ['unfinished', (s.tasks_partial||0)+(s.tasks_failed||0)],
    ['actions', s.actions],['failed', s.failed]
  ].map(([k,v])=>`<span class="stat"><b>${v??0}</b> <i>${k}</i></span>`).join('');
  el('n-tasks').textContent = s.tasks_overstated ? '⚠ '+s.tasks_overstated : '';
  const sel = el('repo'), cur = sel.value;
  sel.innerHTML = '<option value="">all repos</option>' +
    (s.repos||[]).map(r=>`<option ${r===cur?'selected':''}>${esc(r)}</option>`).join('');
}

for(const id of ['since','repo','kind','status','tstatus','source'])
  el(id).onchange = refresh;
el('overstated').onchange = loadTasks;
let deb; el('q').oninput = ()=>{ clearTimeout(deb); deb=setTimeout(refresh,220); };
el('live').onchange = ()=>{ clearInterval(timer);
  if(el('live').checked) timer = setInterval(refresh, 5000); };
for(const t of TABS) el('tab-'+t).onclick = ()=>setTab(t);

setTab(VIEWS.includes(HASH_TAB) ? HASH_TAB : 'tasks');
timer = setInterval(refresh, 5000);
</script></body></html>
"""
