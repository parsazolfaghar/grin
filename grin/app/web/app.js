// Grin desktop app — talks to the Python bridge (window.pywebview.api). Degrades to static
// sample data when opened in a plain browser (no pywebview) so the look is verifiable.
const HAS_API = () => !!(window.pywebview && window.pywebview.api);
const api = () => window.pywebview.api;
const el = (id) => document.getElementById(id);
let JOB = null, POLL = null, CURRENT_FILE = null;

function tag(status){return ({ok:"[ OK ]",missing:"[MISSING]",broken:"[BROKEN]",skipped:"[SKIP]"})[status]||status;}

async function boot(){
  if(!HAS_API()){ return renderStaticFallback(); }
  // preflight log from the doctor
  try{
    const d = await api().doctor();
    el("bootlog").innerHTML = (d.checks||[])
      .map(c => `<div><span class="${c.status==='ok'?'okk':'y'}">${tag(c.status)}</span> ${c.name} — ${c.detail}</div>`)
      .join("") + `<div class="y">[ READY ] awaiting engagement</div>`;
  }catch(e){ el("bootlog").innerHTML = `<div class="y">[ WARN ] doctor: ${e}</div>`; }
  // engagements
  try{
    const rows = await api().list_engagements();
    el("englist").innerHTML = rows.map(r => r.valid
      ? `<div class="row eng" data-file="${r.file}"><span class="mk"></span><div><div class="t">${r.id} · ${r.mode}</div><div class="s">${r.name} // ${r.state} // ${r.targets} target(s)</div></div></div>`
      : `<div class="row"><span class="mk"></span><div><div class="t y">invalid: ${r.file}</div><div class="s">${r.error}</div></div></div>`
    ).join("") || `<div class="s dim">no engagements in this folder</div>`;
    document.querySelectorAll(".eng").forEach(n => n.addEventListener("click", () => startEngagement(n.dataset.file)));
  }catch(e){ el("englist").innerHTML = `<div class="s y">${e}</div>`; }
}

async function startEngagement(file){
  CURRENT_FILE = file;
  const goal = prompt("Engagement goal:", "assess the target") || "assess the target";
  const r = await api().start_engagement(file, goal);
  if(r.error){ alert(r.error); return; }
  JOB = r.job_id;
  el("boot").style.display = "none";
  el("live").style.display = "";
  el("live-path").textContent = "▸ " + file;
  if(POLL) clearInterval(POLL);
  POLL = setInterval(poll, 1500);
  poll();
}

async function poll(){
  if(!JOB) return;
  const s = await api().engagement_state(JOB);
  el("live-chip").textContent = s.status === "running" ? "● RUNNING" : "● " + (s.status||"").toUpperCase();
  renderRows("obj-rows", (s.objectives||[]).map(o => ({t:`${o.objective} · ${o.target}`, s:o.action_class||""})));
  renderRows("find-rows", (s.findings||[]).map(f => ({sev:f.severity, t:`${f.title} · ${f.target}`, s:`${f.evidence} // ${f.tool}`})));
  el("audit-rows").innerHTML = (s.audit||[]).map(a =>
    `<div class="ln ${a.decision==='refuse'?'refuse':'allow'}"><span class="ts">${(a.ts||'').slice(11,19)}</span> ${a.decision} ${a.action_class||''} ${a.command||''}</div>`).join("");
  renderApprove(s.blocked||[]);
  el("live-status").querySelector("#st-obj").textContent = "OBJ " + (s.objectives||[]).length;
  el("live-status").querySelector("#st-find").textContent = "FIND " + (s.findings||[]).length;
  el("live-status").querySelector("#st-block").textContent = "BLOCKED " + (s.blocked||[]).length;
}

function renderRows(id, items){
  el(id).innerHTML = items.map(i =>
    i.sev ? `<div class="row"><span class="sev ${({high:'high',critical:'high',medium:'med',med:'med'})[i.sev]||'info'}">${(i.sev||'info').toUpperCase()}</span><div><div class="t">${i.t}</div><div class="s">${i.s||''}</div></div></div>`
          : `<div class="row"><span class="mk"></span><div><div class="t">${i.t}</div><div class="s">${i.s||''}</div></div></div>`
  ).join("");
}

function renderApprove(blocked){
  const box = el("approve");
  if(!blocked.length){ box.style.display = "none"; return; }
  const b = blocked[0];
  box.style.display = "";
  el("approve-cmd").innerHTML = `${b.tool}: ${b.command} <span class="dim">// ${b.resolved_class} // ${b.target}</span>`;
  el("approve").dataset.pid = b.id;
}

async function decide(approve){
  const pid = el("approve").dataset.pid;
  if(!pid) return;
  await (approve ? api().approve(CURRENT_FILE, pid) : api().deny(CURRENT_FILE, pid));
  poll();
}

document.addEventListener("keydown", (e) => {
  if(el("approve").style.display === "none") return;
  if(e.key.toLowerCase() === "a") decide(true);
  if(e.key.toLowerCase() === "d") decide(false);
});

function renderStaticFallback(){
  // shown only when opened in a plain browser (no pywebview) — the locked sample data
  el("bootlog").innerHTML = `
    <div><span class="okk">[ OK ]</span> spine online — scope · roe · gate loaded</div>
    <div><span class="okk">[ OK ]</span> ollama up — qwen3:14b · qwen3:8b · hermes3:8b</div>
    <div><span class="okk">[ OK ]</span> arsenal bound — kali · blackarch</div>
    <div class="y">[ READY ] awaiting engagement</div>`;
  el("englist").innerHTML = `<div class="row"><span class="mk"></span><div><div class="t">acme-extnet-2026-06 · client</div><div class="s">external network // active // 4 target(s)</div></div></div>`;
}

window.addEventListener("pywebviewready", boot);
window.addEventListener("DOMContentLoaded", () => { if(!HAS_API()) renderStaticFallback(); });
