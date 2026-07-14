import html


def customer_workspace_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Customer Workspace</title>
  <style>
    :root { --bg:#0e1115; --band:#14191f; --panel:#1a2027; --field:#0a0d11; --line:#35404b; --text:#f4f7f8; --muted:#aab5bf; --green:#65df88; --blue:#67bde8; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#11161b; }
    header > div, main, footer > div { width:min(1180px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:72px; display:flex; align-items:center; justify-content:space-between; gap:18px; }
    .brand { font-size:18px; font-weight:800; }
    nav { display:flex; flex-wrap:wrap; gap:8px; }
    nav a, .link-button { display:inline-flex; align-items:center; justify-content:center; min-height:38px; padding:0 11px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:750; }
    main { padding:30px 0 52px; }
    h1 { margin:0; font-size:clamp(2rem,5vw,3.6rem); line-height:1.04; }
    h2 { margin:0; font-size:18px; }
    h3 { margin:0; font-size:15px; }
    .lead { max-width:760px; margin:10px 0 0; color:var(--muted); font-size:16px; }
    .privacy { margin-top:16px; padding:12px 14px; border-left:4px solid var(--blue); background:#151d24; color:var(--muted); }
    .signin { display:grid; grid-template-columns:minmax(260px,1fr) minmax(210px,.45fr) auto auto; gap:10px; align-items:end; margin-top:22px; padding:18px; border:1px solid var(--line); background:var(--band); }
    label { display:block; margin-bottom:6px; color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; }
    input, select { width:100%; min-width:0; height:43px; padding:0 11px; border:1px solid var(--line); border-radius:5px; background:var(--field); color:var(--text); font:inherit; }
    button { min-height:43px; padding:0 14px; border:0; border-radius:5px; background:#29323c; color:var(--text); font:800 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:disabled { cursor:not-allowed; opacity:.5; }
    .primary { background:var(--green); color:#071109; }
    .blue { background:var(--blue); color:#071118; }
    .status { min-height:22px; margin-top:10px; color:var(--muted); }
    .status.good { color:var(--green); } .status.warn { color:var(--yellow); } .status.bad { color:var(--red); }
    #workspace[hidden] { display:none; }
    .toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-top:18px; }
    .metrics { display:grid; grid-template-columns:repeat(8,minmax(110px,1fr)); margin-top:16px; border:1px solid var(--line); }
    .metric { min-width:0; padding:15px; border-right:1px solid var(--line); background:var(--band); }
    .metric:last-child { border-right:0; }
    .metric span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    .metric strong { display:block; margin-top:5px; font-size:16px; overflow-wrap:anywhere; }
    .band { margin-top:22px; padding:20px 0; border-top:1px solid var(--line); }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:14px; margin-bottom:12px; }
    .section-head p { max-width:650px; margin:0; color:var(--muted); text-align:right; }
    .action-list { display:grid; gap:8px; }
    .action { display:grid; grid-template-columns:auto minmax(0,1fr) auto; gap:12px; align-items:center; padding:13px 14px; border-left:4px solid var(--blue); background:var(--panel); }
    .action.now { border-left-color:var(--red); } .action.soon { border-left-color:var(--yellow); } .action.maintain { border-left-color:var(--green); }
    .action input { width:18px; height:18px; }
    .action p, .tool p, .event p, .rank p, .surface p { margin:3px 0 0; color:var(--muted); }
    .action .when { color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; }
    .filters { display:flex; flex-wrap:wrap; gap:6px; margin-bottom:10px; }
    .filters button { min-height:34px; border:1px solid var(--line); background:var(--panel); }
    .filters button.active { border-color:var(--blue); background:var(--blue); color:#071118; }
    .hidden { display:none!important; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:10px; }
    .tool, .event, .rank, .surface { min-width:0; padding:15px; border:1px solid var(--line); border-radius:6px; background:var(--panel); }
    .tool ul { margin:10px 0 0; padding-left:18px; color:var(--muted); }
    .tool li { margin:5px 0; }
    .eyebrow { color:var(--blue); font-size:10px; font-weight:800; text-transform:uppercase; }
    .search-row { display:grid; grid-template-columns:minmax(220px,1fr) auto; gap:9px; margin-bottom:10px; }
    .empty { padding:25px 16px; border:1px dashed var(--line); color:var(--muted); text-align:center; }
    .quick-links { display:flex; flex-wrap:wrap; gap:8px; }
    .quick-links a { background:#202833; }
    footer { border-top:1px solid var(--line); background:#11161b; }
    footer > div { padding:22px 0 28px; color:var(--muted); }
    @media (max-width:1050px) { .metrics { grid-template-columns:repeat(4,1fr); } .metric { border-bottom:1px solid var(--line); } }
    @media (max-width:780px) { header > div,.section-head { align-items:flex-start; flex-direction:column; padding:14px 0; } .section-head p { text-align:left; } .signin { grid-template-columns:1fr 1fr; } .metrics { grid-template-columns:repeat(2,1fr); } }
    @media (max-width:520px) { .signin { grid-template-columns:1fr; } .metrics { grid-template-columns:1fr; } .metric { border-right:0; } .action { grid-template-columns:auto minmax(0,1fr); } .action .when { grid-column:2; } }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Customer Workspace</div><nav><a href="/customer">LICENSE</a><a href="/update">UPDATE</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a><a href="/shop">SHOP</a></nav></div></header>
  <main>
    <h1>Your VaultLink workspace</h1>
    <p class="lead">One check builds your account overview, prioritized action plan, rank tools, release status, renewal timeline, upgrade path, and support routes.</p>
    <div class="privacy">The key stays in this tab's memory, is sent only in the JSON request body, and is never placed in a URL or browser storage. Results exclude customer identity, owner notes, machine identity, receipts, PINs, USB secrets, paths, and file contents.</div>
    <section class="signin">
      <div><label for="licenseKey">License key</label><input id="licenseKey" type="password" autocomplete="off" spellcheck="false"></div>
      <div><label for="appVersion">Installed version, optional</label><input id="appVersion" maxlength="80" autocomplete="off" spellcheck="false" placeholder="2026.07.14.2"></div>
      <button id="load" class="primary" type="button">LOAD WORKSPACE</button>
      <button id="clear" type="button">CLEAR</button>
    </section>
    <div id="status" class="status" role="status" aria-live="polite">Not loaded.</div>

    <div id="workspace" hidden>
      <div class="toolbar"><button id="copy" class="blue" type="button">COPY SAFE SUMMARY</button><button id="export" type="button">EXPORT SAFE JSON</button><button id="exportSupport" type="button">EXPORT SUPPORT PACK</button><button id="exportRecovery" type="button">EXPORT RECOVERY CARD</button><button id="resetProgress" type="button">RESET CHECKLIST</button></div>
      <div id="metrics" class="metrics"></div>

      <section class="band">
        <div class="section-head"><h2>Workspace Score</h2><p id="scoreSummary">Operational status only, not an antivirus result or certification.</p></div>
        <div id="scoreFactors" class="grid"></div>
      </section>

      <section id="action-plan" class="band">
        <div class="section-head"><h2>Priority Action Plan</h2><p id="actionSummary">Session-only checklist. Nothing here can control the customer PC.</p></div>
        <div id="actionFilters" class="filters"><button type="button" data-filter="all" class="active">ALL</button><button type="button" data-filter="now">NOW</button><button type="button" data-filter="soon">THIS WEEK</button><button type="button" data-filter="maintain">THIS MONTH</button></div>
        <div id="actions" class="action-list"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>30-Day Success Plan</h2><p>Actions grouped into today, this week, and this month.</p></div>
        <div id="successPlan" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Benefit Map</h2><p>See what the current rank includes and what the next rank adds.</p></div>
        <div id="benefits" class="grid"></div>
      </section>

      <section id="rank-tools" class="band">
        <div class="section-head"><h2>Unlocked Rank Tools</h2><p>Every included checklist for the active rank, with no hidden device or customer fields.</p></div>
        <div class="search-row"><input id="toolSearch" type="search" autocomplete="off" placeholder="Search unlocked tools"><button id="clearToolSearch" type="button">CLEAR SEARCH</button></div>
        <div id="tools" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>License Timeline</h2><p>Issue, signed release, current check, limits, and renewal dates in one view.</p></div>
        <div id="timeline" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Upgrade Path</h2><p>Compare added entitlements. Payments stay on separately hosted provider pages.</p></div>
        <div id="upgrades" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Customer Tools</h2><p>Direct routes for updates, recovery, service information, privacy, and support preparation.</p></div>
        <div id="quickLinks" class="quick-links"></div>
      </section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. This workspace is informational. It cannot inspect, lock, unlock, execute, install, scan, or modify anything on a customer PC.</div></footer>
  <script>
    const $ = (id) => document.getElementById(id);
    const state = { payload:null, completed:new Set(), actionFilter:"all" };
    const value = (input) => String(input ?? "");
    function setStatus(message,tone="") { $("status").textContent=message; $("status").className=`status ${tone}`; }
    function addText(parent,tag,text,className="") { const node=document.createElement(tag); node.textContent=value(text); if(className) node.className=className; parent.append(node); return node; }
    function metric(label,data) { const item=document.createElement("div"); item.className="metric"; addText(item,"span",label); addText(item,"strong",data); return item; }
    function safeExport() {
      if(!state.payload) return null;
      return { exported_at_utc:new Date().toISOString(), workspace_schema_version:state.payload.workspace_schema_version, summary:state.payload.summary, workspace_score:state.payload.workspace_score, checkup:state.payload.checkup, action_center:state.payload.action_center, success_plan:state.payload.success_plan, benefit_map:state.payload.benefit_map, timeline:state.payload.timeline, rank_tools:state.payload.rank_tools, upgrade_options:state.payload.upgrade_options, support_pack:state.payload.support_pack, recovery_card:state.payload.recovery_card, completed_action_ids:[...state.completed].sort(), privacy_notice:state.payload.privacy_notice };
    }
    function renderMetrics(data) {
      const root=$("metrics"); root.replaceChildren();
      const summary=data.summary; const checkup=data.checkup; const expires=summary.license.expires_at_utc || "No expiration";
      [["Workspace score",`${data.workspace_score.score} / 100`],["Status",summary.status.toUpperCase()],["Rank",`${summary.plan.rank} - ${summary.plan.name}`],["Device seats",`${summary.device_usage.active} / ${summary.device_usage.maximum}`],["Expires",expires],["Desktop",summary.release.latest_version || "Not published"],["Service",summary.service_status.mode],["Needs attention",checkup.attention_count]].forEach(([label,item])=>root.append(metric(label,item)));
    }
    function renderScore(data) {
      const root=$("scoreFactors"); root.replaceChildren(); const score=data.workspace_score;
      $("scoreSummary").textContent=`${score.score} of ${score.maximum} | ${score.label.toUpperCase()} | ${score.limitations}`;
      (score.factors||[]).forEach((item)=>{ const card=document.createElement("article"); card.className="tool"; addText(card,"div",`${item.awarded} of ${item.maximum} | ${item.state}`,"eyebrow"); addText(card,"h3",item.title); addText(card,"p",item.detail); root.append(card); });
    }
    function renderActions(data) {
      const root=$("actions"); root.replaceChildren();
      const items=data.action_center.items || [];
      if(!items.length){ root.innerHTML='<div class="empty">No actions are available.</div>'; return; }
      items.forEach((item)=>{ const row=document.createElement("div"); row.className=`action ${item.when}`; row.dataset.when=item.when; const check=document.createElement("input"); check.type="checkbox"; check.checked=state.completed.has(item.id); check.addEventListener("change",()=>{ if(check.checked)state.completed.add(item.id);else state.completed.delete(item.id); updateProgress(items.length); }); const body=document.createElement("div"); addText(body,"h3",item.title); addText(body,"p",item.detail); row.append(check,body); addText(row,"div",item.when,"when"); root.append(row); });
      filterActions(state.actionFilter);
      updateProgress(items.length);
    }
    function filterActions(filter) { state.actionFilter=filter; document.querySelectorAll("#actionFilters button").forEach(button=>button.classList.toggle("active",button.dataset.filter===filter)); document.querySelectorAll("#actions .action").forEach(row=>row.classList.toggle("hidden",filter!=="all"&&row.dataset.when!==filter)); }
    function updateProgress(total) { $("actionSummary").textContent=`${state.completed.size} of ${total} customer actions complete in this tab. Progress is not uploaded or saved.`; }
    function renderTools(data) {
      const root=$("tools"); root.replaceChildren(); const tools=data.rank_tools.items || [];
      if(!tools.length){ root.innerHTML='<div class="empty">Rank tools are unavailable for the current license status.</div>'; return; }
      tools.forEach((item)=>{ const card=document.createElement("article"); card.className="tool"; card.dataset.search=`${item.name} ${item.summary} ${item.category} ${(item.checklist||[]).join(" ")}`.toLowerCase(); addText(card,"div",`Rank ${item.rank} | ${item.category} | ${item.estimated_minutes} min`,"eyebrow"); addText(card,"h3",item.name); addText(card,"p",item.summary); const list=document.createElement("ul"); (item.checklist||[]).forEach(step=>addText(list,"li",step)); card.append(list); root.append(card); });
      filterTools();
    }
    function filterTools() { const query=($("toolSearch")?.value||"").trim().toLowerCase(); document.querySelectorAll("#tools .tool").forEach(card=>card.classList.toggle("hidden",Boolean(query)&&!card.dataset.search.includes(query))); }
    function renderSuccessPlan(data) {
      const root=$("successPlan"); root.replaceChildren(); [["Today","today"],["This week","this_week"],["This month","this_month"]].forEach(([label,key])=>{ const items=data.success_plan[key]||[]; const card=document.createElement("article"); card.className="tool"; addText(card,"div",`${items.length} action(s)`,"eyebrow"); addText(card,"h3",label); const list=document.createElement("ul"); if(items.length)items.forEach(item=>addText(list,"li",item.title));else addText(list,"li","No actions in this phase."); card.append(list); root.append(card); });
    }
    function renderBenefits(data) {
      const root=$("benefits"); root.replaceChildren(); const map=data.benefit_map; const current=document.createElement("article"); current.className="tool"; addText(current,"div",`${map.unlocked_count} included benefit(s)`,"eyebrow"); addText(current,"h3",`Rank ${map.current_rank.rank} - ${map.current_rank.name}`); const currentList=document.createElement("ul"); (map.unlocked||[]).forEach(item=>addText(currentList,"li",item.title)); current.append(currentList); root.append(current); const next=map.next_rank; const future=document.createElement("article"); future.className="tool"; if(next){addText(future,"div",`${next.added_benefits.length} added benefit(s)`,"eyebrow");addText(future,"h3",`Next: Rank ${next.plan.rank} - ${next.plan.name}`);const list=document.createElement("ul");next.added_benefits.forEach(item=>addText(list,"li",item.title));future.append(list);}else{addText(future,"div","Highest rank","eyebrow");addText(future,"h3","All rank benefits reached");addText(future,"p","No higher VaultLink rank is currently listed.");} root.append(future);
    }
    function renderTimeline(data) {
      const root=$("timeline"); root.replaceChildren(); (data.timeline.items||[]).forEach((item)=>{ const card=document.createElement("article"); card.className="event"; addText(card,"div",item.state,"eyebrow"); addText(card,"h3",item.title); addText(card,"p",item.at_utc); addText(card,"p",item.detail); root.append(card); });
    }
    function renderUpgrades(data) {
      const root=$("upgrades"); root.replaceChildren(); const items=data.upgrade_options.items || [];
      if(!items.length){ root.innerHTML='<div class="empty">This license already has the highest rank.</div>'; return; }
      items.forEach((item)=>{ const card=document.createElement("article"); card.className="rank"; addText(card,"div",`Rank ${item.plan.rank} | ${item.plan.price_label}`,"eyebrow"); addText(card,"h3",item.plan.name); addText(card,"p",`${item.added_entitlement_count} added entitlement(s), ${item.ranks_up} rank step(s) up.`); root.append(card); });
    }
    function renderLinks(data) {
      const root=$("quickLinks"); root.replaceChildren(); (data.quick_links||[]).forEach((item)=>{ const link=document.createElement("a"); link.className="link-button"; link.href=item.path; link.textContent=item.label; root.append(link); });
    }
    function render(data) { state.payload=data; state.completed=new Set(); state.actionFilter="all"; renderMetrics(data); renderScore(data); renderActions(data); renderSuccessPlan(data); renderBenefits(data); renderTools(data); renderTimeline(data); renderUpgrades(data); renderLinks(data); $("workspace").hidden=false; }
    async function loadWorkspace() {
      const licenseKey=$("licenseKey").value.trim(); if(!licenseKey){ setStatus("Enter a license key.","bad"); return; }
      $("load").disabled=true; setStatus("Building your privacy-safe workspace...");
      try { const response=await fetch("/api/v1/licenses/customer-workspace",{method:"POST",headers:{"Content-Type":"application/json","Accept":"application/json"},body:JSON.stringify({license_key:licenseKey,app_version:$("appVersion").value.trim()}),cache:"no-store",redirect:"error"}); const data=await response.json(); if(!response.ok) throw new Error(data.message||"Workspace could not be loaded."); render(data); setStatus(data.message,data.summary.status==="active"?"good":"warn"); }
      catch(error){ state.payload=null; $("workspace").hidden=true; setStatus(error.message||"Workspace could not be loaded.","bad"); }
      finally { $("load").disabled=false; }
    }
    async function copySummary() { const data=safeExport(); if(!data)return; const lines=["VaultLink Customer Workspace",`Workspace score: ${data.workspace_score.score} of 100`, `Status: ${data.summary.status}`,`Rank: ${data.summary.plan.rank} - ${data.summary.plan.name}`,`Seats: ${data.summary.device_usage.active} of ${data.summary.device_usage.maximum}`,`Service: ${data.summary.service_status.mode}`,`Latest desktop: ${data.summary.release.latest_version||"Not published"}`,`Actions needing attention: ${data.checkup.attention_count}`]; try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Privacy-safe summary copied.","good");}catch(_){setStatus("Browser clipboard access was blocked.","bad");} }
    function downloadJson(name,data,message) { const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"}); const url=URL.createObjectURL(blob); const link=document.createElement("a"); link.href=url; link.download=name; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000); setStatus(message,"good"); }
    function exportJson() { const data=safeExport(); if(data)downloadJson("vaultlink-customer-workspace.json",data,"Privacy-safe workspace exported."); }
    function exportSupport() { if(state.payload)downloadJson("vaultlink-support-pack.json",state.payload.support_pack,"Privacy-safe support pack exported."); }
    function exportRecovery() { if(state.payload)downloadJson("vaultlink-offline-recovery-card.json",state.payload.recovery_card,"Offline recovery card exported."); }
    function clearAll() { state.payload=null; state.completed=new Set(); $("licenseKey").value=""; $("appVersion").value=""; $("workspace").hidden=true; setStatus("License key and workspace cleared from page memory."); }
    $("load").addEventListener("click",loadWorkspace); $("clear").addEventListener("click",clearAll); $("copy").addEventListener("click",copySummary); $("export").addEventListener("click",exportJson); $("exportSupport").addEventListener("click",exportSupport); $("exportRecovery").addEventListener("click",exportRecovery); $("resetProgress").addEventListener("click",()=>{state.completed=new Set(); if(state.payload)renderActions(state.payload);}); $("actionFilters").addEventListener("click",event=>{const filter=event.target.dataset.filter;if(filter)filterActions(filter);}); $("toolSearch").addEventListener("input",filterTools); $("clearToolSearch").addEventListener("click",()=>{$("toolSearch").value="";filterTools();}); $("licenseKey").addEventListener("keydown",event=>{if(event.key==="Enter")loadWorkspace();});
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))


def owner_customer_experience_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Customer Experience Console</title>
  <style>
    :root { --bg:#0d1014; --band:#151a20; --panel:#1c222a; --field:#090c10; --line:#36414d; --text:#f4f7f8; --muted:#a9b4bf; --green:#66df89; --blue:#67bde8; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#11161b; }
    header > div, main, footer > div { width:min(1180px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:72px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    header a { color:var(--blue); text-decoration:none; font-weight:800; }
    main { padding:28px 0 50px; }
    h1 { margin:0; font-size:30px; } h2 { margin:0; font-size:18px; } h3 { margin:0; font-size:14px; }
    .lead,.status,.detail { color:var(--muted); }
    .auth { display:grid; grid-template-columns:minmax(260px,1fr) auto auto; gap:10px; align-items:end; margin-top:18px; padding:18px; border:1px solid var(--line); background:var(--band); }
    label { display:block; margin-bottom:6px; color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; }
    input { width:100%; height:43px; padding:0 11px; border:1px solid var(--line); border-radius:5px; background:var(--field); color:var(--text); font:inherit; }
    button { min-height:43px; padding:0 14px; border:0; border-radius:5px; background:#29323c; color:var(--text); font-weight:800; cursor:pointer; }
    .primary { background:var(--blue); color:#071118; }
    .status { min-height:22px; margin-top:10px; } .status.good{color:var(--green)} .status.bad{color:var(--red)}
    #console[hidden] { display:none; }
    .toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
    .metrics { display:grid; grid-template-columns:repeat(8,minmax(120px,1fr)); margin-top:16px; border:1px solid var(--line); }
    .metric { min-width:0; padding:15px; border-right:1px solid var(--line); background:var(--band); }
    .metric:last-child { border-right:0; } .metric span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; } .metric strong { display:block; margin-top:5px; font-size:18px; overflow-wrap:anywhere; }
    .section { margin-top:22px; padding-top:20px; border-top:1px solid var(--line); }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:12px; margin-bottom:12px; }
    .section-head p { margin:0; color:var(--muted); text-align:right; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:10px; }
    .item { padding:15px; border:1px solid var(--line); border-radius:6px; background:var(--panel); }
    .item p { margin:4px 0 0; color:var(--muted); }
    .tone { color:var(--blue); font-size:10px; font-weight:800; text-transform:uppercase; }
    .tone.action { color:var(--red); } .tone.check { color:var(--yellow); } .tone.good { color:var(--green); }
    footer { border-top:1px solid var(--line); background:#11161b; } footer > div { padding:22px 0 28px; color:var(--muted); }
    @media(max-width:980px){.metrics{grid-template-columns:repeat(3,1fr)}}
    @media(max-width:700px){header > div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.auth{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}
    @media(max-width:450px){.metrics{grid-template-columns:1fr}.metric{border-right:0;border-bottom:1px solid var(--line)}}
  </style>
</head>
<body>
  <header><div><strong>VaultLink Customer Experience</strong><a href="/owner">BACK TO OWNER CONSOLE</a></div></header>
  <main>
    <h1>Customer Experience Console</h1>
    <p class="lead">Aggregate customer readiness, service, release adoption, rank coverage, support workload, and public-surface health without customer identities or secrets.</p>
    <section class="auth"><div><label for="token">Owner admin token</label><input id="token" type="password" autocomplete="off" spellcheck="false"></div><button id="connect" class="primary">LOAD CONSOLE</button><button id="clear">CLEAR</button></section>
    <div id="status" class="status">Disconnected. The token stays only in this page memory.</div>
    <div id="console" hidden>
      <div class="toolbar"><button id="refresh">REFRESH</button><button id="export">EXPORT SAFE JSON</button><button id="csv">EXPORT RANK CSV</button><button id="journeyCsv">EXPORT JOURNEY CSV</button></div>
      <div id="metrics" class="metrics"></div>
      <section class="section"><div class="section-head"><h2>Owner Action Queue</h2><p>Read-only guidance. This console cannot control customer PCs.</p></div><div id="actions" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Customer Journey</h2><p>Aggregate progress from issued licenses through current signed releases.</p></div><div id="journey" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Renewal Health</h2><p>Coarse expiration buckets without customer identity or individual license details.</p></div><div id="renewals" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Rank Coverage</h2><p>Aggregate license counts across all seven customer ranks.</p></div><div id="ranks" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Customer Surfaces</h2><p>Every public customer destination included in this release.</p></div><div id="surfaces" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Release And Privacy</h2><p id="privacy"></p></div><div id="release" class="grid"></div></section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. Aggregate console responses exclude license keys, customer labels, email, owner notes, device identities, receipts, file data, paths, PINs, and USB secrets.</div></footer>
  <script>
    const $=id=>document.getElementById(id); const state={token:"",payload:null}; const text=value=>String(value??"");
    function setStatus(message,tone=""){ $("status").textContent=message; $("status").className=`status ${tone}`; }
    function add(parent,tag,value,className=""){const node=document.createElement(tag);node.textContent=text(value);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,value){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",value);return node;}
    function cards(rootId,items,render){const root=$(rootId);root.replaceChildren();items.forEach(item=>root.append(render(item)));}
    function card(title,detail,tone="info",eyebrow=""){const node=document.createElement("article");node.className="item";add(node,"div",eyebrow||tone,`tone ${tone}`);add(node,"h3",title);add(node,"p",detail);return node;}
    function render(data){
      state.payload=data;
      const metrics=$("metrics"); metrics.replaceChildren();
      [["Experience score",`${data.experience_score.score} / 100`],["Active licenses",data.metrics.active_licenses],["Licenses with devices",data.metrics.activated_licenses],["Active devices",data.metrics.active_devices],["Release adoption",`${data.metrics.release_adoption_percent}%`],["Support needs action",data.metrics.support_needs_action],["Expiring in 30 days",data.metrics.expiring_30_days],["Customer surfaces",`${data.surface_summary.ready} / ${data.surface_summary.total}`]].forEach(row=>metrics.append(metric(...row)));
      cards("actions",data.actions,item=>card(item.title,item.detail,item.state,item.category));
      cards("journey",data.customer_journey,item=>card(item.label,`${item.count} of ${item.maximum} | ${item.percent}%`,item.percent>=90?"good":item.percent>=60?"check":"action","aggregate stage"));
      const renewal=data.renewal_health;
      cards("renewals",[["Expiring in 7 days",renewal.expiring_7_days],["Expiring in 30 days",renewal.expiring_30_days],["No expiration",renewal.no_expiration],["Already expired",renewal.expired]].map(([title,count])=>({title,count})),item=>card(item.title,`${item.count} license(s)`,item.title==="Already expired"&&item.count?"action":item.count?"check":"good","renewal bucket"));
      cards("ranks",data.rank_coverage,item=>card(`Rank ${item.rank} - ${item.name}`,`${item.licenses} license(s) | ${item.percent_of_licenses}% of licenses | ${item.entitlement_count} cumulative entitlement(s)`,item.licenses?"good":"info",item.price_label));
      cards("surfaces",data.customer_surfaces,item=>card(item.label,`${item.path} | ${item.purpose}`,item.ready?"good":"check",item.ready?"ready":"check"));
      const release=data.release; const releaseReady=Boolean(release.signed_release_ready); const storageReady=/^(\d+) of \1 persistent$/.test(data.storage_readiness);
      const releaseRows=[["Desktop release",release.desktop_version||"Not published",releaseReady?"good":"check"],["API version",release.api_version,"good"],["Signature",release.signature_check,release.signature_check==="passed"?"good":"action"],["Package hash",release.package_hash_check,release.package_hash_check==="passed"?"good":"action"],["Service",data.service_status.mode,data.service_status.mode==="normal"?"good":"check"],["Storage",data.storage_readiness,storageReady?"good":"action"]];
      cards("release",releaseRows.map(([title,detail,tone])=>({title,detail,tone})),item=>card(item.title,item.detail,item.tone));
      $("privacy").textContent=`${data.experience_score.score} of 100 | ${data.experience_score.label.toUpperCase()} | ${data.experience_score.limitations} ${data.privacy_notice}`;
      $("console").hidden=false; setStatus("Customer experience console refreshed.","good");
    }
    async function load(){if(!state.token){setStatus("Enter the owner admin token.","bad");return;}$("connect").disabled=true;try{const response=await fetch("/api/v1/admin/customer-experience",{headers:{"X-License-Admin-Token":state.token,"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Console failed to load.");render(data);}catch(error){state.payload=null;$("console").hidden=true;setStatus(error.message||"Console failed to load.","bad");}finally{$("connect").disabled=false;}}
    function connect(){state.token=$("token").value.trim();load();}
    function clear(){state.token="";state.payload=null;$("token").value="";$("console").hidden=true;setStatus("Owner token cleared from page memory.");}
    function download(name,body,type){const blob=new Blob([body],{type});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
    function exportJson(){if(!state.payload)return;download("vaultlink-customer-experience.json",JSON.stringify(state.payload,null,2),"application/json");setStatus("Privacy-safe aggregate report exported.","good");}
    function exportCsv(){if(!state.payload)return;const rows=[["rank","name","price","licenses","entitlement_count"],...state.payload.rank_coverage.map(item=>[item.rank,item.name,item.price_label,item.licenses,item.entitlement_count])];const csv=rows.map(row=>row.map(value=>`"${text(value).replaceAll('"','""')}"`).join(",")).join("\r\n");download("vaultlink-rank-coverage.csv",csv,"text/csv");setStatus("Aggregate rank coverage exported.","good");}
    function exportJourneyCsv(){if(!state.payload)return;const rows=[["stage","count","maximum","percent"],...state.payload.customer_journey.map(item=>[item.label,item.count,item.maximum,item.percent])];const csv=rows.map(row=>row.map(value=>`"${text(value).replaceAll('"','""')}"`).join(",")).join("\r\n");download("vaultlink-customer-journey.csv",csv,"text/csv");setStatus("Aggregate customer journey exported.","good");}
    $("connect").addEventListener("click",connect);$("clear").addEventListener("click",clear);$("refresh").addEventListener("click",load);$("export").addEventListener("click",exportJson);$("csv").addEventListener("click",exportCsv);$("journeyCsv").addEventListener("click",exportJourneyCsv);$("token").addEventListener("keydown",event=>{if(event.key==="Enter")connect();});
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))
