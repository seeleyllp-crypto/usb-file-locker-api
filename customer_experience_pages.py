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
  <header><div><div class="brand">VaultLink Customer Workspace</div><nav><a href="/customer">LICENSE</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a><a href="/shop">SHOP</a></nav></div></header>
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
  <header><div><strong>VaultLink Customer Experience</strong><div><a href="/owner/trust">TRUST OPERATIONS</a> &nbsp; <a href="/owner">BACK TO OWNER CONSOLE</a></div></div></header>
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


def customer_trust_center_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Trust Center</title>
  <style>
    :root { --bg:#0d1014; --band:#151a20; --panel:#1b2229; --line:#37434e; --text:#f4f7f8; --muted:#aab5bf; --green:#66df89; --blue:#68bee9; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header,footer { background:#11161b; border-color:var(--line); border-style:solid; border-width:0 0 1px; }
    header > div,main,footer > div { width:min(1160px,calc(100% - 32px)); margin:auto; }
    header > div { min-height:70px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-size:18px; font-weight:800; }
    nav { display:flex; flex-wrap:wrap; gap:7px; }
    nav a { min-height:36px; display:inline-flex; align-items:center; padding:0 10px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:750; }
    main { padding:28px 0 50px; }
    h1 { margin:0; font-size:30px; } h2 { margin:0; font-size:18px; } h3 { margin:0; font-size:15px; }
    .lead,.status,.muted,.item p { color:var(--muted); }
    .lead { max-width:790px; margin:7px 0 0; font-size:15px; }
    .toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-top:18px; }
    button { min-height:42px; padding:0 14px; border:0; border-radius:5px; background:#29333d; color:var(--text); font-weight:800; cursor:pointer; }
    button.primary { background:var(--blue); color:#061119; }
    .status { min-height:22px; margin-top:10px; } .status.good{color:var(--green)} .status.bad{color:var(--red)}
    #content[hidden] { display:none; }
    .score-band { display:grid; grid-template-columns:180px minmax(0,1fr); gap:18px; align-items:center; margin-top:15px; padding:18px; border:1px solid var(--line); background:var(--band); }
    .score { min-height:110px; display:flex; flex-direction:column; justify-content:center; border-left:5px solid var(--blue); padding-left:16px; }
    .score strong { font-size:34px; line-height:1; } .score span { color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; }
    .metrics { display:grid; grid-template-columns:repeat(5,minmax(120px,1fr)); border:1px solid var(--line); }
    .metric { min-width:0; padding:13px; border-right:1px solid var(--line); }
    .metric:last-child { border-right:0; }
    .metric span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    .metric strong { display:block; margin-top:4px; overflow-wrap:anywhere; }
    .section { margin-top:24px; padding-top:19px; border-top:1px solid var(--line); }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:14px; margin-bottom:11px; }
    .section-head p { max-width:680px; margin:0; color:var(--muted); text-align:right; }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(245px,1fr)); gap:9px; }
    .item { min-width:0; padding:14px; border:1px solid var(--line); border-radius:6px; background:var(--panel); }
    .item p { margin:5px 0 0; }
    .eyebrow { color:var(--blue); font-size:10px; font-weight:800; text-transform:uppercase; }
    .eyebrow.good { color:var(--green); } .eyebrow.attention { color:var(--yellow); } .eyebrow.action { color:var(--red); }
    .boundary { border-left:4px solid var(--blue); }
    .boundary.never { border-left-color:var(--green); } .boundary.explicit { border-left-color:var(--yellow); }
    ul { margin:9px 0 0; padding-left:18px; color:var(--muted); } li { margin:5px 0; }
    footer { border-width:1px 0 0; } footer > div { padding:21px 0 27px; color:var(--muted); }
    @media(max-width:900px){.score-band{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.metric{border-bottom:1px solid var(--line)}}
    @media(max-width:650px){header > div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.metrics{grid-template-columns:1fr}.metric{border-right:0}}
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Trust Center</div><nav><a href="/workspace">WORKSPACE</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/update">UPDATE</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a><a href="/privacy">PRIVACY</a></nav></div></header>
  <main>
    <h1>Trust and recovery status</h1>
    <p class="lead">Live service, signed-release, storage, privacy-boundary, and recovery evidence. This public view contains no customer or license records.</p>
    <div class="toolbar"><button id="refresh" class="primary" type="button">REFRESH LIVE STATUS</button><button id="export" type="button" disabled>EXPORT SAFE JSON</button></div>
    <div id="status" class="status" role="status" aria-live="polite">Loading current trust status...</div>
    <div id="content" hidden>
      <section class="score-band"><div class="score"><span>Operational score</span><strong id="score">0 / 100</strong><span id="scoreLabel">LOADING</span></div><div id="metrics" class="metrics"></div></section>
      <section class="section"><div class="section-head"><h2>Live Checks</h2><p>Configuration and signed-release results. A passing result is useful evidence, not certification.</p></div><div id="checks" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Data Boundaries</h2><p>What stays local, what may be sent after an explicit action, and what the API never asks for.</p></div><div id="boundaries" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Cryptography And Release Evidence</h2><p id="releaseSummary"></p></div><div id="crypto" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Recovery Steps</h2><p>Use these before an emergency. They do not test the customer PC or guarantee recovery.</p></div><div id="recovery" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Limitations</h2><p>Plain-language boundaries for sharing this report.</p></div><div id="limitations" class="grid"></div></section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. This public page cannot inspect a PC, unlock files, receive USB secrets, capture PINs, or prove legal compliance.</div></footer>
  <script>
    const $=id=>document.getElementById(id); const state={payload:null}; const value=input=>String(input??"");
    function setStatus(message,tone=""){ $("status").textContent=message; $("status").className=`status ${tone}`; }
    function add(parent,tag,text,className=""){const node=document.createElement(tag);node.textContent=value(text);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,text){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",text);return node;}
    function item(title,detail,tone="",eyebrow=""){const node=document.createElement("article");node.className="item";add(node,"div",eyebrow||tone||"INFO",`eyebrow ${tone}`);add(node,"h3",title);add(node,"p",detail);return node;}
    function listCard(title,values,className=""){const node=document.createElement("article");node.className=`item boundary ${className}`;add(node,"h3",title);const list=document.createElement("ul");(values||[]).forEach(row=>add(list,"li",row));node.append(list);return node;}
    function render(data){
      state.payload=data; const score=data.score; $("score").textContent=`${score.value} / ${score.maximum}`; $("scoreLabel").textContent=`${score.label.toUpperCase()} | ${score.attention_count} attention`;
      const metrics=$("metrics");metrics.replaceChildren();[["API",data.api_version],["Service",data.service_status.mode],["Desktop",data.signed_release.version||"Not published"],["Signature",data.signed_release.checks.ed25519_signature||"failed"],["Storage",data.storage.license_state]].forEach(row=>metrics.append(metric(...row)));
      const checks=$("checks");checks.replaceChildren();(data.checks||[]).forEach(check=>checks.append(item(check.title,`${check.detail}${check.passed||!check.action?"":` Next: ${check.action}`}`,check.state,`${check.category} | ${check.weight} points`)));
      const boundaries=$("boundaries");boundaries.replaceChildren(listCard("Stays On The Customer PC",data.data_boundaries.stays_on_customer_pc),listCard("Sent Only After Explicit Action",data.data_boundaries.may_reach_api_after_explicit_action,"explicit"),listCard("Never Requested By The API",data.data_boundaries.never_requested_by_api,"never"));
      const release=data.signed_release; $("releaseSummary").textContent=release.ready?`Release ${release.version} | signing key ${release.signing_key_id} | ${release.size_bytes} bytes | SHA-256 ${release.sha256}`:"No verified release is currently available.";
      const crypto=$("crypto");crypto.replaceChildren();(data.cryptography||[]).forEach(row=>crypto.append(item(row.purpose,row.control,"good","ACTIVE CONTROL")));
      const recovery=$("recovery");recovery.replaceChildren();(data.recovery_steps||[]).forEach((step,index)=>recovery.append(item(`Step ${index+1}`,step,"","RECOVERY")));
      const limitations=$("limitations");limitations.replaceChildren();(data.limitations||[]).forEach((text,index)=>limitations.append(item(`Boundary ${index+1}`,text,"attention","LIMITATION")));
      $("content").hidden=false; $("export").disabled=false; setStatus(`Trust status refreshed at ${data.server_time_utc}.`,score.label==="action"?"bad":"good");
    }
    async function load(){ $("refresh").disabled=true; setStatus("Loading current trust status..."); try{const response=await fetch("/api/v1/trust-center",{headers:{"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Trust status could not be loaded.");render(data);}catch(error){state.payload=null;$("content").hidden=true;$("export").disabled=true;setStatus(error.message||"Trust status could not be loaded.","bad");}finally{$("refresh").disabled=false;}}
    function exportJson(){if(!state.payload)return;const blob=new Blob([JSON.stringify(state.payload,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="vaultlink-public-trust-report.json";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus("Privacy-safe trust report exported.","good");}
    $("refresh").addEventListener("click",load);$("export").addEventListener("click",exportJson);load();
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))


def customer_diagnostics_center_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Diagnostics Center</title>
  <style>
    :root { --bg:#0d1014; --band:#151a20; --panel:#1b2229; --field:#090c10; --line:#37434e; --text:#f4f7f8; --muted:#aab5bf; --green:#66df89; --blue:#68bee9; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header,footer { background:#11161b; border-color:var(--line); border-style:solid; border-width:0 0 1px; }
    header > div,main,footer > div { width:min(1180px,calc(100% - 32px)); margin:auto; }
    header > div { min-height:70px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-size:18px; font-weight:800; } nav { display:flex; flex-wrap:wrap; gap:7px; }
    nav a { min-height:36px; display:inline-flex; align-items:center; padding:0 10px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:750; }
    main { padding:28px 0 50px; } h1{margin:0;font-size:30px} h2{margin:0;font-size:19px} h3{margin:0;font-size:15px}.lead,.status,.muted,.step p,.boundary p{color:var(--muted)}.lead{max-width:850px;margin:7px 0 0;font-size:15px}
    .controls { display:grid; grid-template-columns:minmax(250px,1fr) auto auto auto; gap:9px; align-items:end; margin-top:18px; padding:17px; border:1px solid var(--line); background:var(--band); }
    label{display:block;margin-bottom:6px;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}select{width:100%;height:42px;padding:0 11px;border:1px solid var(--line);border-radius:5px;background:var(--field);color:var(--text);font:inherit}
    button{min-height:42px;padding:0 14px;border:0;border-radius:5px;background:#29333d;color:var(--text);font-weight:800;cursor:pointer}button.primary{background:var(--blue);color:#061119}button:disabled{opacity:.5;cursor:not-allowed}.status{min-height:22px;margin-top:9px}.status.good{color:var(--green)}.status.bad{color:var(--red)}#workspace[hidden]{display:none}
    .metrics{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));margin-top:13px;border:1px solid var(--line);background:var(--band)}.metric{min-width:0;padding:13px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span{display:block;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}.metric strong{display:block;margin-top:4px;font-size:17px;overflow-wrap:anywhere}
    .section{margin-top:24px;padding-top:19px;border-top:1px solid var(--line)}.section-head{display:flex;align-items:end;justify-content:space-between;gap:14px;margin-bottom:11px}.section-head p{max-width:680px;margin:0;color:var(--muted);text-align:right}.steps{display:grid;gap:9px}.step{display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px;padding:14px;border:1px solid var(--line);border-radius:6px;background:var(--panel)}.step.done{border-color:var(--green)}.step input{width:20px;height:20px;margin:2px 0 0;accent-color:var(--green)}.step p{margin:5px 0 0}.expected{color:var(--blue)!important}.eyebrow{color:var(--yellow);font-size:10px;font-weight:800;text-transform:uppercase}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:9px}.boundary{padding:14px;border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:6px;background:var(--panel)}.boundary p{margin:5px 0 0}.boundary.limit{border-left-color:var(--yellow)}.notice{margin-top:13px;padding:13px;border-left:4px solid var(--yellow);background:var(--band);color:var(--muted)}footer{border-width:1px 0 0}footer>div{padding:21px 0 27px;color:var(--muted)}
    @media(max-width:900px){.controls{grid-template-columns:1fr 1fr}.metrics{grid-template-columns:repeat(2,1fr)}.metric{border-bottom:1px solid var(--line)}}@media(max-width:620px){header>div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.controls,.metrics{grid-template-columns:1fr}.metric{border-right:0}.step{grid-template-columns:28px minmax(0,1fr)}}
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Diagnostics Center</div><nav><a href="/workspace">WORKSPACE</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a></nav></div></header>
  <main>
    <h1>Guided troubleshooting</h1>
    <p class="lead">Choose the visible problem and work through fixed, privacy-safe steps. Progress stays only in this browser tab; this page cannot inspect or control the PC.</p>
    <section class="controls">
      <div><label for="category">Problem category</label><select id="category" disabled></select></div>
      <button id="reset" type="button" disabled>RESET CHECKLIST</button>
      <button id="copy" type="button" disabled>COPY SAFE SUMMARY</button>
      <button id="export" class="primary" type="button" disabled>EXPORT SAFE JSON</button>
    </section>
    <div id="status" class="status" role="status" aria-live="polite">Loading fixed diagnostics guide...</div>
    <div id="workspace" hidden>
      <div id="metrics" class="metrics"></div>
      <section class="section"><div class="section-head"><div><div id="categoryEyebrow" class="eyebrow">CATEGORY</div><h2 id="categoryTitle"></h2></div><p id="categorySummary"></p></div><div id="steps" class="steps"></div><div id="escalation" class="notice"></div></section>
      <section class="section"><div class="section-head"><h2>Privacy Boundaries</h2><p>No free-text field, license proof, file upload, or machine inspection is used.</p></div><div id="boundaries" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Limitations</h2><p>Use diagnostics as a starting point, never as proof or certification.</p></div><div id="limitations" class="grid"></div></section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. Checklist progress is held only in page memory and disappears when this tab closes or reloads.</div></footer>
  <script>
    const $=id=>document.getElementById(id);const state={payload:null,category:"",completed:new Set()};const value=input=>String(input??"");
    function setStatus(message,tone=""){ $("status").textContent=message; $("status").className=`status ${tone}`; }
    function add(parent,tag,text,className=""){const node=document.createElement(tag);node.textContent=value(text);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,text){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",text);return node;}
    function selectedCategory(){return (state.payload?.categories||[]).find(item=>item.id===state.category)||null;}
    function safeExport(){const category=selectedCategory();return {schema_version:1,report_type:"VaultLink Privacy-Safe Browser Diagnostics Progress",generated_at_utc:new Date().toISOString(),api_version:state.payload.api_version,service_mode:state.payload.service_status.mode,signed_desktop_version:state.payload.signed_release.version||"",category_id:category?.id||"",category_title:category?.title||"",completed_step_ids:(category?.steps||[]).map(step=>step.id).filter(id=>state.completed.has(id)),total_steps:(category?.steps||[]).length,privacy_notice:"No license key, receipt, customer identity, machine identity, PIN, USB secret, path, filename, file content, or free-form support text is included."};}
    function renderMetrics(){const category=selectedCategory();const steps=category?.steps||[];const done=steps.filter(step=>state.completed.has(step.id)).length;const root=$("metrics");root.replaceChildren();[["API",state.payload.api_version],["Service",state.payload.service_status.mode],["Signed desktop",state.payload.signed_release.version||"Not published"],["Categories",state.payload.category_count],["Current progress",`${done} / ${steps.length}`]].forEach(row=>root.append(metric(...row)));}
    function renderCategory(){const category=selectedCategory();if(!category)return;$("categoryTitle").textContent=category.title;$("categorySummary").textContent=category.summary;$("categoryEyebrow").textContent=category.id.replaceAll("-"," ");const root=$("steps");root.replaceChildren();category.steps.forEach((step,index)=>{const row=document.createElement("article");row.className=`step ${state.completed.has(step.id)?"done":""}`;const box=document.createElement("input");box.type="checkbox";box.checked=state.completed.has(step.id);box.setAttribute("aria-label",`Complete ${step.title}`);box.addEventListener("change",()=>{box.checked?state.completed.add(step.id):state.completed.delete(step.id);renderCategory();});const body=document.createElement("div");add(body,"div",`STEP ${index+1}`,"eyebrow");add(body,"h3",step.title);add(body,"p",step.action);add(body,"p",`Expected: ${step.expected}`,"expected");row.append(box,body);root.append(row);});$("escalation").textContent=`ESCALATION: ${category.escalation}`;renderMetrics();setStatus(`${category.title}: ${category.steps.filter(step=>state.completed.has(step.id)).length} of ${category.steps.length} steps complete.`,"good");}
    function render(data){state.payload=data;state.category=data.categories[0]?.id||"";state.completed.clear();const select=$("category");select.replaceChildren();data.categories.forEach(category=>{const option=document.createElement("option");option.value=category.id;option.textContent=category.title;select.append(option);});select.value=state.category;select.disabled=false;$("reset").disabled=false;$("copy").disabled=false;$("export").disabled=false;const boundaries=$("boundaries");boundaries.replaceChildren();data.privacy_boundaries.forEach((text,index)=>{const item=document.createElement("article");item.className="boundary";add(item,"div",`BOUNDARY ${index+1}`,"eyebrow");add(item,"p",text);boundaries.append(item);});const limits=$("limitations");limits.replaceChildren();data.limitations.forEach((text,index)=>{const item=document.createElement("article");item.className="boundary limit";add(item,"div",`LIMITATION ${index+1}`,"eyebrow");add(item,"p",text);limits.append(item);});$("workspace").hidden=false;renderCategory();}
    async function load(){try{const response=await fetch("/api/v1/diagnostics-guide",{headers:{"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Diagnostics guide could not be loaded.");render(data);}catch(error){setStatus(error.message||"Diagnostics guide could not be loaded.","bad");}}
    function reset(){const category=selectedCategory();(category?.steps||[]).forEach(step=>state.completed.delete(step.id));renderCategory();}
    async function copy(){const report=safeExport();const lines=[`VaultLink diagnostics: ${report.category_title}`,`Progress: ${report.completed_step_ids.length}/${report.total_steps}`,`API: ${report.api_version} | Service: ${report.service_mode} | Signed desktop: ${report.signed_desktop_version||"not published"}`,report.privacy_notice];try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Privacy-safe diagnostic summary copied.","good");}catch(_error){setStatus("Clipboard access was blocked by the browser.","bad");}}
    function exportJson(){const report=safeExport();const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="vaultlink-browser-diagnostics-progress.json";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus("Privacy-safe browser diagnostic progress exported.","good");}
    $("category").addEventListener("change",event=>{state.category=event.target.value;renderCategory();});$("reset").addEventListener("click",reset);$("copy").addEventListener("click",copy);$("export").addEventListener("click",exportJson);load();
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))


def owner_trust_center_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Trust Operations</title>
  <style>
    :root { --bg:#0d1014; --band:#151a20; --panel:#1b2229; --field:#090c10; --line:#37434e; --text:#f4f7f8; --muted:#aab5bf; --green:#66df89; --blue:#68bee9; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header,footer { background:#11161b; border-color:var(--line); border-style:solid; border-width:0 0 1px; }
    header > div,main,footer > div { width:min(1180px,calc(100% - 32px)); margin:auto; }
    header > div { min-height:70px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-size:18px; font-weight:800; } nav { display:flex; flex-wrap:wrap; gap:7px; }
    nav a { min-height:36px; display:inline-flex; align-items:center; padding:0 10px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:750; }
    main { padding:28px 0 50px; } h1{margin:0;font-size:30px} h2{margin:0;font-size:18px} h3{margin:0;font-size:15px}.lead,.status,.item p{color:var(--muted)}.lead{max-width:820px;margin:7px 0 0}
    .auth { display:grid; grid-template-columns:minmax(260px,1fr) auto auto; gap:9px; align-items:end; margin-top:18px; padding:17px; border:1px solid var(--line); background:var(--band); }
    label{display:block;margin-bottom:6px;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}input{width:100%;height:42px;padding:0 11px;border:1px solid var(--line);border-radius:5px;background:var(--field);color:var(--text);font:inherit}
    button{min-height:42px;padding:0 14px;border:0;border-radius:5px;background:#29333d;color:var(--text);font-weight:800;cursor:pointer}.primary{background:var(--blue);color:#061119}.status{min-height:22px;margin-top:9px}.status.good{color:var(--green)}.status.bad{color:var(--red)}#console[hidden]{display:none}
    .toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-top:15px}.metrics{display:grid;grid-template-columns:repeat(7,minmax(115px,1fr));margin-top:13px;border:1px solid var(--line);background:var(--band)}.metric{min-width:0;padding:13px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span{display:block;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}.metric strong{display:block;margin-top:4px;font-size:17px;overflow-wrap:anywhere}
    .section{margin-top:24px;padding-top:19px;border-top:1px solid var(--line)}.section-head{display:flex;align-items:end;justify-content:space-between;gap:14px;margin-bottom:11px}.section-head p{max-width:680px;margin:0;color:var(--muted);text-align:right}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:9px}.item{min-width:0;padding:14px;border:1px solid var(--line);border-radius:6px;background:var(--panel)}.item p{margin:5px 0 0}.eyebrow{color:var(--blue);font-size:10px;font-weight:800;text-transform:uppercase}.eyebrow.good{color:var(--green)}.eyebrow.action{color:var(--red)}.eyebrow.attention{color:var(--yellow)}footer{border-width:1px 0 0}footer>div{padding:21px 0 27px;color:var(--muted)}
    @media(max-width:1050px){.metrics{grid-template-columns:repeat(3,1fr)}}@media(max-width:700px){header>div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.auth{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}}@media(max-width:450px){.metrics{grid-template-columns:1fr}.metric{border-right:0;border-bottom:1px solid var(--line)}}
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Trust Operations</div><nav><a href="/owner">OWNER CONSOLE</a><a href="/owner/customers">CUSTOMERS</a><a href="/owner/insights">INSIGHTS</a><a href="/trust">PUBLIC TRUST</a></nav></div></header>
  <main>
    <h1>Owner trust gate</h1>
    <p class="lead">A scored operational review of owner authentication, secrets, persistent storage, release integrity, service status, audit integrity, support workload, and signed-release adoption.</p>
    <section class="auth"><div><label for="token">Owner admin token</label><input id="token" type="password" autocomplete="off" spellcheck="false"></div><button id="connect" class="primary" type="button">LOAD TRUST GATE</button><button id="clear" type="button">CLEAR</button></section>
    <div id="status" class="status" role="status" aria-live="polite">Disconnected. The token stays only in page memory and is sent only in a request header.</div>
    <div id="console" hidden>
      <div class="toolbar"><button id="refresh" type="button">REFRESH</button><button id="export" type="button">EXPORT SAFE JSON</button></div>
      <div id="metrics" class="metrics"></div>
      <section class="section"><div class="section-head"><h2>Required Owner Actions</h2><p>Only failed gates appear here. No action can control or disable a customer PC.</p></div><div id="actions" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Trust Checks</h2><p>Each result is aggregate and excludes customer records and license proof.</p></div><div id="checks" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Category Coverage</h2><p>Earned and available points by operational area.</p></div><div id="categories" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Release And Storage</h2><p id="releaseSummary"></p></div><div id="release" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Limitations</h2><p>Use this as an owner checklist, never as a certification claim.</p></div><div id="limitations" class="grid"></div></section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. This owner console excludes license keys, customer identity, notes, machine hashes, receipts, reports, files, paths, PINs, and USB secrets.</div></footer>
  <script>
    const $=id=>document.getElementById(id);const state={token:"",payload:null};const value=input=>String(input??"");
    function setStatus(message,tone=""){ $("status").textContent=message; $("status").className=`status ${tone}`; }
    function add(parent,tag,text,className=""){const node=document.createElement(tag);node.textContent=value(text);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,text){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",text);return node;}
    function item(title,detail,tone="",eyebrow=""){const node=document.createElement("article");node.className="item";add(node,"div",eyebrow||tone||"INFO",`eyebrow ${tone}`);add(node,"h3",title);add(node,"p",detail);return node;}
    function fill(rootId,items,renderer){const root=$(rootId);root.replaceChildren();if(!items.length){root.append(item("No action required","Every gate in this section currently passes.","good","CLEAR"));return;}items.forEach(row=>root.append(renderer(row)));}
    function render(data){state.payload=data;const score=data.score;const metrics=$("metrics");metrics.replaceChildren();[["Trust score",`${score.value} / ${score.maximum}`],["Checks",`${score.passed} / ${score.total}`],["Required actions",data.actions.length],["Release adoption",`${data.metrics.release_adoption_percent}%`],["Support queue",data.metrics.support_needs_action],["High/Critical reports",data.metrics.high_critical_audits],["Persistent stores",`${data.metrics.persistent_stores} / ${data.metrics.total_stores}`]].forEach(row=>metrics.append(metric(...row)));
      fill("actions",data.actions,row=>item(row.title,row.action,"action",row.category));fill("checks",data.checks,row=>item(row.title,`${row.detail}${row.passed?"":` Next: ${row.action}`}`,row.state,`${row.category} | ${row.weight} points`));fill("categories",data.category_summary,row=>item(row.category,`${row.passed} of ${row.total} checks | ${row.earned} of ${row.weight} points`,row.passed===row.total?"good":"attention","CATEGORY"));
      const release=data.release;$("releaseSummary").textContent=release.ready?`Signed desktop ${release.version} | key ${release.signing_key_id} | SHA-256 ${release.sha256}`:"No verified desktop release is ready.";const releaseRows=[["Service",data.service_status.mode,data.service_status.mode==="normal"?"good":"action"],["Manifest",release.checks.ed25519_signature||"failed",release.checks.ed25519_signature==="passed"?"good":"action"],["Package hash",release.checks.package_sha256||"failed",release.checks.package_sha256==="passed"?"good":"action"],...["licenses","audit_exports","support_tickets","announcements","api_activity"].map(key=>[key.replaceAll("_"," "),data.storage[key],data.storage[key]==="persistent_configured"?"good":"action"] )];fill("release",releaseRows,row=>item(row[0],row[1],row[2],"LIVE RESULT"));fill("limitations",data.limitations.map((text,index)=>({text,index})),row=>item(`Boundary ${row.index+1}`,row.text,"attention","LIMITATION"));$("console").hidden=false;setStatus(`Trust gate refreshed at ${data.server_time_utc}.`,score.label==="action"?"bad":"good");}
    async function load(){if(!state.token){setStatus("Enter the owner admin token.","bad");return;}$("connect").disabled=true;try{const response=await fetch("/api/v1/admin/trust-center",{headers:{"X-License-Admin-Token":state.token,"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Trust gate could not be loaded.");render(data);}catch(error){state.payload=null;$("console").hidden=true;setStatus(error.message||"Trust gate could not be loaded.","bad");}finally{$("connect").disabled=false;}}
    function connect(){state.token=$("token").value.trim();load();}function clear(){state.token="";state.payload=null;$("token").value="";$("console").hidden=true;setStatus("Owner token cleared from page memory.");}
    function exportJson(){if(!state.payload)return;const blob=new Blob([JSON.stringify(state.payload,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="vaultlink-owner-trust-gate.json";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus("Privacy-safe owner trust report exported.","good");}
    $("connect").addEventListener("click",connect);$("clear").addEventListener("click",clear);$("refresh").addEventListener("click",load);$("export").addEventListener("click",exportJson);$("token").addEventListener("keydown",event=>{if(event.key==="Enter")connect();});
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))
