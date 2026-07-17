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
    .next-action { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:16px; align-items:center; padding:17px; border-left:4px solid var(--yellow); background:var(--panel); }
    .next-action p { margin:5px 0 0; color:var(--muted); }
    .next-action a { align-self:center; background:var(--yellow); color:#171100; }
    .lane { min-width:0; padding:15px; border:1px solid var(--line); border-top:4px solid var(--green); border-radius:6px; background:var(--panel); }
    .lane.review { border-top-color:var(--yellow); }
    .lane.action { border-top-color:var(--red); }
    .lane p { margin:5px 0 0; color:var(--muted); }
    .routine { display:grid; grid-template-columns:90px minmax(0,1fr) auto; gap:12px; align-items:center; padding:13px 14px; border-bottom:1px solid var(--line); background:var(--panel); }
    .routine:last-child { border-bottom:0; }
    .routine strong { color:var(--blue); }
    .routine p { margin:2px 0 0; color:var(--muted); }
    .routine a { min-height:34px; }
    .seat-summary { display:grid; grid-template-columns:repeat(4,minmax(110px,1fr)); border:1px solid var(--line); background:var(--band); }
    .seat-summary .metric { border-bottom:0; }
    .stage { min-width:0; padding:15px; border:1px solid var(--line); border-left:4px solid var(--blue); border-radius:6px; background:var(--panel); }
    .stage.ready { border-left-color:var(--green); } .stage.review { border-left-color:var(--yellow); } .stage.action { border-left-color:var(--red); }
    .stage p { margin:5px 0 0; color:var(--muted); }
    .phase { min-width:0; padding:15px; border:1px solid var(--line); border-radius:6px; background:var(--panel); }
    .phase ul { margin:10px 0 0; padding-left:18px; color:var(--muted); }
    .phase li { margin:5px 0; }
    footer { border-top:1px solid var(--line); background:#11161b; }
    footer > div { padding:22px 0 28px; color:var(--muted); }
    @media (max-width:1050px) { .metrics { grid-template-columns:repeat(4,1fr); } .metric { border-bottom:1px solid var(--line); } }
    @media (max-width:780px) { header > div,.section-head { align-items:flex-start; flex-direction:column; padding:14px 0; } .section-head p { text-align:left; } .signin { grid-template-columns:1fr 1fr; } .metrics { grid-template-columns:repeat(2,1fr); } }
    @media (max-width:780px) { .seat-summary { grid-template-columns:repeat(2,1fr); } }
    @media (max-width:520px) { .signin { grid-template-columns:1fr; } .metrics,.seat-summary { grid-template-columns:1fr; } .metric { border-right:0; } .action { grid-template-columns:auto minmax(0,1fr); } .action .when { grid-column:2; } .next-action,.routine { grid-template-columns:1fr; align-items:start; } }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Customer Workspace</div><nav><a href="/decision">WIZARD</a><a href="/QNA">ANSWERS</a><a href="/customer">LICENSE</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/recovery-drills">DRILLS</a><a href="/incident-response">INCIDENT</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a><a href="/shop">SHOP</a></nav></div></header>
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
        <div class="section-head"><h2>Next Best Action</h2><p>The first item after privacy-safe urgency sorting. Completion is never uploaded.</p></div>
        <div id="nextAction" class="next-action"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Customer Readiness Lanes</h2><p>Account, signed protection, service, and rank access at a glance.</p></div>
        <div id="readinessLanes" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Continuity Journey</h2><p>Five stages from account access through safe recovery. The server does not track completion.</p></div>
        <div id="journeyMap" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Anonymous Seat Planner</h2><p>Capacity only. Device names and identities are never returned.</p></div>
        <div id="seatPlanner" class="seat-summary"></div>
      </section>

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
        <div class="section-head"><h2>Seven-Day Care Routine</h2><p>A repeatable weekly checklist whose progress stays with the customer.</p></div>
        <div id="weeklyRoutine"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>90-Day Continuity Plan</h2><p>Now, first week, first month, and quarterly review phases.</p></div>
        <div id="ninetyDayPlan" class="grid"></div>
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

      <section class="band">
        <div class="section-head"><h2>Help Paths</h2><p>Start with the right fixed guide before creating a privacy-safe support request.</p></div>
        <div id="helpPaths" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Support Readiness</h2><p>Fixed preparation checks, never proof that a device or file is safe.</p></div>
        <div id="supportReadiness" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Current Change Digest</h2><p>Version, service, and license state without customer or machine identity.</p></div>
        <div id="changeDigest" class="seat-summary"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Plain-Language Glossary</h2><p>Ten common VaultLink terms customers can review before locking or recovering data.</p></div>
        <div id="customerGlossary" class="grid"></div>
      </section>

      <section class="band">
        <div class="section-head"><h2>Privacy Guarantees</h2><p>What this workspace deliberately cannot receive or do.</p></div>
        <div id="privacyGuarantees" class="grid"></div>
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
      return { exported_at_utc:new Date().toISOString(), workspace_schema_version:state.payload.workspace_schema_version, summary:state.payload.summary, customer_snapshot:state.payload.customer_snapshot, workspace_score:state.payload.workspace_score, checkup:state.payload.checkup, action_center:state.payload.action_center, next_best_action:state.payload.next_best_action, readiness_lanes:state.payload.readiness_lanes, journey_map:state.payload.journey_map, seat_planner:state.payload.seat_planner, success_plan:state.payload.success_plan, weekly_routine:state.payload.weekly_routine, ninety_day_plan:state.payload.ninety_day_plan, benefit_map:state.payload.benefit_map, entitlement_categories:state.payload.entitlement_categories, timeline:state.payload.timeline, rank_tools:state.payload.rank_tools, upgrade_options:state.payload.upgrade_options, help_center:state.payload.help_center, support_readiness:state.payload.support_readiness, change_digest:state.payload.change_digest, customer_glossary:state.payload.customer_glossary, privacy_guarantees:state.payload.privacy_guarantees, support_pack:state.payload.support_pack, recovery_card:state.payload.recovery_card, completed_action_ids:[...state.completed].sort(), privacy_notice:state.payload.privacy_notice };
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
    function renderNextAction(data) {
      const root=$("nextAction"); root.replaceChildren(); const item=data.next_best_action||{};
      const body=document.createElement("div"); addText(body,"div",`${value(item.when).toUpperCase()} | ${item.position||1} OF ${item.total_actions||0}`,"eyebrow"); addText(body,"h3",item.title||"Keep the workspace current"); addText(body,"p",item.detail||"Reload after an account or release change."); addText(body,"p",item.reason||"Progress remains local.");
      const link=document.createElement("a"); link.className="link-button"; link.href=item.target_path||"/workspace"; link.textContent="OPEN GUIDE"; root.append(body,link);
    }
    function renderReadiness(data) {
      const root=$("readinessLanes"); root.replaceChildren(); (data.readiness_lanes||[]).forEach((item)=>{ const card=document.createElement("article"); card.className=`lane ${item.state}`; addText(card,"div",`${item.awarded} OF ${item.maximum} | ${item.percent}%`,"eyebrow"); addText(card,"h3",item.title); addText(card,"p",item.purpose); addText(card,"p",`${item.attention_count} factor(s) need attention.`); root.append(card); });
    }
    function renderJourney(data) {
      const root=$("journeyMap"); root.replaceChildren(); ((data.journey_map||{}).stages||[]).forEach((item)=>{ const card=document.createElement("article"); card.className=`stage ${item.state}`; addText(card,"div",`STAGE ${item.order} | ${value(item.state).toUpperCase()}`,"eyebrow"); addText(card,"h3",item.title); addText(card,"p",item.detail); const link=document.createElement("a"); link.className="link-button"; link.href=item.target_path; link.textContent="OPEN"; card.append(link); root.append(card); });
    }
    function renderSeatPlanner(data) {
      const root=$("seatPlanner"); root.replaceChildren(); $("seatPlannerNote")?.remove(); const seat=data.seat_planner||{}; [["Active",seat.active||0],["Available",seat.available||0],["Maximum",seat.maximum||0],["Usage",`${seat.usage_percent||0}%`]].forEach(([label,item])=>root.append(metric(label,item))); const note=document.createElement("div"); note.id="seatPlannerNote"; note.className="privacy"; note.textContent=seat.guidance||"Seat information is unavailable."; root.after(note);
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
    function renderRoutine(data) {
      const root=$("weeklyRoutine"); root.replaceChildren(); ((data.weekly_routine||{}).items||[]).forEach((item)=>{ const row=document.createElement("div"); row.className="routine"; addText(row,"strong",item.day); const body=document.createElement("div"); addText(body,"h3",item.title); addText(body,"p",item.detail); const link=document.createElement("a"); link.className="link-button"; link.href=item.target_path; link.textContent="OPEN"; row.append(body,link); root.append(row); });
    }
    function renderNinetyDayPlan(data) {
      const root=$("ninetyDayPlan"); root.replaceChildren(); ((data.ninety_day_plan||{}).phases||[]).forEach((item)=>{ const card=document.createElement("article"); card.className="phase"; addText(card,"div",`${item.target_days} DAY TARGET`,"eyebrow"); addText(card,"h3",item.label); const list=document.createElement("ul"); (item.items||[]).forEach(action=>addText(list,"li",action.title)); card.append(list); root.append(card); });
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
    function renderHelp(data) {
      const root=$("helpPaths"); root.replaceChildren(); ((data.help_center||{}).items||[]).forEach((item)=>{ const card=document.createElement("article"); card.className="tool"; addText(card,"div",item.support_category,"eyebrow"); addText(card,"h3",item.title); addText(card,"p",item.first_step); const link=document.createElement("a"); link.className="link-button"; link.href=item.target_path; link.textContent="OPEN GUIDE"; card.append(link); root.append(card); });
    }
    function renderSupportReadiness(data) {
      const root=$("supportReadiness"); root.replaceChildren(); const support=data.support_readiness||{}; (support.items||[]).forEach((item)=>{ const card=document.createElement("article"); card.className=`lane ${item.ready?"ready":"review"}`; addText(card,"div",item.ready?"READY":"REVIEW","eyebrow"); addText(card,"h3",item.title); addText(card,"p",item.detail); root.append(card); });
    }
    function renderChangeDigest(data) {
      const root=$("changeDigest"); root.replaceChildren(); const digest=data.change_digest||{}; [["API",digest.api_version],["Installed",digest.installed_version],["Signed desktop",digest.latest_signed_version],["Service",digest.service_mode],["License",digest.license_state],["Desktop state",value(digest.desktop_state).replaceAll("_"," ")]].forEach(([label,item])=>root.append(metric(label,item)));
    }
    function renderGlossary(data) {
      const root=$("customerGlossary"); root.replaceChildren(); (data.customer_glossary||[]).forEach((item)=>{ const card=document.createElement("article"); card.className="tool"; addText(card,"div",item.id.replaceAll("-"," "),"eyebrow"); addText(card,"h3",item.term); addText(card,"p",item.meaning); root.append(card); });
    }
    function renderPrivacy(data) {
      const root=$("privacyGuarantees"); root.replaceChildren(); (data.privacy_guarantees||[]).forEach((text,index)=>{ const card=document.createElement("article"); card.className="surface"; addText(card,"div",`BOUNDARY ${index+1}`,"eyebrow"); addText(card,"p",text); root.append(card); });
    }
    function render(data) { state.payload=data; state.completed=new Set(); state.actionFilter="all"; renderMetrics(data); renderNextAction(data); renderReadiness(data); renderJourney(data); renderSeatPlanner(data); renderScore(data); renderActions(data); renderSuccessPlan(data); renderRoutine(data); renderNinetyDayPlan(data); renderBenefits(data); renderTools(data); renderTimeline(data); renderUpgrades(data); renderLinks(data); renderHelp(data); renderSupportReadiness(data); renderChangeDigest(data); renderGlossary(data); renderPrivacy(data); $("workspace").hidden=false; }
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


def customer_answers_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Customer Answers</title>
  <style>
    :root { --bg:#0e1115; --band:#14191f; --panel:#1a2027; --field:#0a0d11; --line:#35404b; --text:#f4f7f8; --muted:#aab5bf; --green:#65df88; --blue:#67bde8; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#11161b; }
    header > div, main, footer > div { width:min(1120px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-size:17px; font-weight:800; }
    nav { display:flex; flex-wrap:wrap; gap:8px; }
    nav a, .answer-link { display:inline-flex; align-items:center; justify-content:center; min-height:36px; padding:0 11px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:750; }
    main { padding:28px 0 50px; }
    h1 { margin:0; font-size:32px; line-height:1.1; }
    h2 { margin:0; font-size:18px; }
    h3 { margin:0; font-size:15px; }
    .lead { max-width:760px; margin:8px 0 0; color:var(--muted); font-size:15px; }
    .privacy { margin-top:14px; padding:12px 14px; border-left:4px solid var(--blue); background:#151d24; color:var(--muted); }
    .toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-top:18px; }
    button { min-height:40px; padding:0 13px; border:1px solid var(--line); border-radius:5px; background:#29323c; color:var(--text); font:800 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:disabled { cursor:not-allowed; opacity:.5; }
    button.active, .primary { border-color:var(--blue); background:var(--blue); color:#071118; }
    .green { border-color:var(--green); background:var(--green); color:#071109; }
    .status { min-height:22px; margin-top:10px; color:var(--muted); }
    .status.good { color:var(--green); } .status.bad { color:var(--red); }
    .metrics { display:grid; grid-template-columns:repeat(4,minmax(130px,1fr)); margin-top:18px; border:1px solid var(--line); }
    .metric { min-width:0; padding:14px; border-right:1px solid var(--line); background:var(--band); }
    .metric:last-child { border-right:0; }
    .metric span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    .metric strong { display:block; margin-top:4px; font-size:18px; overflow-wrap:anywhere; }
    .search { display:grid; grid-template-columns:minmax(220px,1fr) auto; gap:9px; margin-top:22px; }
    input { width:100%; min-width:0; height:43px; padding:0 12px; border:1px solid var(--line); border-radius:5px; background:var(--field); color:var(--text); font:inherit; }
    .categories { display:flex; flex-wrap:wrap; gap:7px; margin:12px 0; }
    .categories button { min-height:35px; background:var(--panel); }
    .categories button.active { background:var(--blue); }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:14px; padding:18px 0 10px; border-top:1px solid var(--line); }
    .section-head p { margin:0; color:var(--muted); text-align:right; }
    .answers { display:grid; gap:9px; }
    details { min-width:0; border:1px solid var(--line); border-left:4px solid var(--blue); border-radius:6px; background:var(--panel); }
    details.saved { border-left-color:var(--green); }
    summary { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:12px; align-items:center; padding:15px; cursor:pointer; list-style:none; }
    summary::-webkit-details-marker { display:none; }
    summary::after { content:"OPEN"; color:var(--blue); font-size:10px; font-weight:800; }
    details[open] summary::after { content:"CLOSE"; }
    .category { color:var(--blue); font-size:10px; font-weight:800; text-transform:uppercase; }
    .question { margin-top:3px; font-size:15px; font-weight:800; }
    .answer-body { padding:0 15px 15px; border-top:1px solid var(--line); }
    .answer-body p { margin:13px 0 0; color:var(--muted); }
    .answer-body ol { margin:10px 0 0; padding-left:21px; color:var(--muted); }
    .answer-body li { margin:5px 0; }
    .answer-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
    .answer-actions button, .answer-actions a { min-height:36px; }
    .empty { padding:28px 16px; border:1px dashed var(--line); color:var(--muted); text-align:center; }
    footer { border-top:1px solid var(--line); background:#11161b; color:var(--muted); }
    footer > div { padding:18px 0; }
    @media(max-width:760px) {
      header > div { align-items:flex-start; flex-direction:column; padding:14px 0; }
      .metrics { grid-template-columns:repeat(2,minmax(0,1fr)); }
      .metric:nth-child(2) { border-right:0; }
      .metric:nth-child(-n+2) { border-bottom:1px solid var(--line); }
      .search { grid-template-columns:1fr; }
      .section-head { align-items:flex-start; flex-direction:column; }
      .section-head p { text-align:left; }
    }
    @media print {
      header, .toolbar, .search, .categories, footer, .answer-actions, .privacy { display:none!important; }
      body { background:#fff; color:#111; }
      main { width:100%; padding:0; }
      details { break-inside:avoid; border-color:#bbb; background:#fff; }
      details[hidden] { display:none; }
      details summary::after { display:none; }
      .answer-body { display:block!important; }
    }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Customer Answers</div><nav><a href="/workspace">WORKSPACE</a><a href="/readiness">RECOVERY</a><a href="/update">UPDATE</a><a href="/status">STATUS</a></nav></div></header>
  <main>
    <h1>Find a safe next step</h1>
    <p class="lead">Search fixed VaultLink answers about locking, recovery, keys, updates, licensing, privacy, and security.</p>
    <div class="privacy">No question text is uploaded. Search, filters, opened answers, and saved-answer choices stay only in this browser tab and disappear when the page closes.</div>
    <div class="toolbar">
      <button id="refresh" class="primary" type="button">REFRESH ANSWERS</button>
      <button id="savedOnly" type="button">SAVED ONLY</button>
      <button id="export" type="button" disabled>EXPORT SAVED PACK</button>
      <button id="print" type="button">PRINT VISIBLE</button>
      <button id="clearSaved" type="button" disabled>CLEAR SAVED</button>
    </div>
    <div id="status" class="status" role="status">Loading fixed customer answers...</div>
    <div class="metrics">
      <div class="metric"><span>Answers</span><strong id="answerCount">0</strong></div>
      <div class="metric"><span>Categories</span><strong id="categoryCount">0</strong></div>
      <div class="metric"><span>Visible</span><strong id="visibleCount">0</strong></div>
      <div class="metric"><span>Saved this tab</span><strong id="savedCount">0</strong></div>
    </div>
    <div class="search"><input id="search" type="search" maxlength="120" autocomplete="off" placeholder="Search questions, answers, and safe steps" aria-label="Search customer answers"><button id="clearSearch" type="button">CLEAR SEARCH</button></div>
    <div id="categories" class="categories" aria-label="Answer categories"></div>
    <div class="section-head"><h2>Customer Answers</h2><p id="scope">Fixed public guidance. A saved answer is a current-tab bookmark, not proof that a problem was resolved.</p></div>
    <div id="answers" class="answers"></div>
  </main>
  <footer><div>API __API_VERSION__. This page accepts no license key, identity, file, path, PIN, USB secret, local result, or free-form question.</div></footer>
  <script>
    const $=id=>document.getElementById(id);
    const state={payload:null,category:"all",query:"",saved:new Set(),savedOnly:false};
    const text=value=>String(value??"");
    function setStatus(message,tone=""){ $("status").textContent=message; $("status").className=`status ${tone}`.trim(); }
    function add(parent,tag,value,className=""){const node=document.createElement(tag);node.textContent=text(value);if(className)node.className=className;parent.append(node);return node;}
    function categoryTitle(id){return state.payload?.categories.find(item=>item.id===id)?.title||"Other";}
    function answerSearchText(answer){return [answer.question,answer.answer,...answer.steps,...answer.tags,categoryTitle(answer.category_id)].join(" ").toLowerCase();}
    function visibleAnswers(){
      if(!state.payload)return[];
      return state.payload.items.filter(answer=>{
        if(state.category!=="all"&&answer.category_id!==state.category)return false;
        if(state.savedOnly&&!state.saved.has(answer.id))return false;
        return !state.query||answerSearchText(answer).includes(state.query);
      });
    }
    function renderMetrics(visible=visibleAnswers()){ $("answerCount").textContent=state.payload?.count||0; $("categoryCount").textContent=state.payload?.category_count||0; $("visibleCount").textContent=visible.length; $("savedCount").textContent=state.saved.size; $("export").disabled=state.saved.size===0; $("clearSaved").disabled=state.saved.size===0; }
    function renderCategories(){
      const root=$("categories");root.replaceChildren();
      const options=[{id:"all",title:"ALL"},...(state.payload?.categories||[])];
      options.forEach(item=>{const button=document.createElement("button");button.type="button";button.textContent=item.title;button.classList.toggle("active",state.category===item.id);button.addEventListener("click",()=>{state.category=item.id;renderCategories();renderAnswers();});root.append(button);});
    }
    function renderAnswers(){
      const items=visibleAnswers();const root=$("answers");root.replaceChildren();
      if(!items.length){add(root,"div","No fixed answers match these filters.","empty");renderMetrics(items);return;}
      items.forEach(answer=>{
        const card=document.createElement("details");card.dataset.answerId=answer.id;card.classList.toggle("saved",state.saved.has(answer.id));
        const summary=document.createElement("summary");const title=document.createElement("div");add(title,"div",categoryTitle(answer.category_id),"category");add(title,"div",answer.question,"question");summary.append(title);
        const body=document.createElement("div");body.className="answer-body";add(body,"p",answer.answer);
        const steps=document.createElement("ol");answer.steps.forEach(step=>add(steps,"li",step));body.append(steps);
        const actions=document.createElement("div");actions.className="answer-actions";
        const save=document.createElement("button");save.type="button";save.textContent=state.saved.has(answer.id)?"REMOVE SAVED":"SAVE ANSWER";save.className=state.saved.has(answer.id)?"green":"";
        save.addEventListener("click",()=>{state.saved.has(answer.id)?state.saved.delete(answer.id):state.saved.add(answer.id);renderAnswers();setStatus("Saved-answer choices changed only in this browser tab.","good");});
        const copy=document.createElement("button");copy.type="button";copy.textContent="COPY ANSWER";copy.addEventListener("click",()=>copyAnswer(answer));
        const link=document.createElement("a");link.className="answer-link";link.href=answer.target_path;link.textContent=answer.target_label;
        actions.append(save,copy,link);body.append(actions);card.append(summary,body);root.append(card);
      });
      renderMetrics(items);
    }
    async function copyAnswer(answer){
      const lines=[answer.question,answer.answer,"",...answer.steps.map((step,index)=>`${index+1}. ${step}`),`Guide: ${location.origin}${answer.target_path}`,"","Never send passwords, PINs, USB keys, file contents, or personal details to support."];
      try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Fixed answer copied.","good");}catch(_error){setStatus("Browser clipboard access was blocked.","bad");}
    }
    function safeExport(){
      const savedItems=(state.payload?.items||[]).filter(item=>state.saved.has(item.id)).map(item=>({id:item.id,category_id:item.category_id,question:item.question,answer:item.answer,steps:item.steps,target_path:item.target_path,target_label:item.target_label}));
      return {schema_version:1,report_type:"VaultLink Saved Customer Answers",generated_at_utc:new Date().toISOString(),api_version:state.payload?.api_version||"",saved_answer_ids:savedItems.map(item=>item.id),answers:savedItems,privacy_notice:"This public fixed-answer pack contains no license key, identity, machine identity, password, PIN, USB secret, path, filename, file content, local result, or free-form question."};
    }
    function exportSaved(){const report=safeExport();if(!report.answers.length)return;const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="vaultlink-saved-customer-answers.json";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus("Saved-answer pack exported locally.","good");}
    async function load(){
      $("refresh").disabled=true;setStatus("Loading fixed customer answers...");
      try{const response=await fetch("/api/v1/customer-answers",{headers:{"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Answers could not be loaded.");state.payload=data;state.saved=new Set([...state.saved].filter(id=>data.items.some(item=>item.id===id)));renderCategories();renderAnswers();setStatus(`${data.count} fixed answers loaded. Search stays in this browser tab.`,"good");}
      catch(error){state.payload=null;$("answers").replaceChildren();renderMetrics([]);setStatus(error.message||"Answers could not be loaded.","bad");}
      finally{$("refresh").disabled=false;}
    }
    $("refresh").addEventListener("click",load);
    $("search").addEventListener("input",event=>{state.query=event.target.value.trim().toLowerCase();renderAnswers();});
    $("clearSearch").addEventListener("click",()=>{$("search").value="";state.query="";renderAnswers();});
    $("savedOnly").addEventListener("click",()=>{state.savedOnly=!state.savedOnly;$("savedOnly").classList.toggle("active",state.savedOnly);renderAnswers();});
    $("clearSaved").addEventListener("click",()=>{state.saved.clear();state.savedOnly=false;$("savedOnly").classList.remove("active");renderAnswers();setStatus("Current-tab saved answers cleared.","good");});
    $("export").addEventListener("click",exportSaved);
    $("print").addEventListener("click",()=>window.print());
    load();
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))


def customer_decision_wizard_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Recovery Decision Wizard</title>
  <style>
    :root { --bg:#0d1115; --band:#141a20; --panel:#1b2229; --field:#090d11; --line:#35414c; --text:#f4f7f8; --muted:#aab5bf; --green:#65df88; --blue:#67bde8; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header { border-bottom:1px solid var(--line); background:#11161b; }
    header > div, main, footer > div { width:min(1120px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:68px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { font-size:17px; font-weight:800; }
    nav { display:flex; flex-wrap:wrap; gap:8px; }
    nav a, .guide-link { display:inline-flex; align-items:center; justify-content:center; min-height:36px; padding:0 11px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:800; }
    main { padding:28px 0 50px; }
    h1 { margin:0; font-size:32px; line-height:1.1; }
    h2 { margin:0; font-size:19px; } h3 { margin:0; font-size:16px; }
    .lead { max-width:780px; margin:8px 0 0; color:var(--muted); font-size:15px; }
    .privacy { margin-top:14px; padding:12px 14px; border-left:4px solid var(--blue); background:#151d24; color:var(--muted); }
    .toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
    button { min-height:40px; padding:0 13px; border:1px solid var(--line); border-radius:5px; background:#29323c; color:var(--text); font:800 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:disabled { cursor:not-allowed; opacity:.48; }
    .primary { border-color:var(--blue); background:var(--blue); color:#071118; }
    .yes { border-color:var(--green); background:var(--green); color:#071109; }
    .no { border-color:var(--yellow); background:var(--yellow); color:#171203; }
    .status { min-height:22px; margin-top:9px; color:var(--muted); }
    .status.good { color:var(--green); } .status.bad { color:var(--red); }
    .metrics { display:grid; grid-template-columns:repeat(3,minmax(130px,1fr)); margin-top:18px; border:1px solid var(--line); }
    .metric { min-width:0; padding:14px; border-right:1px solid var(--line); background:var(--band); }
    .metric:last-child { border-right:0; }
    .metric span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    .metric strong { display:block; margin-top:4px; font-size:19px; }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:14px; padding:22px 0 10px; border-bottom:1px solid var(--line); }
    .section-head p { margin:0; color:var(--muted); text-align:right; }
    .scenarios { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; padding-top:12px; }
    .scenarios[hidden] { display:none; }
    .scenario { min-width:0; min-height:104px; padding:15px; border-left:4px solid var(--blue); background:var(--panel); text-align:left; }
    .scenario span { display:block; margin-top:7px; color:var(--muted); font-weight:500; line-height:1.45; }
    .workspace { margin-top:16px; border:1px solid var(--line); background:var(--panel); }
    .workspace[hidden], .outcome[hidden] { display:none; }
    .workspace-head { display:flex; align-items:start; justify-content:space-between; gap:14px; padding:16px; border-bottom:1px solid var(--line); }
    .eyebrow { color:var(--blue); font-size:10px; font-weight:800; text-transform:uppercase; }
    .question { padding:22px 16px; }
    .question h2 { max-width:760px; margin-top:5px; font-size:24px; line-height:1.25; }
    .question p { max-width:800px; margin:10px 0 0; color:var(--muted); }
    .choices { display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:20px; }
    .choices button { min-height:54px; font-size:14px; }
    .trail { padding:0 16px 16px; }
    .trail ol { margin:8px 0 0; padding-left:20px; color:var(--muted); }
    .trail li { margin:5px 0; }
    .outcome { margin-top:16px; padding:18px; border:1px solid var(--line); border-left:5px solid var(--green); background:var(--band); }
    .outcome.watch { border-left-color:var(--yellow); } .outcome.urgent { border-left-color:var(--red); }
    .outcome p { color:var(--muted); }
    .outcome ol { padding-left:21px; color:var(--muted); }
    .outcome li { margin:6px 0; }
    .warning { padding:10px 12px; border:1px solid var(--line); background:var(--field); color:var(--yellow); }
    .outcome-actions { display:flex; flex-wrap:wrap; gap:8px; margin-top:14px; }
    footer { border-top:1px solid var(--line); background:#11161b; color:var(--muted); }
    footer > div { padding:18px 0; }
    @media(max-width:720px) {
      header > div { align-items:flex-start; flex-direction:column; padding:14px 0; }
      .scenarios { grid-template-columns:1fr; }
      .metrics { grid-template-columns:1fr; }
      .metric { border-right:0; border-bottom:1px solid var(--line); }
      .metric:last-child { border-bottom:0; }
      .section-head,.workspace-head { align-items:flex-start; flex-direction:column; }
      .section-head p { text-align:left; }
      .choices { grid-template-columns:1fr; }
    }
    @media print {
      header,.toolbar,.privacy,.scenarios,.choices,.workspace-head,footer,.outcome-actions { display:none!important; }
      body { background:#fff; color:#111; }
      main { width:100%; padding:0; }
      .workspace,.outcome { border-color:#999; background:#fff; }
      .question p,.trail ol,.outcome p,.outcome ol { color:#222; }
    }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Recovery Decision Wizard</div><nav><a href="/workspace">WORKSPACE</a><a href="/QNA">ANSWERS</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a></nav></div></header>
  <main>
    <h1>Choose the safest next move</h1>
    <p class="lead">Pick a situation and answer up to three fixed yes-or-no questions. VaultLink will route you to a reviewed action plan without inspecting your PC.</p>
    <div class="privacy">Choices, decision history, and the result stay only in the current browser tab. This page accepts no typed problem description, license key, identity, file, path, PIN, USB secret, or local scan result.</div>
    <div class="toolbar">
      <button id="refresh" type="button" class="primary">REFRESH WIZARD</button>
      <button id="back" type="button" disabled>BACK ONE ANSWER</button>
      <button id="restart" type="button" disabled>CHOOSE ANOTHER SITUATION</button>
      <button id="copy" type="button" disabled>COPY ACTION PLAN</button>
      <button id="export" type="button" disabled>EXPORT ACTION PLAN</button>
      <button id="print" type="button" disabled>PRINT PLAN</button>
    </div>
    <div id="status" class="status" role="status" aria-live="polite">Loading fixed decision paths...</div>
    <section class="metrics" aria-label="Wizard catalog totals">
      <div class="metric"><span>Situations</span><strong id="scenarioCount">0</strong></div>
      <div class="metric"><span>Decision points</span><strong id="nodeCount">0</strong></div>
      <div class="metric"><span>Fixed outcomes</span><strong id="outcomeCount">0</strong></div>
    </section>
    <div class="section-head"><div><h2>What is happening?</h2></div><p>Select one fixed situation. Do not enter secrets or personal details.</p></div>
    <section id="scenarios" class="scenarios" aria-label="Customer situations"></section>
    <section id="workspace" class="workspace" hidden>
      <div class="workspace-head"><div><div class="eyebrow" id="scenarioPosition">SITUATION</div><h3 id="scenarioTitle"></h3></div><div class="eyebrow" id="decisionProgress"></div></div>
      <div class="question">
        <div class="eyebrow">YES OR NO</div>
        <h2 id="questionText"></h2>
        <p id="questionHelp"></p>
        <div class="choices"><button id="yes" type="button" class="yes">YES</button><button id="no" type="button" class="no">NO</button></div>
      </div>
      <div class="trail"><div class="eyebrow">CURRENT-TAB DECISION TRAIL</div><ol id="trail"></ol></div>
    </section>
    <section id="outcome" class="outcome" hidden>
      <div class="eyebrow" id="outcomePriority"></div>
      <h2 id="outcomeTitle"></h2>
      <p id="outcomeSummary"></p>
      <ol id="outcomeSteps"></ol>
      <div id="outcomeWarning" class="warning"></div>
      <div class="outcome-actions"><a id="guideLink" class="guide-link" href="/workspace">OPEN GUIDE</a></div>
    </section>
  </main>
  <footer><div>API __API_VERSION__. Fixed guidance only. The wizard cannot inspect, scan, lock, unlock, install, delete, quarantine, or control a customer PC.</div></footer>
  <script>
    const $=id=>document.getElementById(id);
    const state={payload:null,scenario:null,currentNode:null,outcome:null,history:[]};
    const nodeMap=()=>new Map((state.payload?.nodes||[]).map(item=>[item.id,item]));
    const outcomeMap=()=>new Map((state.payload?.outcomes||[]).map(item=>[item.id,item]));
    function setStatus(message,tone=""){const el=$("status");el.textContent=message;el.className=`status ${tone}`.trim();}
    function setButtons(){
      const hasScenario=Boolean(state.scenario);const hasOutcome=Boolean(state.outcome);
      $("back").disabled=!hasScenario||state.history.length===0;
      $("restart").disabled=!hasScenario;
      $("copy").disabled=!hasOutcome;$("export").disabled=!hasOutcome;$("print").disabled=!hasOutcome;
    }
    function renderCatalog(){
      $("scenarioCount").textContent=state.payload?.scenario_count||0;
      $("nodeCount").textContent=state.payload?.decision_count||0;
      $("outcomeCount").textContent=state.payload?.outcome_count||0;
      const root=$("scenarios");root.replaceChildren();
      (state.payload?.scenarios||[]).forEach((scenario,index)=>{
        const button=document.createElement("button");button.type="button";button.className="scenario";
        button.dataset.scenarioId=scenario.id;button.textContent=scenario.title;
        const detail=document.createElement("span");detail.textContent=scenario.summary;button.append(detail);
        button.addEventListener("click",()=>selectScenario(scenario,index));root.append(button);
      });
    }
    function selectScenario(scenario,index){
      state.scenario=scenario;state.currentNode=scenario.start_node_id;state.outcome=null;state.history=[];
      $("scenarioPosition").textContent=`SITUATION ${index+1} OF ${state.payload.scenario_count}`;
      $("scenarioTitle").textContent=scenario.title;$("scenarios").hidden=true;$("workspace").hidden=false;$("outcome").hidden=true;
      renderDecision();setButtons();setStatus("Answer only the fixed yes-or-no question shown. Choices stay in this tab.","good");
    }
    function renderDecision(){
      const node=nodeMap().get(state.currentNode);if(!node){setStatus("This fixed decision path is unavailable.","bad");return;}
      $("questionText").textContent=node.question;$("questionHelp").textContent=node.explanation;
      $("decisionProgress").textContent=`DECISION ${state.history.length+1} OF UP TO ${state.scenario.max_decisions}`;
      const trail=$("trail");trail.replaceChildren();
      state.history.forEach(item=>{const row=document.createElement("li");row.textContent=`${item.question} ${item.answer.toUpperCase()}`;trail.append(row);});
      if(!state.history.length){const row=document.createElement("li");row.textContent="No answers recorded yet.";trail.append(row);}
    }
    function choose(answer){
      const node=nodeMap().get(state.currentNode);if(!node)return;
      state.history.push({node_id:node.id,question:node.question,answer});
      const target=node[answer];
      if(target.target_type==="node"){state.currentNode=target.target_id;renderDecision();setButtons();return;}
      state.outcome=outcomeMap().get(target.target_id);renderOutcome();
    }
    function renderOutcome(){
      const item=state.outcome;if(!item){setStatus("This fixed outcome is unavailable.","bad");return;}
      $("workspace").hidden=true;$("outcome").hidden=false;$("outcome").className=`outcome ${item.priority}`;
      $("outcomePriority").textContent=`${item.priority.toUpperCase()} ACTION PLAN`;
      $("outcomeTitle").textContent=item.title;$("outcomeSummary").textContent=item.summary;
      const steps=$("outcomeSteps");steps.replaceChildren();item.steps.forEach(step=>{const row=document.createElement("li");row.textContent=step;steps.append(row);});
      $("outcomeWarning").textContent=item.warning;$("guideLink").href=item.target_path;$("guideLink").textContent=item.target_label;
      setButtons();setStatus("Fixed action plan ready. Review it before copying, exporting, or printing.","good");
    }
    function replay(){
      state.outcome=null;state.currentNode=state.scenario.start_node_id;
      for(const item of state.history){const node=nodeMap().get(state.currentNode);const target=node?.[item.answer];if(!target)break;if(target.target_type==="node")state.currentNode=target.target_id;else state.outcome=outcomeMap().get(target.target_id);}
      if(state.outcome)renderOutcome();else{$("workspace").hidden=false;$("outcome").hidden=true;renderDecision();setButtons();}
    }
    function back(){if(!state.history.length)return;state.history.pop();replay();setStatus("Last current-tab answer removed.","good");}
    function restart(){
      state.scenario=null;state.currentNode=null;state.outcome=null;state.history=[];
      $("scenarios").hidden=false;$("workspace").hidden=true;$("outcome").hidden=true;setButtons();setStatus("Choose another fixed situation.");
    }
    function safePlan(){
      if(!state.outcome||!state.scenario)return null;
      return {schema_version:1,report_type:"VaultLink Recovery Decision Plan",generated_at_utc:new Date().toISOString(),api_version:state.payload?.api_version||"",scenario_id:state.scenario.id,scenario_title:state.scenario.title,decision_history:state.history.map(item=>({node_id:item.node_id,answer:item.answer})),outcome:{id:state.outcome.id,title:state.outcome.title,priority:state.outcome.priority,summary:state.outcome.summary,steps:state.outcome.steps,target_path:state.outcome.target_path,target_label:state.outcome.target_label,warning:state.outcome.warning},privacy_notice:"This fixed action plan contains no license key, identity, machine identity, file, path, filename, PIN, USB secret, local scan result, file content, or free-form problem description."};
    }
    async function copyPlan(){
      const plan=safePlan();if(!plan)return;
      const lines=[plan.scenario_title,`${plan.outcome.priority.toUpperCase()}: ${plan.outcome.title}`,plan.outcome.summary,"",...plan.outcome.steps.map((step,index)=>`${index+1}. ${step}`),"",plan.outcome.warning,`Guide: ${location.origin}${plan.outcome.target_path}`];
      try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Fixed action plan copied.","good");}catch(_error){setStatus("Browser clipboard access was blocked.","bad");}
    }
    function exportPlan(){
      const plan=safePlan();if(!plan)return;const blob=new Blob([JSON.stringify(plan,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="vaultlink-recovery-decision-plan.json";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus("Privacy-safe action plan exported locally.","good");
    }
    async function load(){
      $("refresh").disabled=true;setStatus("Loading fixed decision paths...");
      try{const response=await fetch("/api/v1/customer-decisions",{headers:{"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Decision wizard could not be loaded.");state.payload=data;restart();renderCatalog();setStatus(`${data.scenario_count} situations and ${data.decision_count} decision points loaded.`,"good");}
      catch(error){state.payload=null;$("scenarios").replaceChildren();setStatus(error.message||"Decision wizard could not be loaded.","bad");}
      finally{$("refresh").disabled=false;}
    }
    $("refresh").addEventListener("click",load);$("back").addEventListener("click",back);$("restart").addEventListener("click",restart);
    $("yes").addEventListener("click",()=>choose("yes"));$("no").addEventListener("click",()=>choose("no"));
    $("copy").addEventListener("click",copyPlan);$("export").addEventListener("click",exportPlan);$("print").addEventListener("click",()=>window.print());
    load();
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
  <header><div><strong>VaultLink Customer Experience</strong><div><a href="/owner/operations">MAINTENANCE OPS</a> &nbsp; <a href="/owner/trust">TRUST OPERATIONS</a> &nbsp; <a href="/owner">BACK TO OWNER CONSOLE</a></div></div></header>
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
  <header><div><div class="brand">VaultLink Trust Center</div><nav><a href="/workspace">WORKSPACE</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/recovery-drills">DRILLS</a><a href="/incident-response">INCIDENT</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/update">UPDATE</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a><a href="/privacy">PRIVACY</a></nav></div></header>
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
  <header><div><div class="brand">VaultLink Diagnostics Center</div><nav><a href="/workspace">WORKSPACE</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/recovery-drills">DRILLS</a><a href="/incident-response">INCIDENT</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/readiness">RECOVERY</a><a href="/status">STATUS</a></nav></div></header>
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


def customer_incident_response_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Incident Response</title>
  <style>
    :root { --bg:#0d1014; --band:#151a20; --panel:#1b2229; --field:#090c10; --line:#37434e; --text:#f4f7f8; --muted:#aab5bf; --green:#66df89; --blue:#68bee9; --yellow:#ffd166; --red:#ff7b72; }
    * { box-sizing:border-box; letter-spacing:0; } body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header,footer { background:#11161b; border-color:var(--line); border-style:solid; border-width:0 0 1px; } header>div,main,footer>div { width:min(1180px,calc(100% - 32px)); margin:auto; }
    header>div { min-height:70px; display:flex; align-items:center; justify-content:space-between; gap:16px; }.brand{font-size:18px;font-weight:800}nav{display:flex;flex-wrap:wrap;gap:7px}nav a{min-height:36px;display:inline-flex;align-items:center;padding:0 10px;border:1px solid var(--line);border-radius:5px;color:var(--text);text-decoration:none;font-weight:750}
    main{padding:28px 0 50px}h1{margin:0;font-size:30px}h2{margin:0;font-size:19px}h3{margin:0;font-size:15px}.lead,.status,.muted,.step p,.boundary p{color:var(--muted)}.lead{max-width:900px;margin:7px 0 0;font-size:15px}.warning{margin-top:14px;padding:12px 14px;border-left:4px solid var(--yellow);background:var(--band);color:var(--muted)}
    .controls{display:grid;grid-template-columns:minmax(230px,1fr) repeat(5,auto);gap:9px;align-items:end;margin-top:18px;padding:17px;border:1px solid var(--line);background:var(--band)}label{display:block;margin-bottom:6px;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}select{width:100%;height:42px;padding:0 11px;border:1px solid var(--line);border-radius:5px;background:var(--field);color:var(--text);font:inherit}button{min-height:42px;padding:0 12px;border:0;border-radius:5px;background:#29333d;color:var(--text);font-weight:800;cursor:pointer}button.primary{background:var(--yellow);color:#171100}button:disabled{opacity:.5;cursor:not-allowed}.status{min-height:22px;margin-top:9px}.status.good{color:var(--green)}.status.bad{color:var(--red)}#workspace[hidden]{display:none}
    .metrics{display:grid;grid-template-columns:repeat(5,minmax(120px,1fr));margin-top:13px;border:1px solid var(--line);background:var(--band)}.metric{min-width:0;padding:13px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span{display:block;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}.metric strong{display:block;margin-top:4px;font-size:17px;overflow-wrap:anywhere}
    .section{margin-top:24px;padding-top:19px;border-top:1px solid var(--line)}.section-head{display:flex;align-items:end;justify-content:space-between;gap:14px;margin-bottom:11px}.section-head p{max-width:680px;margin:0;color:var(--muted);text-align:right}.steps{display:grid;gap:9px}.step{display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px;padding:14px;border:1px solid var(--line);border-radius:6px;background:var(--panel)}.step.done{border-color:var(--green)}.step input{width:20px;height:20px;margin:2px 0 0;accent-color:var(--green)}.step p{margin:5px 0 0}.expected{color:var(--blue)!important}.eyebrow{color:var(--yellow);font-size:10px;font-weight:800;text-transform:uppercase}.notice{margin-top:13px;padding:13px;border-left:4px solid var(--yellow);background:var(--band);color:var(--muted)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:9px}.boundary{padding:14px;border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:6px;background:var(--panel)}.boundary p{margin:5px 0 0}.boundary.limit{border-left-color:var(--yellow)}footer{border-width:1px 0 0}footer>div{padding:21px 0 27px;color:var(--muted)}
    @media(max-width:1050px){.controls{grid-template-columns:1fr 1fr 1fr}.controls>div{grid-column:1/-1}}@media(max-width:900px){.metrics{grid-template-columns:repeat(2,1fr)}.metric{border-bottom:1px solid var(--line)}}@media(max-width:620px){header>div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.controls,.metrics{grid-template-columns:1fr}.controls>div{grid-column:auto}.metric{border-right:0}.step{grid-template-columns:28px minmax(0,1fr)}}
    @media print{header,.controls,.status,footer{display:none!important}body{background:#fff;color:#111}.step,.boundary,.notice{break-inside:avoid;background:#fff;color:#111;border-color:#777}.lead,.step p,.boundary p,.section-head p,.notice{color:#333!important}main{width:100%;padding:0}}
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Incident Response</div><nav><a href="/workspace">WORKSPACE</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/recovery-drills">DRILLS</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/status">STATUS</a></nav></div></header>
  <main>
    <h1>Respond without exposing secrets</h1>
    <p class="lead">Choose what happened and follow fixed safety steps. This page cannot inspect or control the PC, and progress disappears when the current tab closes or reloads.</p>
    <div class="warning">For immediate danger, financial theft, identity theft, or suspected unauthorized control, stop entering passwords on the affected PC and involve a trusted adult or qualified professional.</div>
    <section class="controls">
      <div><label for="playbook">Incident playbook</label><select id="playbook" disabled></select></div>
      <button id="reset" type="button" disabled>RESET CHECKLIST</button>
      <button id="next" type="button" disabled>COPY NEXT STEP</button>
      <button id="copy" type="button" disabled>COPY SAFE SUMMARY</button>
      <button id="print" type="button" disabled>PRINT CHECKLIST</button>
      <button id="export" class="primary" type="button" disabled>EXPORT SAFE JSON</button>
    </section>
    <div id="status" class="status" role="status" aria-live="polite">Loading fixed incident playbooks...</div>
    <div id="workspace" hidden>
      <div id="metrics" class="metrics"></div>
      <section class="section"><div class="section-head"><div><div id="playbookEyebrow" class="eyebrow">PLAYBOOK</div><h2 id="playbookTitle"></h2></div><p id="playbookSummary"></p></div><div id="steps" class="steps"></div><div id="escalation" class="notice"></div></section>
      <section class="section"><div class="section-head"><h2>Privacy Boundaries</h2><p>No free-text report, license proof, screenshot, process list, file upload, or machine inspection is used.</p></div><div id="boundaries" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Limitations</h2><p>Use the playbooks as a safe starting point, never as proof that an incident is resolved.</p></div><div id="limitations" class="grid"></div></section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. Checklist progress stays only in the current tab's page memory and is never submitted to VaultLink.</div></footer>
  <script>
    const $=id=>document.getElementById(id);const state={payload:null,playbook:"",completed:new Set()};const value=input=>String(input??"");
    function setStatus(message,tone=""){$("status").textContent=message;$("status").className=`status ${tone}`;}
    function add(parent,tag,text,className=""){const node=document.createElement(tag);node.textContent=value(text);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,text){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",text);return node;}
    function selectedPlaybook(){return(state.payload?.playbooks||[]).find(item=>item.id===state.playbook)||null;}
    function safeExport(){const playbook=selectedPlaybook();return{schema_version:1,report_type:"VaultLink Privacy-Safe Browser Incident Progress",generated_at_utc:new Date().toISOString(),api_version:state.payload.api_version,service_mode:state.payload.service_status.mode,signed_desktop_version:state.payload.signed_release.version||"",playbook_id:playbook?.id||"",playbook_title:playbook?.title||"",completed_step_ids:(playbook?.steps||[]).map(step=>step.id).filter(id=>state.completed.has(id)),total_steps:(playbook?.steps||[]).length,privacy_notice:"No license key, receipt, identity, password, PIN, USB secret, path, filename, screenshot, process list, file content, or free-form incident text is included."};}
    function renderMetrics(){const playbook=selectedPlaybook();const steps=playbook?.steps||[];const done=steps.filter(step=>state.completed.has(step.id)).length;const root=$("metrics");root.replaceChildren();[["API",state.payload.api_version],["Service",state.payload.service_status.mode],["Signed desktop",state.payload.signed_release.version||"Not published"],["Playbooks",state.payload.playbook_count],["Current progress",`${done} / ${steps.length}`]].forEach(row=>root.append(metric(...row)));}
    function renderPlaybook(){const playbook=selectedPlaybook();if(!playbook)return;$("playbookTitle").textContent=playbook.title;$("playbookSummary").textContent=playbook.summary;$("playbookEyebrow").textContent=playbook.id.replaceAll("-"," ");const root=$("steps");root.replaceChildren();playbook.steps.forEach((step,index)=>{const row=document.createElement("article");row.className=`step ${state.completed.has(step.id)?"done":""}`;const box=document.createElement("input");box.type="checkbox";box.checked=state.completed.has(step.id);box.setAttribute("aria-label",`Complete ${step.title}`);box.addEventListener("change",()=>{box.checked?state.completed.add(step.id):state.completed.delete(step.id);renderPlaybook();});const body=document.createElement("div");add(body,"div",`STEP ${index+1}`,"eyebrow");add(body,"h3",step.title);add(body,"p",step.action);add(body,"p",`Expected: ${step.expected}`,"expected");row.append(box,body);root.append(row);});$("escalation").textContent=`ESCALATION: ${playbook.escalation}`;renderMetrics();setStatus(`${playbook.title}: ${playbook.steps.filter(step=>state.completed.has(step.id)).length} of ${playbook.steps.length} steps complete.`,"good");}
    function render(data){state.payload=data;state.playbook=data.playbooks[0]?.id||"";state.completed.clear();const select=$("playbook");select.replaceChildren();data.playbooks.forEach(playbook=>{const option=document.createElement("option");option.value=playbook.id;option.textContent=playbook.title;select.append(option);});select.value=state.playbook;select.disabled=false;["reset","next","copy","print","export"].forEach(id=>$(id).disabled=false);const boundaries=$("boundaries");boundaries.replaceChildren();data.privacy_boundaries.forEach((text,index)=>{const item=document.createElement("article");item.className="boundary";add(item,"div",`BOUNDARY ${index+1}`,"eyebrow");add(item,"p",text);boundaries.append(item);});const limits=$("limitations");limits.replaceChildren();data.limitations.forEach((text,index)=>{const item=document.createElement("article");item.className="boundary limit";add(item,"div",`LIMITATION ${index+1}`,"eyebrow");add(item,"p",text);limits.append(item);});$("workspace").hidden=false;renderPlaybook();}
    async function load(){try{const response=await fetch("/api/v1/incident-guide",{headers:{"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Incident guide could not be loaded.");render(data);}catch(error){setStatus(error.message||"Incident guide could not be loaded.","bad");}}
    function reset(){const playbook=selectedPlaybook();(playbook?.steps||[]).forEach(step=>state.completed.delete(step.id));renderPlaybook();}
    async function copyNext(){const playbook=selectedPlaybook();const step=(playbook?.steps||[]).find(item=>!state.completed.has(item.id));if(!step){setStatus("Every step in this playbook is marked complete.","good");return;}const lines=[`VaultLink next safe step: ${step.title}`,step.action,`Expected: ${step.expected}`,"Do not include passwords, PINs, keys, private files, or personal details in support messages."];try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Next fixed safety step copied.","good");}catch(_error){setStatus("Clipboard access was blocked by the browser.","bad");}}
    async function copy(){const report=safeExport();const lines=[`VaultLink incident playbook: ${report.playbook_title}`,`Progress: ${report.completed_step_ids.length}/${report.total_steps}`,`API: ${report.api_version} | Service: ${report.service_mode} | Signed desktop: ${report.signed_desktop_version||"not published"}`,report.privacy_notice];try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Privacy-safe incident summary copied.","good");}catch(_error){setStatus("Clipboard access was blocked by the browser.","bad");}}
    function exportJson(){const report=safeExport();const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="vaultlink-browser-incident-progress.json";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus("Privacy-safe incident progress exported.","good");}
    $("playbook").addEventListener("change",event=>{state.playbook=event.target.value;renderPlaybook();});$("reset").addEventListener("click",reset);$("next").addEventListener("click",copyNext);$("copy").addEventListener("click",copy);$("print").addEventListener("click",()=>window.print());$("export").addEventListener("click",exportJson);load();
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))


def customer_recovery_drills_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Recovery Drills</title>
  <style>
    :root{--bg:#0d1014;--band:#151a20;--panel:#1b2229;--field:#090c10;--line:#37434e;--text:#f4f7f8;--muted:#aab5bf;--green:#66df89;--blue:#68bee9;--yellow:#ffd166;--red:#ff7b72}
    *{box-sizing:border-box;letter-spacing:0}body{margin:0;min-width:320px;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",Arial,sans-serif}header,footer{background:#11161b;border-color:var(--line);border-style:solid;border-width:0 0 1px}header>div,main,footer>div{width:min(1180px,calc(100% - 32px));margin:auto}header>div{min-height:70px;display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{font-size:18px;font-weight:800}nav{display:flex;flex-wrap:wrap;gap:7px}nav a{min-height:36px;display:inline-flex;align-items:center;padding:0 10px;border:1px solid var(--line);border-radius:5px;color:var(--text);text-decoration:none;font-weight:750}
    main{padding:28px 0 50px}h1{margin:0;font-size:30px}h2{margin:0;font-size:19px}h3{margin:0;font-size:15px}.lead,.status,.step p,.boundary p{color:var(--muted)}.lead{max-width:920px;margin:7px 0 0;font-size:15px}.notice{margin-top:14px;padding:12px 14px;border-left:4px solid var(--green);background:var(--band);color:var(--muted)}
    .selectors{display:grid;grid-template-columns:190px minmax(260px,1fr);gap:9px;margin-top:18px;padding:15px;border:1px solid var(--line);background:var(--band)}label{display:block;margin-bottom:6px;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}select{width:100%;height:42px;padding:0 11px;border:1px solid var(--line);border-radius:5px;background:var(--field);color:var(--text);font:inherit}.actions{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));gap:8px;margin-top:9px}button{min-height:42px;padding:0 10px;border:0;border-radius:5px;background:#29333d;color:var(--text);font-weight:800;cursor:pointer}button.primary{background:var(--green);color:#061109}button.export{background:var(--yellow);color:#171100}button:disabled{opacity:.5;cursor:not-allowed}.status{min-height:22px;margin-top:9px}.status.good{color:var(--green)}.status.bad{color:var(--red)}#workspace[hidden]{display:none}
    .metrics{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));margin-top:13px;border:1px solid var(--line);background:var(--band)}.metric{min-width:0;padding:13px;border-right:1px solid var(--line)}.metric:last-child{border-right:0}.metric span{display:block;color:var(--muted);font-size:10px;font-weight:800;text-transform:uppercase}.metric strong{display:block;margin-top:4px;font-size:16px;overflow-wrap:anywhere}
    .section{margin-top:24px;padding-top:19px;border-top:1px solid var(--line)}.section-head{display:flex;align-items:end;justify-content:space-between;gap:14px;margin-bottom:11px}.section-head p{max-width:680px;margin:0;color:var(--muted);text-align:right}.steps{display:grid;gap:9px}.step{display:grid;grid-template-columns:34px minmax(0,1fr);gap:12px;padding:14px;border:1px solid var(--line);border-radius:6px;background:var(--panel)}.step.done{border-color:var(--green)}.step input{width:20px;height:20px;margin:2px 0 0;accent-color:var(--green)}.step p{margin:5px 0 0}.expected{color:var(--blue)!important}.eyebrow{color:var(--yellow);font-size:10px;font-weight:800;text-transform:uppercase}.success{margin-top:13px;padding:13px;border-left:4px solid var(--green);background:var(--band);color:var(--muted)}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:9px}.boundary{padding:14px;border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:6px;background:var(--panel)}.boundary p{margin:5px 0 0}.boundary.limit{border-left-color:var(--yellow)}footer{border-width:1px 0 0}footer>div{padding:21px 0 27px;color:var(--muted)}
    @media(max-width:1050px){.actions{grid-template-columns:repeat(4,1fr)}}@media(max-width:820px){.metrics{grid-template-columns:repeat(2,1fr)}.metric{border-bottom:1px solid var(--line)}}@media(max-width:620px){header>div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.selectors,.metrics,.actions{grid-template-columns:1fr}.metric{border-right:0}.step{grid-template-columns:28px minmax(0,1fr)}}
    @media print{header,.selectors,.actions,.status,footer{display:none!important}body{background:#fff;color:#111}.step,.boundary,.success{break-inside:avoid;background:#fff;color:#111;border-color:#777}.lead,.step p,.boundary p,.section-head p,.success{color:#333!important}main{width:100%;padding:0}}
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Recovery Drills</div><nav><a href="/workspace">WORKSPACE</a><a href="/maintenance">MAINTENANCE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/incident-response">INCIDENT</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/update">UPDATE</a><a href="/status">STATUS</a></nav></div></header>
  <main>
    <h1>Practice recovery before it matters</h1>
    <p class="lead">Choose a fixed exercise, follow every step, and export only reviewed coarse progress. This page cannot inspect the PC, verify a real backup, or receive customer drill history.</p>
    <div class="notice">Ransomware exercises are tabletop guidance only. Never run malware, suspicious code, destructive scripts, or file-encryption simulations for training.</div>
    <section class="selectors">
      <div><label for="category">Category</label><select id="category" disabled></select></div>
      <div><label for="drill">Recovery drill</label><select id="drill" disabled></select></div>
    </section>
    <section class="actions">
      <button id="reset" type="button" disabled>RESET</button>
      <button id="next" class="primary" type="button" disabled>MARK NEXT</button>
      <button id="all" type="button" disabled>MARK ALL</button>
      <button id="random" type="button" disabled>RANDOM DRILL</button>
      <button id="copyNext" type="button" disabled>COPY NEXT STEP</button>
      <button id="copy" type="button" disabled>COPY SUMMARY</button>
      <button id="print" type="button" disabled>PRINT</button>
      <button id="export" class="export" type="button" disabled>EXPORT SAFE JSON</button>
    </section>
    <div id="status" class="status" role="status" aria-live="polite">Loading fixed recovery drills...</div>
    <div id="workspace" hidden>
      <div id="metrics" class="metrics"></div>
      <section class="section"><div class="section-head"><div><div id="drillEyebrow" class="eyebrow">DRILL</div><h2 id="drillTitle"></h2></div><p id="drillSummary"></p></div><div id="steps" class="steps"></div><div id="success" class="success"></div></section>
      <section class="section"><div class="section-head"><h2>Privacy Boundaries</h2><p>Progress exists only in the current tab unless the customer explicitly downloads a reviewed JSON file.</p></div><div id="boundaries" class="grid"></div></section>
      <section class="section"><div class="section-head"><h2>Limitations</h2><p>A completed exercise is preparation, never proof that a future recovery will succeed.</p></div><div id="limitations" class="grid"></div></section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. This page does not use browser storage, customer accounts, license proof, uploads, or a progress submission API.</div></footer>
  <script>
    const $=id=>document.getElementById(id);const state={payload:null,category:"ALL",drill:"",progress:new Map()};const value=input=>String(input??"");
    function setStatus(message,tone=""){$("status").textContent=message;$("status").className=`status ${tone}`;}
    function add(parent,tag,text,className=""){const node=document.createElement(tag);node.textContent=value(text);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,text){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",text);return node;}
    function drills(){return state.payload?.drills||[];}function selected(){return drills().find(item=>item.id===state.drill)||null;}function completed(id=state.drill){if(!state.progress.has(id))state.progress.set(id,new Set());return state.progress.get(id);}
    function filtered(){return drills().filter(item=>state.category==="ALL"||item.category===state.category);}
    function safeExport(){const drill=selected();const progress={};drills().forEach(item=>{const ids=item.steps.map(step=>step.id).filter(id=>completed(item.id).has(id));if(ids.length)progress[item.id]=ids;});return{schema_version:1,report_type:"VaultLink Privacy-Safe Browser Recovery Drill Progress",generated_at_utc:new Date().toISOString(),api_version:state.payload.api_version,service_mode:state.payload.service_status.mode,signed_desktop_version:state.payload.signed_release.version||"",selected_drill_id:drill?.id||"",selected_drill_title:drill?.title||"",progress,privacy_notice:"No license key, receipt, identity, password, PIN, USB secret, path, filename, screenshot, process list, file content, local check result, or free-form note is included."};}
    function renderMetrics(){const drill=selected();const done=(drill?.steps||[]).filter(step=>completed().has(step.id)).length;const root=$("metrics");root.replaceChildren();[["API",state.payload.api_version],["Service",state.payload.service_status.mode],["Signed desktop",state.payload.signed_release.version||"Not published"],["Drills",state.payload.drill_count],["Fixed steps",state.payload.step_count],["Current progress",`${done} / ${(drill?.steps||[]).length}`]].forEach(row=>root.append(metric(...row)));}
    function renderDrill(){const drill=selected();if(!drill)return;$("drillTitle").textContent=drill.title;$("drillSummary").textContent=drill.summary;$("drillEyebrow").textContent=`${drill.category} | ${drill.id.replaceAll("-"," ")}`;const root=$("steps");root.replaceChildren();drill.steps.forEach((step,index)=>{const row=document.createElement("article");row.className=`step ${completed().has(step.id)?"done":""}`;const box=document.createElement("input");box.type="checkbox";box.checked=completed().has(step.id);box.setAttribute("aria-label",`Complete ${step.title}`);box.addEventListener("change",()=>{box.checked?completed().add(step.id):completed().delete(step.id);renderDrill();});const body=document.createElement("div");add(body,"div",`STEP ${index+1}`,"eyebrow");add(body,"h3",step.title);add(body,"p",step.action);add(body,"p",`Expected: ${step.expected}`,"expected");row.append(box,body);root.append(row);});$("success").textContent=`SUCCESS TARGET: ${drill.success}`;renderMetrics();setStatus(`${drill.title}: ${drill.steps.filter(step=>completed().has(step.id)).length} of ${drill.steps.length} steps complete.`,"good");}
    function renderDrillOptions(){const options=filtered();if(!options.some(item=>item.id===state.drill))state.drill=options[0]?.id||"";const select=$("drill");select.replaceChildren();options.forEach(item=>{const option=document.createElement("option");option.value=item.id;option.textContent=item.title;select.append(option);});select.value=state.drill;renderDrill();}
    function render(data){state.payload=data;state.drill=data.drills[0]?.id||"";state.progress.clear();const categories=["ALL",...new Set(data.drills.map(item=>item.category))];const category=$("category");category.replaceChildren();categories.forEach(text=>{const option=document.createElement("option");option.value=text;option.textContent=text;category.append(option);});category.value=state.category;category.disabled=false;$("drill").disabled=false;["reset","next","all","random","copyNext","copy","print","export"].forEach(id=>$(id).disabled=false);const boundaries=$("boundaries");boundaries.replaceChildren();data.privacy_boundaries.forEach((text,index)=>{const item=document.createElement("article");item.className="boundary";add(item,"div",`BOUNDARY ${index+1}`,"eyebrow");add(item,"p",text);boundaries.append(item);});const limits=$("limitations");limits.replaceChildren();data.limitations.forEach((text,index)=>{const item=document.createElement("article");item.className="boundary limit";add(item,"div",`LIMITATION ${index+1}`,"eyebrow");add(item,"p",text);limits.append(item);});$("workspace").hidden=false;renderDrillOptions();}
    async function load(){try{const response=await fetch("/api/v1/recovery-drills",{headers:{"Accept":"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Recovery drills could not be loaded.");render(data);}catch(error){setStatus(error.message||"Recovery drills could not be loaded.","bad");}}
    function reset(){completed().clear();renderDrill();}function markNext(){const drill=selected();const step=drill?.steps.find(item=>!completed().has(item.id));if(step)completed().add(step.id);renderDrill();}function markAll(){(selected()?.steps||[]).forEach(step=>completed().add(step.id));renderDrill();}
    function randomDrill(){const options=filtered();if(!options.length)return;const bytes=new Uint32Array(1);crypto.getRandomValues(bytes);state.drill=options[bytes[0]%options.length].id;$("drill").value=state.drill;renderDrill();}
    async function copyNext(){const drill=selected();const step=drill?.steps.find(item=>!completed().has(item.id));if(!step){setStatus("Every step in this drill is marked complete.","good");return;}const lines=[`VaultLink next recovery step: ${step.title}`,step.action,`Expected: ${step.expected}`,"Do not include passwords, PINs, keys, private files, or personal details in support messages."];try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Next fixed recovery step copied.","good");}catch(_error){setStatus("Clipboard access was blocked by the browser.","bad");}}
    async function copySummary(){const report=safeExport();const selectedProgress=report.progress[report.selected_drill_id]||[];const lines=[`VaultLink recovery drill: ${report.selected_drill_title}`,`Progress: ${selectedProgress.length}/${selected()?.steps.length||0}`,`API: ${report.api_version} | Service: ${report.service_mode} | Signed desktop: ${report.signed_desktop_version||"not published"}`,report.privacy_notice];try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Privacy-safe drill summary copied.","good");}catch(_error){setStatus("Clipboard access was blocked by the browser.","bad");}}
    function exportJson(){const report=safeExport();const blob=new Blob([JSON.stringify(report,null,2)],{type:"application/json"});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download="vaultlink-browser-recovery-drills.json";document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);setStatus("Privacy-safe browser drill progress exported.","good");}
    $("category").addEventListener("change",event=>{state.category=event.target.value;renderDrillOptions();});$("drill").addEventListener("change",event=>{state.drill=event.target.value;renderDrill();});$("reset").addEventListener("click",reset);$("next").addEventListener("click",markNext);$("all").addEventListener("click",markAll);$("random").addEventListener("click",randomDrill);$("copyNext").addEventListener("click",copyNext);$("copy").addEventListener("click",copySummary);$("print").addEventListener("click",()=>window.print());$("export").addEventListener("click",exportJson);load();
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
  <header><div><div class="brand">VaultLink Trust Operations</div><nav><a href="/owner">OWNER CONSOLE</a><a href="/owner/operations">MAINTENANCE OPS</a><a href="/owner/customers">CUSTOMERS</a><a href="/owner/insights">INSIGHTS</a><a href="/trust">PUBLIC TRUST</a></nav></div></header>
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
