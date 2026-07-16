import html


def owner_maintenance_operations_html(api_version):
    page = r'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultLink Owner Maintenance Operations</title>
  <style>
    :root { color-scheme:dark; --bg:#0c0f12; --band:#13181d; --panel:#1a2027; --field:#090c0f; --line:#36414b; --text:#f4f7f9; --muted:#a6b1bc; --green:#5ede84; --blue:#63bce7; --yellow:#f2c95c; --red:#ff747c; }
    * { box-sizing:border-box; letter-spacing:0; }
    body { margin:0; min-width:320px; background:var(--bg); color:var(--text); font:14px/1.5 "Segoe UI",Arial,sans-serif; }
    header,footer { background:#101419; border-color:var(--line); border-style:solid; border-width:0 0 1px; }
    header > div,main,footer > div { width:min(1240px,calc(100% - 32px)); margin:0 auto; }
    header > div { min-height:72px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
    .brand { display:flex; align-items:baseline; gap:12px; min-width:0; }
    .brand strong { font-size:19px; }
    .brand span { color:var(--muted); font-size:11px; font-weight:800; text-transform:uppercase; }
    nav { display:flex; flex-wrap:wrap; gap:7px; }
    nav a,.action-link { min-height:36px; display:inline-flex; align-items:center; justify-content:center; padding:0 10px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:750; }
    main { padding:28px 0 52px; }
    h1 { margin:0; font-size:30px; }
    h2 { margin:0; font-size:18px; }
    h3 { margin:0; font-size:14px; }
    .lead,.status,.muted,.card p { color:var(--muted); }
    .lead { max-width:880px; margin:8px 0 0; }
    .auth { display:grid; grid-template-columns:minmax(260px,1fr) auto auto; gap:9px; align-items:end; margin-top:18px; padding:17px; border:1px solid var(--line); background:var(--band); }
    label { display:block; margin-bottom:6px; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    input,select { width:100%; min-width:0; height:42px; padding:0 11px; border:1px solid var(--line); border-radius:5px; background:var(--field); color:var(--text); font:inherit; }
    input[type="checkbox"] { width:18px; height:18px; accent-color:var(--green); }
    button { min-height:42px; padding:0 14px; border:0; border-radius:5px; background:#29323c; color:var(--text); font:800 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:hover,.action-link:hover,nav a:hover { filter:brightness(1.12); }
    button:disabled { cursor:not-allowed; opacity:.48; }
    .primary { background:var(--blue); color:#061118; }
    .good-button { background:var(--green); color:#07120a; }
    .status { min-height:22px; margin-top:9px; }
    .status.good { color:var(--green); }
    .status.bad { color:var(--red); }
    #console[hidden] { display:none; }
    .toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; align-items:center; }
    .toggle { min-height:42px; display:inline-flex; align-items:center; gap:8px; padding:0 12px; border:1px solid var(--line); border-radius:5px; background:var(--band); color:var(--text); font-size:11px; font-weight:800; }
    .metrics { display:grid; grid-template-columns:repeat(8,minmax(110px,1fr)); margin-top:14px; border:1px solid var(--line); background:var(--band); }
    .metric { min-width:0; padding:14px; border-right:1px solid var(--line); }
    .metric:last-child { border-right:0; }
    .metric span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    .metric strong { display:block; margin-top:5px; font-size:18px; overflow-wrap:anywhere; }
    .section { margin-top:25px; padding-top:20px; border-top:1px solid var(--line); }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:14px; margin-bottom:11px; }
    .section-head p { max-width:720px; margin:0; color:var(--muted); text-align:right; }
    .briefing { display:grid; grid-template-columns:minmax(280px,1.4fr) minmax(260px,.8fr); gap:10px; }
    .briefing-main { padding:19px; border-left:5px solid var(--blue); background:var(--band); }
    .briefing-main h3 { font-size:20px; }
    .briefing-main p { margin:7px 0 0; color:var(--muted); }
    .briefing-facts { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
    .fact { min-width:0; padding:12px; border:1px solid var(--line); background:var(--panel); }
    .fact span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    .fact strong { display:block; margin-top:4px; overflow-wrap:anywhere; }
    .filters { display:grid; grid-template-columns:minmax(220px,1fr) minmax(170px,.45fr) minmax(150px,.4fr) auto; gap:9px; align-items:end; }
    .planner { display:grid; grid-template-columns:minmax(220px,.8fr) minmax(220px,.7fr) auto auto; gap:9px; align-items:end; }
    .session-controls { display:grid; grid-template-columns:minmax(240px,1fr) repeat(4,auto); gap:9px; align-items:end; }
    .session-summary { display:grid; grid-template-columns:minmax(260px,1fr) minmax(220px,.6fr); gap:9px; margin:10px 0; }
    .session-summary .card { min-height:100%; }
    .summary-strip { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-top:10px; color:var(--muted); }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:9px; }
    .checks { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
    .card { min-width:0; padding:14px; border:1px solid var(--line); border-left:4px solid var(--blue); border-radius:6px; background:var(--panel); }
    .card.good { border-left-color:var(--green); }
    .card.attention { border-left-color:var(--yellow); }
    .card.action,.card.worse { border-left-color:var(--red); }
    .card.improved { border-left-color:var(--green); }
    .card.steady { border-left-color:var(--blue); }
    .card p { margin:5px 0 0; overflow-wrap:anywhere; }
    .eyebrow { color:var(--blue); font-size:10px; font-weight:800; text-transform:uppercase; }
    .eyebrow.good,.eyebrow.improved { color:var(--green); }
    .eyebrow.attention { color:var(--yellow); }
    .eyebrow.action,.eyebrow.worse { color:var(--red); }
    .next { margin-top:8px!important; color:var(--text)!important; }
    .action-link { width:fit-content; margin-top:10px; min-height:32px; color:var(--blue); }
    .progress { height:7px; margin-top:10px; overflow:hidden; border-radius:4px; background:#090c0f; }
    .progress span { display:block; height:100%; background:var(--green); }
    .category { margin-top:17px; }
    .category-head { display:flex; justify-content:space-between; gap:10px; margin-bottom:8px; color:var(--muted); }
    .category-head strong { color:var(--text); }
    .plan-steps { margin:10px 0 0; padding-left:19px; color:var(--muted); }
    .plan-steps li { margin:5px 0; }
    .review-card.reviewed { border-left-color:var(--green); opacity:.78; }
    .review-card.focused { outline:2px solid var(--blue); outline-offset:2px; }
    .review-toggle { display:flex; align-items:flex-start; gap:10px; margin-bottom:8px; }
    .review-toggle input { flex:0 0 18px; margin:2px 0 0; }
    .review-toggle label { margin:0; color:var(--text); font-size:14px; line-height:1.35; text-transform:none; cursor:pointer; }
    .empty { padding:25px 15px; border:1px dashed var(--line); color:var(--muted); text-align:center; }
    footer { border-width:1px 0 0; }
    footer > div { padding:21px 0 28px; color:var(--muted); }
    @media(max-width:1080px){.metrics{grid-template-columns:repeat(4,1fr)}.planner,.session-controls{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:780px){header>div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.auth,.filters,.planner,.briefing,.session-controls,.session-summary{grid-template-columns:1fr}.checks{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}button{width:100%}.toggle{width:100%;justify-content:center}.action-link{width:100%}}
    @media(max-width:460px){.brand{align-items:flex-start;flex-direction:column;gap:2px}.metrics,.briefing-facts{grid-template-columns:1fr}.metric{border-right:0;border-bottom:1px solid var(--line)}}
    @media print { header,.auth,.toolbar,.filters,.planner button,.action-link,footer { display:none!important; } body { background:#fff; color:#111; } main { width:100%; padding:0; } .card,.metric,.briefing-main,.fact { break-inside:avoid; background:#fff; border-color:#999; color:#111; } .card p,.section-head p,.briefing-main p,.fact span,.metric span,.summary-strip { color:#444; } }
  </style>
</head>
<body>
  <header><div><div class="brand"><strong>Owner Maintenance Operations</strong><span>gates, decision queue, review session, and 40 fixed readiness checks</span></div><nav><a href="/owner">OWNER CONSOLE</a><a href="/owner/insights">INSIGHTS</a><a href="/owner/customers">CUSTOMERS</a><a href="/owner/trust">TRUST</a></nav></div></header>
  <main>
    <h1>Owner operations cockpit</h1>
    <p class="lead">A privacy-safe maintenance board for owner access, secrets, storage, signed releases, customer surfaces, licensing, support, audit review, commerce, and governance.</p>
    <section class="auth">
      <div><label for="token">Owner admin token</label><input id="token" type="password" autocomplete="off" spellcheck="false"></div>
      <button id="connect" class="primary" type="button">LOAD OPERATIONS</button>
      <button id="clear" type="button">CLEAR</button>
    </section>
    <div id="status" class="status" role="status" aria-live="polite">Disconnected. The token stays only in this page memory and is sent only in the admin header.</div>
    <div id="console" hidden>
      <div class="toolbar">
        <button id="refresh" class="good-button" type="button">REFRESH</button>
        <label class="toggle"><input id="autoRefresh" type="checkbox"> AUTO REFRESH 60S</label>
        <button id="copyBriefing" type="button">COPY BRIEFING</button>
        <button id="textExport" type="button">EXPORT TEXT</button>
        <button id="json" type="button">EXPORT SAFE JSON</button>
        <button id="csv" type="button">EXPORT CHECKS CSV</button>
        <button id="receipt" type="button">SHA-256 RECEIPT</button>
        <button id="print" type="button">PRINT</button>
      </div>
      <div id="metrics" class="metrics"></div>

      <section class="section">
        <div class="section-head"><h2>Daily Owner Briefing</h2><p>A compact current-state summary with no customer identity or secret fields.</p></div>
        <div class="briefing"><div id="briefingMain" class="briefing-main"></div><div id="briefingFacts" class="briefing-facts"></div></div>
        <div id="severity" class="grid" style="margin-top:9px"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Approval Gates</h2><p>Six non-overlapping gates divide all 40 fixed checks exactly once.</p></div>
        <div id="approvalGates" class="grid"></div>
      </section>

      <section class="section" id="review-session">
        <div class="section-head"><h2>Owner Review Session</h2><p>Review marks stay only in this tab and do not resolve or complete the underlying action.</p></div>
        <div class="session-controls">
          <div><label for="reviewLane">Review lane</label><select id="reviewLane"></select></div>
          <button id="focusNext" class="primary" type="button">FOCUS NEXT</button>
          <button id="markLaneReviewed" type="button">MARK LANE REVIEWED</button>
          <button id="clearReviewSession" type="button">CLEAR SESSION</button>
          <button id="exportHandoff" type="button">EXPORT HANDOFF</button>
        </div>
        <div class="session-summary"><div id="reviewProgress" class="card steady"></div><div id="reviewNext" class="card steady"></div></div>
        <div id="reviewQueue" class="checks"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Change Watch</h2><p>Compares live aggregate metrics with a baseline kept only in this tab.</p></div>
        <div class="toolbar"><button id="setBaseline" type="button">SET CURRENT BASELINE</button><button id="clearBaseline" type="button">CLEAR BASELINE</button><span id="baselineStatus" class="muted">No baseline set.</span></div>
        <div id="changes" class="grid" style="margin-top:10px"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Domain Scorecards</h2><p>Five checks per domain with direct navigation to the relevant owner surface.</p></div>
        <div id="domains" class="grid"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Priority Runbook</h2><p>Failed checks become owner tasks. These instructions cannot run commands or control customer PCs.</p></div>
        <div id="runbook" class="grid"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Maintenance Window Planner</h2><p>Choose one fixed owner review plan. Schedule and calendar generation happen only in this tab.</p></div>
        <div class="planner">
          <div><label for="reviewWindow">Review window</label><select id="reviewWindow"></select></div>
          <div><label for="reviewStart">Start time, optional</label><input id="reviewStart" type="datetime-local"></div>
          <button id="copyPlan" type="button">COPY PLAN</button>
          <button id="calendar" type="button">EXPORT CALENDAR</button>
        </div>
        <div id="reviewPlan" class="card steady" style="margin-top:10px"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Owner Shortcuts</h2><p>Open the relevant aggregate or public operating surface.</p></div>
        <div id="shortcuts" class="grid"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Release, Storage, And Service</h2><p>Live aggregate configuration and signed-package verification results.</p></div>
        <div id="matrices" class="grid"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Customer Surface Matrix</h2><p>Readiness of public customer destinations without customer visits, identities, or browser progress.</p></div>
        <div id="surfaces" class="grid"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Readiness Checks</h2><p>Search and filters stay in this tab and are not uploaded.</p></div>
        <div class="filters">
          <div><label for="search">Search checks</label><input id="search" type="search" autocomplete="off" placeholder="release, storage, support..."></div>
          <div><label for="category">Category</label><select id="category"><option value="">ALL CATEGORIES</option></select></div>
          <div><label for="stateFilter">State</label><select id="stateFilter"><option value="">ALL STATES</option><option value="good">GOOD</option><option value="attention">ATTENTION</option><option value="action">ACTION</option></select></div>
          <button id="resetFilters" type="button">RESET FILTERS</button>
        </div>
        <div class="summary-strip"><span id="showing">Showing 0 of 40</span><span id="updated">Not loaded</span></div>
        <div id="checks"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Privacy Boundaries</h2><p>Hard limits for the owner console and API.</p></div>
        <div id="boundaries" class="grid"></div>
      </section>

      <section class="section">
        <div class="section-head"><h2>Limitations</h2><p>This readiness board is operational guidance, not certification or a guarantee.</p></div>
        <div id="limitations" class="grid"></div>
      </section>
    </div>
  </main>
  <footer><div>API __API_VERSION__. Safe exports exclude license keys, license ids, customer labels, email addresses, owner notes, device identifiers, receipts, report contents, file data, paths, PINs, USB secrets, and customer maintenance history.</div></footer>
  <script>
    const $=id=>document.getElementById(id);
    const state={token:"",payload:null,visible:[],baseline:null,baselineTime:"",autoTimer:null,reviewed:new Set(),activeLane:"all-actions",focusedId:""};
    const text=value=>String(value??"");
    function setStatus(message,tone=""){ $("status").textContent=message; $("status").className=`status ${tone}`; }
    function add(parent,tag,value,className=""){const node=document.createElement(tag);node.textContent=text(value);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,value){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",value);return node;}
    function card(title,detail,tone="steady",eyebrow="",next="",link=null){const node=document.createElement("article");node.className=`card ${tone}`;add(node,"div",eyebrow||tone,`eyebrow ${tone}`);add(node,"h3",title);add(node,"p",detail);if(next)add(node,"p",`Next: ${next}`,"next");if(link){const anchor=document.createElement("a");anchor.className="action-link";anchor.href=link.path;anchor.textContent=link.label;node.append(anchor);}return node;}
    function fill(rootId,items,renderer,emptyText){const root=$(rootId);root.replaceChildren();if(!items.length){const empty=document.createElement("div");empty.className="empty";empty.textContent=emptyText;root.append(empty);return;}items.forEach(item=>root.append(renderer(item)));}
    function buildCategories(categories){const select=$("category");const current=select.value;select.replaceChildren(new Option("ALL CATEGORIES",""));categories.forEach(name=>select.append(new Option(name.toUpperCase(),name)));if([...select.options].some(option=>option.value===current))select.value=current;}
    function renderBriefing(data){
      const briefing=data.briefing;
      const host=$("briefingMain");host.replaceChildren();add(host,"div",data.score.label.toUpperCase(),`eyebrow ${data.score.label==="ready"?"good":data.score.label==="attention"?"attention":"action"}`);add(host,"h3",briefing.headline);add(host,"p",briefing.summary);
      const facts=$("briefingFacts");facts.replaceChildren();
      [["Customer impact",briefing.customer_impact.toUpperCase()],["Next review",`${briefing.next_review_minutes} minutes`],["Service",briefing.service_mode.toUpperCase()],["Release",briefing.release_version||"Not published"]].forEach(([label,value])=>{const node=document.createElement("div");node.className="fact";add(node,"span",label);add(node,"strong",value);facts.append(node);});
      const severity=data.severity_summary;
      const rows=[["Completed",severity.complete,"good"],["Critical",severity.critical,severity.critical?"action":"good"],["High",severity.high,severity.high?"attention":"good"],["Medium",severity.medium,severity.medium?"attention":"good"],["Low",severity.low,severity.low?"attention":"good"]];
      fill("severity",rows,row=>card(row[0],`${row[1]} check(s)`,row[2],"SEVERITY"),"No severity data is available.");
    }
    function renderApprovalGates(data){
      fill("approvalGates",data.approval_gates,item=>{
        const detail=`${item.purpose} ${item.passed} of ${item.total} checks pass | ${item.action_count} action(s) | ${item.blocking_action_count} blocking.`;
        const node=card(item.label,detail,item.state,item.outcome.toUpperCase(),item.action_count?item.next_action:"",{path:item.owner_path,label:item.owner_path_label});
        const bar=document.createElement("div");bar.className="progress";const fillNode=document.createElement("span");fillNode.style.width=`${item.score}%`;bar.append(fillNode);node.insertBefore(bar,node.querySelector(".action-link"));return node;
      },"No approval gates are available.");
    }
    function buildReviewLanes(data){
      const select=$("reviewLane");const requested=state.activeLane||select.value||"all-actions";select.replaceChildren();
      data.review_lanes.forEach(item=>select.append(new Option(`${item.label.toUpperCase()} (${item.action_count})`,item.id)));
      state.activeLane=data.review_lanes.some(item=>item.id===requested)?requested:"all-actions";select.value=state.activeLane;
    }
    function laneQueue(){return state.payload?state.payload.decision_queue.filter(item=>item.lane_ids.includes(state.activeLane)):[];}
    function renderReviewSession(data=state.payload){
      if(!data)return;
      const currentIds=new Set(data.decision_queue.map(item=>item.id));state.reviewed=new Set([...state.reviewed].filter(id=>currentIds.has(id)));buildReviewLanes(data);
      const queue=laneQueue();const reviewedTotal=data.decision_queue.filter(item=>state.reviewed.has(item.id)).length;const progress=data.decision_queue.length?Math.round((reviewedTotal/data.decision_queue.length)*100):100;
      const progressHost=$("reviewProgress");progressHost.replaceChildren();add(progressHost,"div",`${reviewedTotal} OF ${data.decision_queue.length} REVIEWED`,`eyebrow ${reviewedTotal===data.decision_queue.length?"good":"steady"}`);add(progressHost,"h3",`${progress}% session review coverage`);add(progressHost,"p","Current-tab review marker only. Underlying owner actions remain unchanged.");const bar=document.createElement("div");bar.className="progress";const fillNode=document.createElement("span");fillNode.style.width=`${progress}%`;bar.append(fillNode);progressHost.append(bar);
      const next=queue.find(item=>!state.reviewed.has(item.id))||data.decision_queue.find(item=>!state.reviewed.has(item.id));const nextHost=$("reviewNext");nextHost.replaceChildren();add(nextHost,"div",next?next.suggested_review_window.toUpperCase():"QUEUE CLEAR",`eyebrow ${next?next.state:"good"}`);add(nextHost,"h3",next?next.title:"No unreviewed owner actions");add(nextHost,"p",next?next.action:"Every current decision-queue item is marked reviewed in this tab.");
      fill("reviewQueue",queue,item=>{
        const reviewed=state.reviewed.has(item.id);const node=document.createElement("article");node.className=`card ${item.state} review-card${reviewed?" reviewed":""}${state.focusedId===item.id?" focused":""}`;node.dataset.reviewId=item.id;
        const toggle=document.createElement("div");toggle.className="review-toggle";const box=document.createElement("input");box.type="checkbox";box.id=`review-${item.id}`;box.checked=reviewed;const label=document.createElement("label");label.htmlFor=box.id;label.textContent=item.title;toggle.append(box,label);node.append(toggle);
        add(node,"div",`#${item.sequence} | ${item.priority} | ${item.suggested_review_window}`,`eyebrow ${item.state}`);add(node,"p",item.detail);add(node,"p",`Next: ${item.action}`,"next");const link=document.createElement("a");link.className="action-link";link.href=item.owner_path;link.textContent=item.owner_path_label;node.append(link);
        box.addEventListener("change",()=>{if(box.checked)state.reviewed.add(item.id);else state.reviewed.delete(item.id);state.focusedId="";renderReviewSession();});return node;
      },"No failed checks are in this review lane.");
    }
    function renderChanges(data){
      const baseline=state.baseline;
      if(!baseline){$("baselineStatus").textContent="No baseline set. Choose SET CURRENT BASELINE.";fill("changes",[],()=>null,"Set a current-tab baseline to compare future refreshes.");return;}
      $("baselineStatus").textContent=`Baseline set ${new Date(state.baselineTime).toLocaleString()}.`;
      const baselineMap=new Map(baseline.map(item=>[item.id,item]));
      fill("changes",data.watch_metrics,item=>{
        const old=baselineMap.get(item.id);
        if(!old)return card(item.label,`${item.value} ${item.unit}`,"steady","NEW METRIC");
        const delta=Number(item.value)-Number(old.value);
        const improved=delta!==0&&(item.better==="higher"?delta>0:delta<0);
        const tone=delta===0?"steady":improved?"improved":"worse";
        const prefix=delta>0?"+":"";
        return card(item.label,`${item.value} ${item.unit} | baseline ${old.value} | delta ${prefix}${delta}`,tone,delta===0?"NO CHANGE":improved?"IMPROVED":"WORSE");
      },"No watch metrics are available.");
    }
    function renderDomains(data){
      fill("domains",data.category_summary,item=>{
        const node=card(item.category,`${item.passed} of ${item.total} checks pass | ${item.actions} action(s) | ${item.critical_actions} critical | ${item.high_actions} high`,item.state,`${item.score} / 100`,"",{path:item.owner_path,label:item.owner_path_label});
        const bar=document.createElement("div");bar.className="progress";const fillNode=document.createElement("span");fillNode.style.width=`${item.score}%`;bar.append(fillNode);node.insertBefore(bar,node.querySelector(".action-link"));return node;
      },"No domain scores are available.");
    }
    function renderRunbook(data){
      fill("runbook",data.runbook,item=>card(item.title,item.detail,item.state,`${item.category} | ${item.priority}`,item.action,{path:item.owner_path,label:item.owner_path_label}),"Every fixed owner operations check currently passes.");
    }
    function renderPlanner(data){
      const select=$("reviewWindow");const current=select.value;select.replaceChildren();
      data.review_windows.forEach(item=>select.append(new Option(`${item.label} - ${item.purpose}`,item.id)));
      if(data.review_windows.some(item=>item.id===current))select.value=current;
      renderSelectedPlan();
    }
    function selectedPlan(){return state.payload?.review_windows.find(item=>item.id===$("reviewWindow").value)||state.payload?.review_windows[0]||null;}
    function renderSelectedPlan(){
      const plan=selectedPlan();const host=$("reviewPlan");host.replaceChildren();
      if(!plan){add(host,"p","No review plan is available.");return;}
      add(host,"div",`${plan.minutes} MINUTES`,"eyebrow steady");add(host,"h3",plan.label);add(host,"p",plan.purpose);
      const list=document.createElement("ol");list.className="plan-steps";plan.steps.forEach(step=>add(list,"li",step));host.append(list);
    }
    function renderShortcuts(data){
      fill("shortcuts",data.owner_shortcuts,item=>card(item.label,item.purpose,"steady","OWNER SURFACE","",{path:item.path,label:`OPEN ${item.label.toUpperCase()}`}),"No owner shortcuts are available.");
    }
    function renderMatrices(data){
      const release=data.release_gate;
      const rows=[
        {title:"Desktop release",detail:release.ready?`${release.version} | ${release.package_filename}`:release.message,state:release.ready?"good":"action",eyebrow:"SIGNED RELEASE"},
        {title:"Manifest signature",detail:`Ed25519: ${release.checks.ed25519_signature}`,state:release.checks.ed25519_signature==="passed"?"good":"action",eyebrow:release.signing_key_id||"SIGNING KEY"},
        {title:"Package integrity",detail:`SHA-256 ${release.checks.package_sha256} | size ${release.checks.package_size}`,state:release.checks.package_sha256==="passed"&&release.checks.package_size==="passed"?"good":"action",eyebrow:"PACKAGE"},
        {title:"App-data preservation",detail:release.checks.app_data_preservation,state:release.checks.app_data_preservation==="passed"?"good":"action",eyebrow:"UPDATE BOUNDARY"},
        {title:"Service status",detail:`${data.service_status.mode.toUpperCase()} | ${data.service_status.message}`,state:data.service_status.mode==="normal"?"good":"attention",eyebrow:"PUBLIC STATUS"},
        ...data.storage_matrix.map(item=>({title:item.label,detail:item.status,state:item.persistent?"good":"action",eyebrow:"STORAGE"}))
      ];
      fill("matrices",rows,item=>card(item.title,item.detail,item.state,item.eyebrow),"No matrix data is available.");
    }
    function render(data){
      state.payload=data;
      const score=data.score;
      const metrics=$("metrics");metrics.replaceChildren();
      [["Readiness",`${score.value} / 100`],["Checks",`${score.passed} / ${score.total}`],["Owner actions",data.runbook.length],["Persistent stores",`${data.metrics.persistent_stores} / ${data.metrics.total_stores}`],["Customer surfaces",`${data.metrics.ready_surfaces} / ${data.metrics.total_surfaces}`],["Release adoption",`${data.metrics.release_adoption_percent}%`],["Support queue",data.metrics.support_needs_action],["High/Critical",data.metrics.high_critical_audits]].forEach(row=>metrics.append(metric(...row)));
      renderBriefing(data);renderApprovalGates(data);renderReviewSession(data);renderChanges(data);renderDomains(data);renderRunbook(data);renderPlanner(data);renderShortcuts(data);renderMatrices(data);
      fill("surfaces",data.customer_surfaces,item=>card(item.label,`${item.path} | ${item.purpose}`,item.ready?"good":"attention",item.ready?"READY":"CHECK","",{path:item.path,label:"OPEN SURFACE"}),"No customer surface data is available.");
      buildCategories(data.categories);
      $("updated").textContent=`Updated ${new Date(data.server_time_utc).toLocaleString()}`;
      fill("boundaries",data.privacy_boundaries.map((detail,index)=>({detail,index})),item=>card(`Boundary ${item.index+1}`,item.detail,"good","ENFORCED"),"No privacy boundaries were returned.");
      fill("limitations",data.limitations.map((detail,index)=>({detail,index})),item=>card(`Limitation ${item.index+1}`,item.detail,"attention","READ THIS"),"No limitations were returned.");
      $("console").hidden=false;renderChecks();
      setStatus(`Owner operations loaded. ${score.passed} of ${score.total} checks pass.`,score.label==="action"?"bad":"good");
    }
    function filteredChecks(){
      if(!state.payload)return[];
      const query=$("search").value.trim().toLowerCase();const category=$("category").value;const tone=$("stateFilter").value;
      return state.payload.checks.filter(item=>{const haystack=`${item.title} ${item.detail} ${item.action} ${item.category}`.toLowerCase();return(!query||haystack.includes(query))&&(!category||item.category===category)&&(!tone||item.state===tone);});
    }
    function renderChecks(){
      state.visible=filteredChecks();$("showing").textContent=`Showing ${state.visible.length} of 40`;const root=$("checks");root.replaceChildren();
      if(!state.visible.length){const empty=document.createElement("div");empty.className="empty";empty.textContent="No checks match those filters.";root.append(empty);return;}
      const groups=new Map();state.visible.forEach(item=>{if(!groups.has(item.category))groups.set(item.category,[]);groups.get(item.category).push(item);});
      groups.forEach((items,category)=>{const section=document.createElement("section");section.className="category";const head=document.createElement("div");head.className="category-head";add(head,"strong",category);add(head,"span",`${items.filter(item=>item.passed).length} of ${items.length} visible checks pass`);const grid=document.createElement("div");grid.className="checks";items.forEach(item=>grid.append(card(item.title,item.detail,item.state,`${item.state} | ${item.priority}`,item.passed?"":item.action,{path:item.owner_path,label:item.owner_path_label})));section.append(head,grid);root.append(section);});
    }
    async function load(silent=false){
      if(!state.token){setStatus("Enter the owner admin token.","bad");return;}
      $("connect").disabled=true;
      try{
        const response=await fetch("/api/v1/admin/maintenance-operations",{headers:{"X-License-Admin-Token":state.token,"Accept":"application/json"},cache:"no-store",redirect:"error"});
        const data=await response.json().catch(()=>({}));
        if(!response.ok)throw new Error(data.message||"Owner operations could not be loaded.");
        if(data.operations_schema_version!==3||data.check_count!==40||!Array.isArray(data.checks)||data.approval_gates?.length!==6||data.review_lanes?.length!==5)throw new Error("The API did not return the complete owner operations contract.");
        render(data);if(!silent)setStatus(`Owner operations loaded. ${data.score.passed} of ${data.score.total} checks pass.`,data.score.label==="action"?"bad":"good");
      }catch(error){state.payload=null;state.visible=[];$("console").hidden=true;setStatus(error.message||"Owner operations could not be loaded.","bad");}
      finally{$("connect").disabled=false;}
    }
    function connect(){state.token=$("token").value.trim();load();}
    function clear(){state.token="";state.payload=null;state.visible=[];state.baseline=null;state.baselineTime="";state.reviewed.clear();state.activeLane="all-actions";state.focusedId="";$("token").value="";$("console").hidden=true;$("autoRefresh").checked=false;stopAutoRefresh();setStatus("Owner token, report, baseline, and current-tab review session cleared.");}
    function download(name,body,type){const blob=new Blob([body],{type});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
    function briefingText(){
      if(!state.payload)return"";
      const p=state.payload;const lines=[`VaultLink Owner Operations`,`${p.briefing.headline}`,p.briefing.summary,`Customer impact: ${p.briefing.customer_impact}`,`Next review: ${p.briefing.next_review_minutes} minutes`,`Service: ${p.briefing.service_mode}`,`Release: ${p.briefing.release_version||"not published"}`,"","Approval gates",...p.approval_gates.map(item=>`${item.label}: ${item.outcome.toUpperCase()} | ${item.passed}/${item.total}`),"",`Priority runbook (${p.runbook.length})`];
      if(!p.runbook.length)lines.push("No owner actions are currently required.");else p.runbook.forEach((item,index)=>lines.push(`${index+1}. [${item.priority.toUpperCase()}] ${item.title}: ${item.action}`));
      lines.push("","Operational guidance only. No customer records, secrets, files, paths, or maintenance history are included.");return lines.join("\n");
    }
    function copyBriefing(){if(!state.payload)return;navigator.clipboard.writeText(briefingText()).then(()=>setStatus("Owner briefing copied.","good")).catch(()=>setStatus("Clipboard access was blocked.","bad"));}
    function exportText(){if(!state.payload)return;download("vaultlink-owner-operations-briefing.txt",briefingText(),"text/plain");setStatus("Privacy-safe owner briefing exported.","good");}
    function exportJson(){if(!state.payload)return;download("vaultlink-owner-maintenance-operations.json",JSON.stringify(state.payload,null,2),"application/json");setStatus("Privacy-safe owner operations report exported.","good");}
    function exportCsv(){if(!state.payload)return;const rows=[["id","category","title","state","passed","priority","detail","action","owner_path"],...state.payload.checks.map(item=>[item.id,item.category,item.title,item.state,item.passed,item.priority,item.detail,item.action,item.owner_path])];const csv=rows.map(row=>row.map(value=>`"${text(value).replaceAll('"','""')}"`).join(",")).join("\r\n");download("vaultlink-owner-maintenance-checks.csv",csv,"text/csv");setStatus("Owner maintenance checks exported.","good");}
    async function exportReceipt(){
      if(!state.payload)return;
      const p=state.payload;
      const payload={schema_version:2,generated_at_utc:new Date().toISOString(),source_server_time_utc:p.server_time_utc,api_version:p.api_version,operations_schema_version:p.operations_schema_version,score:p.score,severity_summary:p.severity_summary,approval_gates:p.approval_gates.map(item=>({id:item.id,outcome:item.outcome,passed:item.passed,total:item.total,action_count:item.action_count})),review_session:{lane_id:state.activeLane,reviewed_ids:[...state.reviewed].sort(),total_actions:p.decision_queue.length},watch_metrics:p.watch_metrics,checks:p.checks.map(item=>({id:item.id,category:item.category,passed:item.passed,state:item.state,priority:item.priority})),privacy:"Aggregate fixed results and current-tab fixed IDs only; no admin token, customer record, license proof, file, path, PIN, or USB secret."};
      const canonical=JSON.stringify(payload);const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(canonical));const sha256=[...new Uint8Array(digest)].map(value=>value.toString(16).padStart(2,"0")).join("");
      download("vaultlink-owner-operations-sha256-receipt.json",JSON.stringify({receipt_schema_version:2,algorithm:"SHA-256",sha256,payload},null,2),"application/json");setStatus(`SHA-256 evidence receipt exported: ${sha256.slice(0,16)}...`,"good");
    }
    function focusNext(){const next=laneQueue().find(item=>!state.reviewed.has(item.id));if(!next){setStatus("Every action in this lane is marked reviewed in this tab.","good");return;}state.focusedId=next.id;renderReviewSession();const node=[...document.querySelectorAll("[data-review-id]")].find(item=>item.dataset.reviewId===next.id);if(node){node.scrollIntoView({behavior:"smooth",block:"center"});node.querySelector("input")?.focus();}setStatus(`Focused next owner action: ${next.title}`);}
    function markLaneReviewed(){const queue=laneQueue();queue.forEach(item=>state.reviewed.add(item.id));state.focusedId="";renderReviewSession();setStatus(`${queue.length} action(s) in this lane are marked reviewed for this tab only.`,"good");}
    function clearReviewSession(){state.reviewed.clear();state.focusedId="";renderReviewSession();setStatus("Current-tab owner review session cleared.");}
    function handoffText(){if(!state.payload)return"";const p=state.payload;const lines=["VaultLink Owner Review Handoff",`Generated: ${new Date().toISOString()}`,`Source server time: ${p.server_time_utc}`,`Readiness: ${p.score.value} / 100`,`Current lane: ${state.activeLane}`,`Reviewed in this tab: ${state.reviewed.size} of ${p.decision_queue.length}`,"","Approval gates",...p.approval_gates.map(item=>`${item.label}: ${item.outcome.toUpperCase()} | ${item.passed}/${item.total}`),"","Decision queue"];
      if(!p.decision_queue.length)lines.push("No failed fixed checks are currently queued.");else p.decision_queue.forEach(item=>lines.push(`${state.reviewed.has(item.id)?"REVIEWED":"OPEN"} | ${item.priority.toUpperCase()} | ${item.id} | ${item.title} | ${item.suggested_review_window}`));lines.push("","Review marks are current-tab notes only and do not prove remediation. No token, customer record, license proof, file, path, PIN, USB secret, or free-form note is included.");return lines.join("\n");}
    function exportHandoff(){if(!state.payload)return;download("vaultlink-owner-review-handoff.txt",handoffText(),"text/plain");setStatus("Privacy-safe fixed-field owner handoff exported.","good");}
    function setBaseline(){if(!state.payload)return;state.baseline=state.payload.watch_metrics.map(item=>({...item}));state.baselineTime=new Date().toISOString();renderChanges(state.payload);setStatus("Current-tab change baseline set.","good");}
    function clearBaseline(){state.baseline=null;state.baselineTime="";if(state.payload)renderChanges(state.payload);setStatus("Current-tab change baseline cleared.");}
    function selectedStart(){const raw=$("reviewStart").value;if(raw){const parsed=new Date(raw);if(!Number.isNaN(parsed.getTime()))return parsed;}return new Date(Date.now()+5*60*1000);}
    function copyPlan(){const plan=selectedPlan();if(!plan)return;const lines=[plan.label,plan.purpose,...plan.steps.map((step,index)=>`${index+1}. ${step}`),"","Fixed owner plan only. No customer data or free-form note is included."];navigator.clipboard.writeText(lines.join("\n")).then(()=>setStatus("Fixed maintenance plan copied.","good")).catch(()=>setStatus("Clipboard access was blocked.","bad"));}
    function icsTime(date){return date.toISOString().replace(/[-:]/g,"").replace(/\.\d{3}Z$/,"Z");}
    function icsEscape(value){return text(value).replaceAll("\\","\\\\").replaceAll("\n","\\n").replaceAll(",","\\,").replaceAll(";","\\;");}
    function exportCalendar(){const plan=selectedPlan();if(!plan)return;const start=selectedStart();const end=new Date(start.getTime()+plan.minutes*60*1000);const description=[plan.purpose,...plan.steps.map((step,index)=>`${index+1}. ${step}`)].join("\n");const body=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//VaultLink//Owner Operations//EN","CALSCALE:GREGORIAN","BEGIN:VEVENT",`UID:vaultlink-${plan.id}-${Date.now()}@local`,`DTSTAMP:${icsTime(new Date())}`,`DTSTART:${icsTime(start)}`,`DTEND:${icsTime(end)}`,`SUMMARY:${icsEscape(`VaultLink ${plan.label}`)}`,`DESCRIPTION:${icsEscape(description)}`,"END:VEVENT","END:VCALENDAR",""].join("\r\n");download(`vaultlink-${plan.id}.ics`,body,"text/calendar");setStatus("Fixed owner review calendar exported.","good");}
    function stopAutoRefresh(){if(state.autoTimer){clearInterval(state.autoTimer);state.autoTimer=null;}}
    function toggleAutoRefresh(){stopAutoRefresh();if($("autoRefresh").checked){state.autoTimer=setInterval(()=>{if(state.token)load(true);},60000);setStatus("Auto refresh enabled for this tab every 60 seconds.","good");}else setStatus("Auto refresh disabled.");}
    function resetFilters(){$("search").value="";$("category").value="";$("stateFilter").value="";renderChecks();}
    $("connect").addEventListener("click",connect);$("clear").addEventListener("click",clear);$("refresh").addEventListener("click",()=>load());$("autoRefresh").addEventListener("change",toggleAutoRefresh);$("copyBriefing").addEventListener("click",copyBriefing);$("textExport").addEventListener("click",exportText);$("json").addEventListener("click",exportJson);$("csv").addEventListener("click",exportCsv);$("receipt").addEventListener("click",()=>exportReceipt().catch(error=>setStatus(error.message||"Receipt export failed.","bad")));$("print").addEventListener("click",()=>window.print());$("focusNext").addEventListener("click",focusNext);$("markLaneReviewed").addEventListener("click",markLaneReviewed);$("clearReviewSession").addEventListener("click",clearReviewSession);$("exportHandoff").addEventListener("click",exportHandoff);$("reviewLane").addEventListener("change",()=>{state.activeLane=$("reviewLane").value;state.focusedId="";renderReviewSession();});$("setBaseline").addEventListener("click",setBaseline);$("clearBaseline").addEventListener("click",clearBaseline);$("reviewWindow").addEventListener("change",renderSelectedPlan);$("copyPlan").addEventListener("click",copyPlan);$("calendar").addEventListener("click",exportCalendar);$("search").addEventListener("input",renderChecks);$("category").addEventListener("change",renderChecks);$("stateFilter").addEventListener("change",renderChecks);$("resetFilters").addEventListener("click",resetFilters);$("token").addEventListener("keydown",event=>{if(event.key==="Enter")connect();});window.addEventListener("beforeunload",stopAutoRefresh);
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))
