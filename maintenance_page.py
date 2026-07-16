import html


def customer_maintenance_html(api_version):
    page = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>VaultLink Security Maintenance</title>
  <style>
    :root{--bg:#0b1013;--band:#11181d;--surface:#182229;--surface2:#202c34;--field:#070a0c;--line:#354650;--text:#f4f7f8;--muted:#a8b7bf;--green:#58e28a;--blue:#5fc4e8;--yellow:#ffd166;--red:#ff7e78}
    *{box-sizing:border-box}
    html{background:var(--bg);color:var(--text);font-family:Segoe UI,Arial,sans-serif;letter-spacing:0}
    body{margin:0;min-width:0;background:var(--bg)}
    button,select{font:inherit;letter-spacing:0}
    header{border-bottom:1px solid var(--line);background:var(--band)}
    header>div,main,footer>div{width:min(1280px,calc(100% - 32px));margin:auto}
    header>div{display:flex;align-items:center;justify-content:space-between;gap:18px;min-height:64px}
    .brand{font-size:1rem;font-weight:800}
    nav{display:flex;flex-wrap:wrap;gap:8px}
    nav a{padding:8px 9px;border:1px solid var(--line);border-radius:5px;color:var(--text);font-size:.72rem;font-weight:800;text-decoration:none}
    main{padding:32px 0 48px}
    h1{margin:0;font-size:2rem;line-height:1.1}
    h2{margin:0;font-size:1.2rem}
    h3{margin:0;font-size:1rem}
    p{color:var(--muted);line-height:1.5}
    .lead{max-width:940px;margin:9px 0 0}
    .privacy{margin:18px 0;padding:14px 16px;border-left:4px solid var(--green);background:var(--band);color:var(--muted);line-height:1.5}
    .controls{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:8px;align-items:end;padding:14px;border:1px solid var(--line);background:var(--band)}
    .controls>div{grid-column:span 2}
    label,.eyebrow{display:block;margin-bottom:6px;color:var(--yellow);font-size:.68rem;font-weight:800;text-transform:uppercase}
    select,button{min-height:40px;border:1px solid var(--line);border-radius:5px}
    select{width:100%;padding:0 10px;background:var(--field);color:var(--text)}
    button{padding:0 11px;background:#273640;color:var(--text);font-size:.72rem;font-weight:800;cursor:pointer}
    button.primary{background:var(--green);color:#031009;border-color:var(--green)}
    button.blue{background:var(--blue);color:#031014;border-color:var(--blue)}
    button.export{background:var(--yellow);color:#171100;border-color:var(--yellow)}
    button:disabled,select:disabled{cursor:not-allowed;opacity:.45}
    .status{min-height:34px;padding:10px 0;color:var(--muted)}
    .status.good{color:var(--green)}
    .status.bad{color:var(--red)}
    .metrics{display:grid;grid-template-columns:repeat(8,minmax(0,1fr));margin:3px 0 22px;border:1px solid var(--line)}
    .metric{min-width:0;padding:13px;border-right:1px solid var(--line)}
    .metric:last-child{border-right:0}
    .metric span{display:block;color:var(--muted);font-size:.65rem;font-weight:700;text-transform:uppercase}
    .metric strong{display:block;margin-top:6px;overflow-wrap:anywhere;font-size:.95rem}
    .dashboard{display:grid;grid-template-columns:1fr 1fr 320px;gap:12px;margin-bottom:22px}
    .dashboard-section{padding-top:16px;border-top:1px solid var(--line)}
    .coverage-list,.priority-list,.stack{display:grid;gap:8px;margin-top:10px}
    .coverage-row,.priority-row{padding:11px;border:1px solid var(--line);border-radius:7px;background:var(--surface)}
    .coverage-head{display:flex;align-items:center;justify-content:space-between;gap:12px;font-size:.82rem;font-weight:700}
    .bar{height:8px;margin-top:8px;background:var(--field);border:1px solid var(--line);border-radius:4px;overflow:hidden}
    .bar>span{display:block;height:100%;background:var(--green)}
    .priority-row{display:grid;grid-template-columns:auto minmax(0,1fr);gap:10px}
    .priority-number{color:var(--yellow);font-weight:800}
    .priority-row p{margin:4px 0 0;font-size:.78rem}
    .layout{display:block}
    .section{padding-top:20px;border-top:1px solid var(--line)}
    .section-head{display:flex;align-items:end;justify-content:space-between;gap:20px;margin-bottom:12px}
    .section-head p{max-width:620px;margin:0;text-align:right}
    .tasks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
    .task{display:grid;grid-template-columns:auto minmax(0,1fr);gap:12px;min-width:0;padding:15px;border:1px solid var(--line);border-radius:7px;background:var(--surface)}
    .task.reviewed{border-color:var(--green);background:#14231c}
    .task.priority{border-left:4px solid var(--yellow)}
    .task input{width:19px;height:19px;margin:2px 0 0;accent-color:var(--green)}
    .task p{margin:7px 0 0;font-size:.86rem}
    .task-meta{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:5px}
    .tag{padding:3px 6px;border:1px solid var(--line);border-radius:4px;color:var(--blue);font-size:.64rem;font-weight:800;text-transform:uppercase}
    .due{color:var(--yellow)}
    .expected{margin-top:10px;padding-top:9px;border-top:1px solid var(--line);color:var(--muted);font-size:.8rem;line-height:1.4}
    .expected strong{color:var(--yellow)}
    .sidebar{display:block;margin-top:20px}
    .sidebar .section{margin-top:18px}
    #routines{grid-template-columns:repeat(3,minmax(0,1fr))}
    #boundaries,#limitations{grid-template-columns:repeat(2,minmax(0,1fr))}
    .routine,.boundary{padding:14px;border:1px solid var(--line);border-radius:7px;background:var(--surface)}
    .routine.active{border-color:var(--blue)}
    .routine button{width:100%;margin-top:9px}
    .routine p,.boundary p{margin:7px 0 0;font-size:.84rem}
    .boundary{border-top:3px solid var(--yellow)}
    .empty{padding:24px;border:1px dashed var(--line);color:var(--muted);text-align:center}
    footer{border-top:1px solid var(--line);background:var(--band)}
    footer>div{padding:20px 0;color:var(--muted);font-size:.82rem;line-height:1.45}
    @media(max-width:1180px){
      .controls{grid-template-columns:repeat(4,minmax(0,1fr))}
      .dashboard{grid-template-columns:1fr 1fr}
      .dashboard-section:last-child{grid-column:1/-1}
      #routines{grid-template-columns:repeat(2,minmax(0,1fr))}
      .metrics{grid-template-columns:repeat(4,minmax(0,1fr))}
      .metric:nth-child(4),.metric:nth-child(8){border-right:0}
    }
    @media(max-width:700px){
      header>div{align-items:flex-start;flex-direction:column;padding:14px 0}
      main{padding-top:24px}
      h1{font-size:1.65rem}
      .controls,.metrics,.dashboard,.tasks,#routines,#boundaries,#limitations{grid-template-columns:1fr}
      .controls>div,.dashboard-section:last-child{grid-column:auto}
      .controls button{width:100%}
      .metric{border-right:0;border-bottom:1px solid var(--line)}
      .metric:last-child{border-bottom:0}
      .section-head{align-items:flex-start;flex-direction:column}
      .section-head p{text-align:left}
    }
  </style>
</head>
<body>
  <header><div><div class="brand">VaultLink Security Maintenance</div><nav><a href="/workspace">WORKSPACE</a><a href="/retention">RETENTION</a><a href="/data-control">DATA</a><a href="/recovery-kit">KIT</a><a href="/backup-verification">BACKUPS</a><a href="/diagnostics">DIAGNOSTICS</a><a href="/trust">TRUST</a><a href="/status">STATUS</a></nav></div></header>
  <main>
    <h1>Maintenance planner</h1>
    <p class="lead">Review fixed defensive tasks by category, routine, and cadence horizon.</p>
    <div class="privacy">Review state and coverage calculations exist only in the current tab and disappear on reload. They are reminder coverage, not security-health results. This page cannot inspect a PC, run a scan, change Windows, complete a task remotely, or receive desktop history or snapshots.</div>
    <div class="controls">
      <div><label for="category">Category</label><select id="category" disabled></select></div>
      <div><label for="routine">Routine</label><select id="routine" disabled></select></div>
      <div><label for="horizon">Cadence horizon</label><select id="horizon" disabled></select></div>
      <button id="reset" type="button" disabled>RESET</button>
      <button id="next" class="primary" type="button" disabled>REVIEW NEXT</button>
      <button id="priority" class="export" type="button" disabled>REVIEW PRIORITY 5</button>
      <button id="routineAll" class="blue" type="button" disabled>REVIEW ROUTINE</button>
      <button id="visibleAll" type="button" disabled>REVIEW VISIBLE</button>
      <button id="copy" type="button" disabled>COPY</button>
      <button id="calendar" type="button" disabled>CALENDAR</button>
      <button id="print" type="button" disabled>PRINT</button>
      <button id="export" class="export" type="button" disabled>EXPORT JSON</button>
    </div>
    <div id="status" class="status" role="status" aria-live="polite">Loading the fixed maintenance guide...</div>
    <div id="workspace" hidden>
      <div id="metrics" class="metrics"></div>
      <div class="dashboard">
        <section class="dashboard-section"><div class="eyebrow">CATEGORY COVERAGE</div><h2>Eight fixed areas</h2><div id="categoryCoverage" class="coverage-list"></div></section>
        <section class="dashboard-section"><div class="eyebrow">ROUTINE COVERAGE</div><h2>Six fixed routines</h2><div id="routineCoverage" class="coverage-list"></div></section>
        <section class="dashboard-section"><div class="eyebrow">PRIORITY QUEUE</div><h2>Next fixed reviews</h2><div id="priorityQueue" class="priority-list"></div></section>
      </div>
      <div class="layout">
        <section class="section"><div class="section-head"><div><div class="eyebrow">CURRENT-TAB REVIEW</div><h2>Maintenance tasks</h2></div><p>Checking a task is a browser review marker only. Desktop completion dates and snapshots remain local.</p></div><div id="tasks" class="tasks"></div></section>
        <aside class="sidebar">
          <section class="section"><div class="eyebrow">FIXED ROUTINES</div><h2>Routine map</h2><div id="routines" class="stack"></div></section>
          <section class="section"><div class="eyebrow">PRIVACY BOUNDARIES</div><div id="boundaries" class="stack"></div></section>
          <section class="section"><div class="eyebrow">LIMITATIONS</div><div id="limitations" class="stack"></div></section>
        </aside>
      </div>
    </div>
  </main>
  <footer><div>API __API_VERSION__. No browser storage, progress submission, snapshot upload, schedule-score upload, account, license proof, path, file, local result, maintenance command, or free-form note API is used.</div></footer>
  <script>
    const $=id=>document.getElementById(id);
    const state={payload:null,category:"all",routine:"all",horizon:"all",reviewed:new Set()};
    const value=input=>String(input??"");
    function add(parent,tag,text,className=""){const node=document.createElement(tag);node.textContent=value(text);if(className)node.className=className;parent.append(node);return node;}
    function setStatus(text,tone=""){$("status").textContent=text;$("status").className=`status ${tone}`;}
    function metric(label,text){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",text);return node;}
    function knownIds(){return new Set((state.payload?.tasks||[]).map(item=>item.id));}
    function selectedRoutine(){return(state.payload?.routines||[]).find(item=>item.id===state.routine)||null;}
    function routineIds(){const item=selectedRoutine();return item?new Set(item.task_ids):knownIds();}
    function horizonMax(){const item=(state.payload?.planning_horizons||[]).find(row=>row.id===state.horizon);return item?Number(item.maximum_cadence_days||0):0;}
    function categoryTitle(id){return(state.payload.categories.find(item=>item.id===id)||{}).title||id;}
    function taskOrder(items){return [...items].sort((a,b)=>Number(state.reviewed.has(a.id))-Number(state.reviewed.has(b.id))||a.cadence_days-b.cadence_days||a.id.localeCompare(b.id));}
    function visibleTasks(){let items=state.payload?.tasks||[];if(state.category!=="all")items=items.filter(item=>item.category_id===state.category);if(state.routine!=="all"){const allowed=routineIds();items=items.filter(item=>allowed.has(item.id));}const maximum=horizonMax();if(maximum>0)items=items.filter(item=>item.cadence_days<=maximum);return taskOrder(items);}
    function coverage(ids){const valid=[...ids].filter(id=>knownIds().has(id));const reviewed=valid.filter(id=>state.reviewed.has(id)).length;return{reviewed,total:valid.length,percent:valid.length?Math.round(reviewed/valid.length*100):0};}
    function categoryRows(){return state.payload.categories.map(item=>{const ids=state.payload.tasks.filter(task=>task.category_id===item.id).map(task=>task.id);return{...item,...coverage(ids)};});}
    function routineRows(){return state.payload.routines.map(item=>({...item,...coverage(item.task_ids)}));}
    function fullyReviewed(rows){return rows.filter(item=>item.total>0&&item.reviewed===item.total).length;}
    function safeReceipt(){const known=knownIds();const reviewed=[...state.reviewed].filter(id=>known.has(id)).sort();const categories=categoryRows();const routines=routineRows();return{schema_version:2,report_type:"VaultLink Privacy-Safe Browser Maintenance Review",generated_at_utc:new Date().toISOString(),api_version:state.payload.api_version,service_mode:state.payload.service_status.mode,signed_desktop_version:state.payload.signed_release.version||"",selected_category_id:state.category,selected_routine_id:state.routine,selected_horizon_id:state.horizon,reviewed_task_ids:reviewed,reviewed_count:reviewed.length,task_count:known.size,review_percent:known.size?Math.round(reviewed.length/known.size*100):0,reviewed_category_count:fullyReviewed(categories),reviewed_routine_count:fullyReviewed(routines),privacy_notice:"No name, contact, license proof, receipt, key, PIN, USB secret, path, filename, file content, local result, completion time, snapshot, customer record, screenshot, process list, or free-form note is included."};}
    function renderMetrics(){const root=$("metrics");root.replaceChildren();const report=safeReceipt();const visible=visibleTasks();[["API",state.payload.api_version],["Service",state.payload.service_status.mode],["Signed desktop",state.payload.signed_release.version||"Not published"],["Visible",visible.length],["Reviewed",`${report.reviewed_count} / ${report.task_count}`],["Review %",`${report.review_percent}%`],["Categories",`${report.reviewed_category_count} / ${state.payload.category_count}`],["Routines",`${report.reviewed_routine_count} / ${state.payload.routine_count}`]].forEach(row=>root.append(metric(...row)));setStatus(`${visible.length} fixed task(s) visible. Review percentage is current-tab reminder coverage only.`,"good");}
    function renderCoverage(){const renderRows=(rootId,rows)=>{const root=$(rootId);root.replaceChildren();rows.forEach(item=>{const card=document.createElement("article");card.className="coverage-row";const head=document.createElement("div");head.className="coverage-head";add(head,"span",item.title||item.label);add(head,"span",`${item.reviewed}/${item.total} | ${item.percent}%`);const bar=document.createElement("div");bar.className="bar";const fill=document.createElement("span");fill.style.width=`${item.percent}%`;bar.append(fill);card.append(head,bar);root.append(card);});};renderRows("categoryCoverage",categoryRows());renderRows("routineCoverage",routineRows());}
    function renderPriority(){const root=$("priorityQueue");root.replaceChildren();const items=taskOrder(state.payload.tasks).filter(item=>!state.reviewed.has(item.id)).slice(0,8);if(!items.length){add(root,"div","Every fixed task is reviewed in this tab.","empty");return;}items.forEach((item,index)=>{const row=document.createElement("article");row.className="priority-row";add(row,"div",String(index+1),"priority-number");const body=document.createElement("div");add(body,"strong",item.title);add(body,"p",`${categoryTitle(item.category_id)} | ${item.cadence_days} days`);row.append(body);root.append(row);});}
    function renderTasks(){const root=$("tasks");root.replaceChildren();const items=visibleTasks();const priorities=new Set(taskOrder(state.payload.tasks).filter(item=>!state.reviewed.has(item.id)).slice(0,5).map(item=>item.id));if(!items.length){add(root,"div","No fixed tasks match this plan.","empty");}items.forEach(item=>{const card=document.createElement("article");card.className=`task ${state.reviewed.has(item.id)?"reviewed":""} ${priorities.has(item.id)?"priority":""}`;const box=document.createElement("input");box.type="checkbox";box.checked=state.reviewed.has(item.id);box.setAttribute("aria-label",`Review ${item.title}`);box.addEventListener("change",()=>{box.checked?state.reviewed.add(item.id):state.reviewed.delete(item.id);renderAll();});const body=document.createElement("div");const meta=document.createElement("div");meta.className="task-meta";add(meta,"span",categoryTitle(item.category_id),"tag");add(meta,"span",`${item.cadence_days} DAYS`,"tag due");body.append(meta);add(body,"h3",item.title);add(body,"p",item.action);const expected=document.createElement("div");expected.className="expected";add(expected,"strong","Expected: ");expected.append(document.createTextNode(item.expected));body.append(expected);card.append(box,body);root.append(card);});}
    function renderRoutines(){const root=$("routines");root.replaceChildren();state.payload.routines.forEach(item=>{const card=document.createElement("article");card.className=`routine ${state.routine===item.id?"active":""}`;const row=coverage(item.task_ids);add(card,"h3",item.label);add(card,"p",item.summary);add(card,"div",`${row.reviewed}/${row.total} reviewed | ${row.percent}%`,"expected");const button=add(card,"button","USE ROUTINE");button.type="button";button.addEventListener("click",()=>{state.routine=item.id;$("routine").value=item.id;renderAll();});card.append(button);root.append(card);});}
    function renderAll(){renderTasks();renderCoverage();renderPriority();renderRoutines();renderMetrics();}
    function render(data){state.payload=data;const category=$("category");category.replaceChildren();[["all","All categories"],...data.categories.map(item=>[item.id,item.title])].forEach(([id,label])=>{const option=document.createElement("option");option.value=id;option.textContent=label;category.append(option);});const routine=$("routine");routine.replaceChildren();[["all","All tasks"],...data.routines.map(item=>[item.id,item.label])].forEach(([id,label])=>{const option=document.createElement("option");option.value=id;option.textContent=label;routine.append(option);});const horizon=$("horizon");horizon.replaceChildren();data.planning_horizons.forEach(item=>{const option=document.createElement("option");option.value=item.id;option.textContent=item.label;horizon.append(option);});category.disabled=false;routine.disabled=false;horizon.disabled=false;["reset","next","priority","routineAll","visibleAll","copy","calendar","print","export"].forEach(id=>$(id).disabled=false);[["boundaries",data.privacy_boundaries],["limitations",data.limitations]].forEach(([id,items])=>{const root=$(id);root.replaceChildren();items.forEach(text=>{const card=document.createElement("article");card.className="boundary";add(card,"p",text);root.append(card);});});$("workspace").hidden=false;renderAll();}
    async function load(){try{const response=await fetch("/api/v1/maintenance-guide",{headers:{Accept:"application/json"},cache:"no-store",redirect:"error"});const data=await response.json();if(!response.ok)throw new Error(data.message||"Maintenance guide could not be loaded.");render(data);}catch(error){setStatus(error.message||"Maintenance guide could not be loaded.","bad");}}
    function reset(){state.reviewed.clear();renderAll();}
    function reviewNext(){const item=visibleTasks().find(entry=>!state.reviewed.has(entry.id));if(item)state.reviewed.add(item.id);renderAll();}
    function reviewPriority(){taskOrder(state.payload.tasks).filter(item=>!state.reviewed.has(item.id)).slice(0,5).forEach(item=>state.reviewed.add(item.id));renderAll();}
    function reviewRoutine(){const ids=routineIds();state.payload.tasks.forEach(item=>{if(ids.has(item.id))state.reviewed.add(item.id);});renderAll();}
    function reviewVisible(){visibleTasks().forEach(item=>state.reviewed.add(item.id));renderAll();}
    async function copySummary(){const report=safeReceipt();const lines=["VaultLink security maintenance review",`Reviewed fixed tasks: ${report.reviewed_count}/${report.task_count} | ${report.review_percent}%`,`Completed categories: ${report.reviewed_category_count}/${state.payload.category_count} | routines: ${report.reviewed_routine_count}/${state.payload.routine_count}`,`Category: ${report.selected_category_id} | Routine: ${report.selected_routine_id} | Horizon: ${report.selected_horizon_id}`,`API: ${report.api_version} | Service: ${report.service_mode} | Signed desktop: ${report.signed_desktop_version||"not published"}`,"Review coverage is current-tab reminder progress, not a security-health result.",report.privacy_notice];try{await navigator.clipboard.writeText(lines.join("\n"));setStatus("Privacy-safe maintenance summary copied.","good");}catch(_error){setStatus("Clipboard access was blocked by the browser.","bad");}}
    function download(name,type,text){const blob=new Blob([text],{type});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
    function exportJson(){download("vaultlink-browser-maintenance-review.json","application/json",JSON.stringify(safeReceipt(),null,2));setStatus("Privacy-safe browser maintenance review exported.","good");}
    function escapeIcs(text){return value(text).replace(/\\/g,"\\\\").replace(/\r?\n/g,"\\n").replace(/,/g,"\\,").replace(/;/g,"\\;");}
    function ymd(date){return date.toISOString().slice(0,10).replaceAll("-","");}
    function exportCalendar(){const visible=visibleTasks();const base=new Date();const lines=["BEGIN:VCALENDAR","VERSION:2.0","PRODID:-//VaultLink//Security Maintenance//EN","CALSCALE:GREGORIAN","METHOD:PUBLISH"];visible.forEach(item=>{const due=new Date(base.getTime()+item.cadence_days*86400000);lines.push("BEGIN:VEVENT",`UID:vaultlink-maintenance-${escapeIcs(item.id)}-${ymd(due)}@local`,`DTSTAMP:${base.toISOString().replace(/[-:]/g,"").replace(/\.\d{3}Z$/,"Z")}`,`DTSTART;VALUE=DATE:${ymd(due)}`,`SUMMARY:${escapeIcs(`VaultLink: ${item.title}`)}`,`DESCRIPTION:${escapeIcs("Review this fixed maintenance task in the local VaultLink Security Maintenance Center. Do not place secrets or customer data in calendar notes.")}`,"END:VEVENT");});lines.push("END:VCALENDAR");download("vaultlink-maintenance-plan.ics","text/calendar",lines.join("\r\n")+"\r\n");setStatus(`Exported ${visible.length} fixed calendar reminder(s).`,"good");}
    $("category").addEventListener("change",event=>{state.category=event.target.value;renderAll();});
    $("routine").addEventListener("change",event=>{state.routine=event.target.value;renderAll();});
    $("horizon").addEventListener("change",event=>{state.horizon=event.target.value;renderAll();});
    $("reset").addEventListener("click",reset);
    $("next").addEventListener("click",reviewNext);
    $("priority").addEventListener("click",reviewPriority);
    $("routineAll").addEventListener("click",reviewRoutine);
    $("visibleAll").addEventListener("click",reviewVisible);
    $("copy").addEventListener("click",copySummary);
    $("calendar").addEventListener("click",exportCalendar);
    $("print").addEventListener("click",()=>window.print());
    $("export").addEventListener("click",exportJson);
    load();
  </script>
</body>
</html>"""
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))
