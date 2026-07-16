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
    nav a { min-height:36px; display:inline-flex; align-items:center; padding:0 10px; border:1px solid var(--line); border-radius:5px; color:var(--text); text-decoration:none; font-weight:750; }
    main { padding:28px 0 52px; }
    h1 { margin:0; font-size:30px; }
    h2 { margin:0; font-size:18px; }
    h3 { margin:0; font-size:14px; }
    .lead,.status,.muted,.check p,.runbook p,.surface p,.matrix p,.boundary p { color:var(--muted); }
    .lead { max-width:850px; margin:8px 0 0; }
    .auth { display:grid; grid-template-columns:minmax(260px,1fr) auto auto; gap:9px; align-items:end; margin-top:18px; padding:17px; border:1px solid var(--line); background:var(--band); }
    label { display:block; margin-bottom:6px; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    input,select { width:100%; min-width:0; height:42px; padding:0 11px; border:1px solid var(--line); border-radius:5px; background:var(--field); color:var(--text); font:inherit; }
    button { min-height:42px; padding:0 14px; border:0; border-radius:5px; background:#29323c; color:var(--text); font:800 12px "Segoe UI",Arial,sans-serif; cursor:pointer; }
    button:hover { filter:brightness(1.12); }
    button:disabled { cursor:not-allowed; opacity:.48; }
    .primary { background:var(--blue); color:#061118; }
    .good-button { background:var(--green); color:#07120a; }
    .status { min-height:22px; margin-top:9px; }
    .status.good { color:var(--green); }
    .status.bad { color:var(--red); }
    #console[hidden] { display:none; }
    .toolbar { display:flex; flex-wrap:wrap; gap:8px; margin-top:16px; }
    .metrics { display:grid; grid-template-columns:repeat(8,minmax(110px,1fr)); margin-top:14px; border:1px solid var(--line); background:var(--band); }
    .metric { min-width:0; padding:14px; border-right:1px solid var(--line); }
    .metric:last-child { border-right:0; }
    .metric span { display:block; color:var(--muted); font-size:10px; font-weight:800; text-transform:uppercase; }
    .metric strong { display:block; margin-top:5px; font-size:18px; overflow-wrap:anywhere; }
    .section { margin-top:25px; padding-top:20px; border-top:1px solid var(--line); }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:14px; margin-bottom:11px; }
    .section-head p { max-width:720px; margin:0; color:var(--muted); text-align:right; }
    .filters { display:grid; grid-template-columns:minmax(220px,1fr) minmax(170px,.45fr) minmax(150px,.4fr) auto; gap:9px; align-items:end; }
    .summary-strip { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-top:10px; color:var(--muted); }
    .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(250px,1fr)); gap:9px; }
    .checks { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:8px; }
    .check,.runbook,.surface,.matrix,.boundary { min-width:0; padding:14px; border:1px solid var(--line); border-left:4px solid var(--blue); border-radius:6px; background:var(--panel); }
    .check.good,.matrix.good { border-left-color:var(--green); }
    .check.attention,.runbook.attention,.matrix.attention { border-left-color:var(--yellow); }
    .check.action,.runbook.action,.matrix.action { border-left-color:var(--red); }
    .check p,.runbook p,.surface p,.matrix p,.boundary p { margin:5px 0 0; overflow-wrap:anywhere; }
    .eyebrow { color:var(--blue); font-size:10px; font-weight:800; text-transform:uppercase; }
    .eyebrow.good { color:var(--green); }
    .eyebrow.attention { color:var(--yellow); }
    .eyebrow.action { color:var(--red); }
    .next { margin-top:8px!important; color:var(--text)!important; }
    .category { margin-top:17px; }
    .category-head { display:flex; justify-content:space-between; gap:10px; margin-bottom:8px; color:var(--muted); }
    .category-head strong { color:var(--text); }
    .empty { padding:25px 15px; border:1px dashed var(--line); color:var(--muted); text-align:center; }
    footer { border-width:1px 0 0; }
    footer > div { padding:21px 0 28px; color:var(--muted); }
    @media(max-width:1080px){.metrics{grid-template-columns:repeat(4,1fr)}}
    @media(max-width:780px){header>div,.section-head{align-items:flex-start;flex-direction:column;padding:14px 0}.section-head p{text-align:left}.auth,.filters{grid-template-columns:1fr}.checks{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}button{width:100%}}
    @media(max-width:460px){.brand{align-items:flex-start;flex-direction:column;gap:2px}.metrics{grid-template-columns:1fr}.metric{border-right:0;border-bottom:1px solid var(--line)}}
  </style>
</head>
<body>
  <header><div><div class="brand"><strong>Owner Maintenance Operations</strong><span>40 fixed readiness checks</span></div><nav><a href="/owner">OWNER CONSOLE</a><a href="/owner/insights">INSIGHTS</a><a href="/owner/customers">CUSTOMERS</a><a href="/owner/trust">TRUST</a></nav></div></header>
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
      <div class="toolbar"><button id="refresh" class="good-button" type="button">REFRESH</button><button id="copy" type="button">COPY RUNBOOK</button><button id="json" type="button">EXPORT SAFE JSON</button><button id="csv" type="button">EXPORT CHECKS CSV</button></div>
      <div id="metrics" class="metrics"></div>

      <section class="section">
        <div class="section-head"><h2>Priority Runbook</h2><p>Failed checks become owner tasks. These are instructions only and cannot run commands or control customer PCs.</p></div>
        <div id="runbook" class="grid"></div>
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
        <div class="section-head"><h2>Readiness Checks</h2><p>Filter the fixed 40-check contract. Search and filters stay in this tab and are not uploaded.</p></div>
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
    const state={token:"",payload:null,visible:[]};
    const text=value=>String(value??"");
    function setStatus(message,tone=""){ $("status").textContent=message; $("status").className=`status ${tone}`; }
    function add(parent,tag,value,className=""){const node=document.createElement(tag);node.textContent=text(value);if(className)node.className=className;parent.append(node);return node;}
    function metric(label,value){const node=document.createElement("div");node.className="metric";add(node,"span",label);add(node,"strong",value);return node;}
    function card(className,title,detail,tone="good",eyebrow="",next=""){const node=document.createElement("article");node.className=`${className} ${tone}`;add(node,"div",eyebrow||tone,`eyebrow ${tone}`);add(node,"h3",title);add(node,"p",detail);if(next)add(node,"p",`Next: ${next}`,"next");return node;}
    function fill(rootId,items,renderer,emptyText){const root=$(rootId);root.replaceChildren();if(!items.length){const empty=document.createElement("div");empty.className="empty";empty.textContent=emptyText;root.append(empty);return;}items.forEach(item=>root.append(renderer(item)));}
    function buildCategories(categories){const select=$("category");const current=select.value;select.replaceChildren(new Option("ALL CATEGORIES",""));categories.forEach(name=>select.append(new Option(name.toUpperCase(),name)));if([...select.options].some(option=>option.value===current))select.value=current;}
    function render(data){
      state.payload=data;
      const score=data.score;
      const metrics=$("metrics");metrics.replaceChildren();
      [["Readiness",`${score.value} / 100`],["Checks",`${score.passed} / ${score.total}`],["Owner actions",data.runbook.length],["Persistent stores",`${data.metrics.persistent_stores} / ${data.metrics.total_stores}`],["Customer surfaces",`${data.metrics.ready_surfaces} / ${data.metrics.total_surfaces}`],["Release adoption",`${data.metrics.release_adoption_percent}%`],["Support queue",data.metrics.support_needs_action],["High/Critical",data.metrics.high_critical_audits]].forEach(row=>metrics.append(metric(...row)));
      fill("runbook",data.runbook,item=>card("runbook",item.title,item.detail,item.state,item.category,item.action),"Every fixed owner operations check currently passes.");
      const release=data.release_gate;
      const matrixRows=[
        {title:"Desktop release",detail:release.ready?`${release.version} | ${release.package_filename}`:release.message,state:release.ready?"good":"action",eyebrow:"SIGNED RELEASE"},
        {title:"Manifest signature",detail:`Ed25519: ${release.checks.ed25519_signature}`,state:release.checks.ed25519_signature==="passed"?"good":"action",eyebrow:release.signing_key_id||"SIGNING KEY"},
        {title:"Package integrity",detail:`SHA-256 ${release.checks.package_sha256} | size ${release.checks.package_size}`,state:release.checks.package_sha256==="passed"&&release.checks.package_size==="passed"?"good":"action",eyebrow:"PACKAGE"},
        {title:"App-data preservation",detail:release.checks.app_data_preservation,state:release.checks.app_data_preservation==="passed"?"good":"action",eyebrow:"UPDATE BOUNDARY"},
        {title:"Service status",detail:`${data.service_status.mode.toUpperCase()} | ${data.service_status.message}`,state:data.service_status.mode==="normal"?"good":"attention",eyebrow:"PUBLIC STATUS"},
        ...data.storage_matrix.map(item=>({title:item.label,detail:item.status,state:item.persistent?"good":"action",eyebrow:"STORAGE"}))
      ];
      fill("matrices",matrixRows,item=>card("matrix",item.title,item.detail,item.state,item.eyebrow),"No matrix data is available.");
      fill("surfaces",data.customer_surfaces,item=>card("surface",item.label,`${item.path} | ${item.purpose}`,item.ready?"good":"attention",item.ready?"READY":"CHECK"),"No customer surface data is available.");
      buildCategories(data.categories);
      $("updated").textContent=`Updated ${new Date(data.server_time_utc).toLocaleString()}`;
      fill("boundaries",data.privacy_boundaries.map((detail,index)=>({detail,index})),item=>card("boundary",`Boundary ${item.index+1}`,item.detail,"good","ENFORCED"),"No privacy boundaries were returned.");
      fill("limitations",data.limitations.map((detail,index)=>({detail,index})),item=>card("boundary",`Limitation ${item.index+1}`,item.detail,"attention","READ THIS"),"No limitations were returned.");
      $("console").hidden=false;
      renderChecks();
      setStatus(`Owner operations loaded. ${score.passed} of ${score.total} checks pass.`,score.label==="action"?"bad":"good");
    }
    function filteredChecks(){
      if(!state.payload)return[];
      const query=$("search").value.trim().toLowerCase();
      const category=$("category").value;
      const tone=$("stateFilter").value;
      return state.payload.checks.filter(item=>{
        const haystack=`${item.title} ${item.detail} ${item.action} ${item.category}`.toLowerCase();
        return(!query||haystack.includes(query))&&(!category||item.category===category)&&(!tone||item.state===tone);
      });
    }
    function renderChecks(){
      state.visible=filteredChecks();
      $("showing").textContent=`Showing ${state.visible.length} of 40`;
      const root=$("checks");root.replaceChildren();
      if(!state.visible.length){const empty=document.createElement("div");empty.className="empty";empty.textContent="No checks match those filters.";root.append(empty);return;}
      const groups=new Map();
      state.visible.forEach(item=>{if(!groups.has(item.category))groups.set(item.category,[]);groups.get(item.category).push(item);});
      groups.forEach((items,category)=>{
        const section=document.createElement("section");section.className="category";
        const head=document.createElement("div");head.className="category-head";add(head,"strong",category);add(head,"span",`${items.filter(item=>item.passed).length} of ${items.length} visible checks pass`);
        const grid=document.createElement("div");grid.className="checks";
        items.forEach(item=>grid.append(card("check",item.title,item.detail,item.state,`${item.state} | ${item.priority}`,item.passed?"":item.action)));
        section.append(head,grid);root.append(section);
      });
    }
    async function load(){
      if(!state.token){setStatus("Enter the owner admin token.","bad");return;}
      $("connect").disabled=true;
      try{
        const response=await fetch("/api/v1/admin/maintenance-operations",{headers:{"X-License-Admin-Token":state.token,"Accept":"application/json"},cache:"no-store",redirect:"error"});
        const data=await response.json().catch(()=>({}));
        if(!response.ok)throw new Error(data.message||"Owner operations could not be loaded.");
        if(data.check_count!==40||!Array.isArray(data.checks))throw new Error("The API did not return the complete 40-check operations contract.");
        render(data);
      }catch(error){
        state.payload=null;state.visible=[];$("console").hidden=true;setStatus(error.message||"Owner operations could not be loaded.","bad");
      }finally{$("connect").disabled=false;}
    }
    function connect(){state.token=$("token").value.trim();load();}
    function clear(){state.token="";state.payload=null;state.visible=[];$("token").value="";$("console").hidden=true;setStatus("Owner token and operations report cleared from page memory.");}
    function download(name,body,type){const blob=new Blob([body],{type});const url=URL.createObjectURL(blob);const link=document.createElement("a");link.href=url;link.download=name;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
    function copyRunbook(){
      if(!state.payload)return;
      const lines=[`VaultLink owner operations: ${state.payload.score.value}/100`,...state.payload.runbook.map((item,index)=>`${index+1}. ${item.title}: ${item.action}`),...(!state.payload.runbook.length?["No owner actions are currently required."]:[])];
      navigator.clipboard.writeText(lines.join("\n")).then(()=>setStatus("Owner runbook copied.","good")).catch(()=>setStatus("Clipboard access was blocked.","bad"));
    }
    function exportJson(){if(!state.payload)return;download("vaultlink-owner-maintenance-operations.json",JSON.stringify(state.payload,null,2),"application/json");setStatus("Privacy-safe owner operations report exported.","good");}
    function exportCsv(){
      if(!state.payload)return;
      const rows=[["id","category","title","state","passed","priority","detail","action"],...state.payload.checks.map(item=>[item.id,item.category,item.title,item.state,item.passed,item.priority,item.detail,item.action])];
      const csv=rows.map(row=>row.map(value=>`"${text(value).replaceAll('"','""')}"`).join(",")).join("\r\n");
      download("vaultlink-owner-maintenance-checks.csv",csv,"text/csv");setStatus("Owner maintenance checks exported.","good");
    }
    function resetFilters(){$("search").value="";$("category").value="";$("stateFilter").value="";renderChecks();}
    $("connect").addEventListener("click",connect);
    $("clear").addEventListener("click",clear);
    $("refresh").addEventListener("click",load);
    $("copy").addEventListener("click",copyRunbook);
    $("json").addEventListener("click",exportJson);
    $("csv").addEventListener("click",exportCsv);
    $("search").addEventListener("input",renderChecks);
    $("category").addEventListener("change",renderChecks);
    $("stateFilter").addEventListener("change",renderChecks);
    $("resetFilters").addEventListener("click",resetFilters);
    $("token").addEventListener("keydown",event=>{if(event.key==="Enter")connect();});
  </script>
</body>
</html>'''
    return page.replace("__API_VERSION__", html.escape(str(api_version), quote=True))
