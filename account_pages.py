from html import escape as html_escape


COMMON_STYLE = """
:root{color-scheme:dark;--bg:#0d1014;--panel:#161a20;--field:#0a0d11;--line:#303640;--text:#f4f6f8;--muted:#a6afba;--green:#38df7b;--yellow:#ffd166;--blue:#66bde8;--red:#ff6876}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px "Segoe UI",Arial,sans-serif;letter-spacing:0}button,input,select{font:inherit}
.top{height:64px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 24px;background:#11151a}.brand{font-size:20px;font-weight:800}.version{color:var(--muted);font-size:12px}
.shell{max-width:1180px;margin:0 auto;padding:24px}.bar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:18px}.status{margin-left:auto;color:var(--muted)}
.panel{border:1px solid var(--line);background:var(--panel);border-radius:7px;padding:18px}.grid{display:grid;grid-template-columns:360px minmax(0,1fr);gap:18px}.stack{display:grid;gap:18px}
h1,h2,h3,p{margin-top:0}h1{font-size:24px;margin-bottom:4px}h2{font-size:17px}h3{font-size:13px;color:var(--muted);text-transform:uppercase;margin-bottom:10px}
.muted{color:var(--muted)}label{display:block;color:var(--muted);font-size:12px;font-weight:700;margin:12px 0 6px;text-transform:uppercase}
input,select{width:100%;border:1px solid var(--line);border-radius:5px;background:var(--field);color:var(--text);padding:10px 11px;outline:none}input:focus,select:focus{border-color:var(--blue)}
button{border:0;border-radius:5px;padding:10px 14px;font-weight:800;cursor:pointer;background:#29303a;color:var(--text)}button:hover{filter:brightness(1.12)}button:disabled{opacity:.45;cursor:not-allowed}.primary{background:var(--green);color:#08110c}.blue{background:var(--blue);color:#071117}.yellow{background:var(--yellow);color:#171205}.danger{background:var(--red);color:#17080a}.row{display:flex;gap:9px;align-items:center;flex-wrap:wrap}
.segments{display:grid;grid-template-columns:1fr 1fr;border:1px solid var(--line);border-radius:6px;overflow:hidden}.segments button{border-radius:0;background:transparent}.segments button.active{background:var(--blue);color:#071117}
.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.metric{border-left:3px solid var(--blue);background:#101419;padding:12px}.metric b{display:block;font-size:18px;margin-top:4px}.good{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}
.hidden{display:none!important}.message{min-height:22px;margin-top:12px;color:var(--muted);white-space:pre-wrap}.message.bad{color:var(--red)}.message.good{color:var(--green)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px 8px;vertical-align:middle}th{color:var(--muted);font-size:11px;text-transform:uppercase}tbody tr{cursor:pointer}tbody tr:hover,tbody tr.selected{background:#20262e}.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 7px;font-size:11px}
.key{font:12px Consolas,monospace;background:var(--field);border:1px solid var(--line);padding:10px;word-break:break-all;border-radius:5px}.split{display:grid;grid-template-columns:1fr 1fr;gap:12px}.scroll{overflow:auto;max-height:510px}
@media(max-width:820px){.shell{padding:14px}.grid,.split{grid-template-columns:1fr}.metric-grid{grid-template-columns:1fr}.top{padding:0 14px}.status{width:100%;margin-left:0}}
"""


def customer_account_html(api_version):
    page = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VaultLink Account</title><style>__STYLE__</style></head>
<body><header class="top"><div class="brand">VaultLink Account</div><div class="version">API __VERSION__</div></header>
<main class="shell">
  <div class="bar"><h1>Customer Account</h1><div id="topStatus" class="status">Signed out</div><button id="logout" class="hidden">SIGN OUT</button></div>
  <section id="authView" class="grid">
    <div class="panel">
      <div class="segments"><button id="signInTab" class="active">SIGN IN</button><button id="createTab">CREATE ACCOUNT</button></div>
      <label for="username">Username</label><input id="username" maxlength="32" autocomplete="username">
      <label for="password">Password</label><input id="password" type="password" maxlength="128" autocomplete="current-password">
      <label id="confirmLabel" class="hidden" for="confirm">Confirm password</label><input id="confirm" class="hidden" type="password" maxlength="128" autocomplete="new-password">
      <button id="submit" class="primary" style="width:100%;margin-top:14px">SIGN IN</button>
      <div id="authMessage" class="message"></div>
    </div>
    <div class="panel">
      <h2>Account Security</h2>
      <div class="metric-grid">
        <div class="metric"><span class="muted">Password</span><b>One-way hash</b></div>
        <div class="metric"><span class="muted">Session</span><b>12 hours</b></div>
        <div class="metric"><span class="muted">Storage</span><b>Encrypted</b></div>
      </div>
      <p class="muted" style="margin-top:16px">Passwords cannot be viewed by the owner. This page keeps the signed session only in the current browser tab.</p>
    </div>
  </section>
  <section id="accountView" class="grid hidden">
    <div class="stack">
      <div class="panel"><h3>Account</h3><h2 id="profileName">-</h2><div id="profileStatus" class="pill">-</div><p class="muted" id="profileDates" style="margin-top:12px"></p></div>
      <div class="panel"><h3>Change Password</h3><label for="currentPassword">Current password</label><input id="currentPassword" type="password" autocomplete="current-password"><label for="newPassword">New password</label><input id="newPassword" type="password" autocomplete="new-password"><button id="changePassword" class="blue" style="margin-top:12px">CHANGE PASSWORD</button><div id="passwordMessage" class="message"></div></div>
    </div>
    <div class="panel"><h3>Assigned Access</h3><div id="noLicense" class="muted">No license or rank is assigned yet.</div>
      <div id="licenseView" class="hidden"><div class="metric-grid"><div class="metric"><span class="muted">Rank</span><b id="rank">-</b></div><div class="metric"><span class="muted">Plan</span><b id="plan">-</b></div><div class="metric"><span class="muted">Status</span><b id="licenseStatus">-</b></div></div><h3 style="margin-top:18px">License Key</h3><div id="licenseKey" class="key"></div><div class="row" style="margin-top:10px"><button id="copyKey" class="primary">COPY LICENSE KEY</button><a href="/customer"><button>OPEN LICENSE CENTER</button></a></div><p class="muted" id="licenseMeta" style="margin-top:14px"></p></div>
    </div>
  </section>
</main>
<script>
const $=id=>document.getElementById(id);let mode="login";let session=sessionStorage.getItem("vaultlink_account_session")||"";let current=null;
function message(id,text,kind=""){const el=$(id);el.textContent=text;el.className="message "+kind}
async function api(path,options={}){const headers={"Content-Type":"application/json",...(options.headers||{})};if(session)headers.Authorization="Bearer "+session;const response=await fetch(path,{...options,headers});const data=await response.json().catch(()=>({message:"Invalid server response."}));if(!response.ok)throw new Error(data.message||"Request failed.");return data}
function setMode(next){mode=next;const create=mode==="register";$("signInTab").classList.toggle("active",!create);$("createTab").classList.toggle("active",create);$("confirm").classList.toggle("hidden",!create);$("confirmLabel").classList.toggle("hidden",!create);$("submit").textContent=create?"CREATE ACCOUNT":"SIGN IN";$("password").autocomplete=create?"new-password":"current-password";message("authMessage","")}
function showAccount(account){current=account;$("authView").classList.add("hidden");$("accountView").classList.remove("hidden");$("logout").classList.remove("hidden");$("topStatus").textContent="Signed in";$("profileName").textContent=account.username;$("profileStatus").textContent=account.status.toUpperCase();$("profileDates").textContent="Created "+(account.created_at_utc||"unknown")+" | Last sign-in "+(account.last_login_at_utc||"unknown");const license=account.license||{};$("noLicense").classList.toggle("hidden",!!license.assigned);$("licenseView").classList.toggle("hidden",!license.assigned);if(license.assigned){$("rank").textContent=license.rank?"Rank "+license.rank:"-";$("plan").textContent=license.plan_name||license.plan_id||"-";$("licenseStatus").textContent=(license.status||"unknown").toUpperCase();$("licenseKey").textContent=license.license_key||"Unavailable";$("licenseMeta").textContent="License "+(license.license_id||"-")+" | Devices "+(license.active_devices||0)+" / "+(license.max_devices||1)+(license.expires_at_utc?" | Expires "+license.expires_at_utc:"")}}
function signedOut(){session="";current=null;sessionStorage.removeItem("vaultlink_account_session");$("authView").classList.remove("hidden");$("accountView").classList.add("hidden");$("logout").classList.add("hidden");$("topStatus").textContent="Signed out";$("password").value="";$("confirm").value=""}
async function restore(){if(!session)return;try{const data=await api("/api/v1/accounts/me",{method:"GET"});showAccount(data.account)}catch(_){signedOut()}}
$("signInTab").onclick=()=>setMode("login");$("createTab").onclick=()=>setMode("register");$("logout").onclick=signedOut;
$("submit").onclick=async()=>{const username=$("username").value.trim(),password=$("password").value;if(mode==="register"&&password!==$("confirm").value)return message("authMessage","Passwords do not match.","bad");$("submit").disabled=true;try{const data=await api(mode==="register"?"/api/v1/accounts/register":"/api/v1/accounts/login",{method:"POST",body:JSON.stringify({username,password})});session=data.session_token;sessionStorage.setItem("vaultlink_account_session",session);showAccount(data.account);message("authMessage","")}catch(error){message("authMessage",error.message,"bad")}finally{$("submit").disabled=false}};
$("changePassword").onclick=async()=>{try{const data=await api("/api/v1/accounts/change-password",{method:"POST",body:JSON.stringify({current_password:$("currentPassword").value,new_password:$("newPassword").value})});session=data.session_token;sessionStorage.setItem("vaultlink_account_session",session);$("currentPassword").value="";$("newPassword").value="";message("passwordMessage","Password changed. Other sessions were signed out.","good")}catch(error){message("passwordMessage",error.message,"bad")}};
$("copyKey").onclick=async()=>{const key=current?.license?.license_key||"";if(!key)return;await navigator.clipboard.writeText(key);$("copyKey").textContent="COPIED";setTimeout(()=>$("copyKey").textContent="COPY LICENSE KEY",1200)};
restore();
</script></body></html>"""
    return page.replace("__STYLE__", COMMON_STYLE).replace("__VERSION__", html_escape(str(api_version)))


def owner_accounts_html(api_version):
    page = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VaultLink Owner Accounts</title><style>__STYLE__</style></head>
<body><header class="top"><div class="brand">VaultLink Owner Accounts</div><div class="version">API __VERSION__</div></header>
<main class="shell">
  <div class="bar"><input id="token" type="password" placeholder="LICENSE_ADMIN_TOKEN" autocomplete="off" style="max-width:360px"><button id="load" class="blue">LOAD ACCOUNTS</button><button id="refresh">REFRESH</button><div id="topStatus" class="status">Owner token required</div></div>
  <div class="grid">
    <section class="panel"><div class="row" style="justify-content:space-between"><h2>Accounts</h2><span id="count" class="pill">0</span></div><input id="search" placeholder="Search username or license" autocomplete="off"><div class="scroll"><table><thead><tr><th>Username</th><th>Rank</th><th>Status</th></tr></thead><tbody id="accounts"></tbody></table></div></section>
    <section class="stack">
      <div class="panel"><h3>Selected Account</h3><h2 id="selectedName">Choose an account</h2><div class="split"><div><span class="muted">Account ID</span><div id="selectedId" class="key">-</div></div><div><span class="muted">Current access</span><div id="selectedAccess" class="key">-</div></div></div><div class="row" style="margin-top:12px"><button id="enable">ENABLE</button><button id="disable" class="danger">DISABLE</button></div></div>
      <div class="panel"><h3>Assign New Rank</h3><div class="split"><div><label for="plan">Rank</label><select id="plan"></select></div><div><label for="devices">Device seats</label><input id="devices" type="number" min="1" max="1000" value="1"></div></div><label for="note">Private license note</label><input id="note" maxlength="2000"><button id="issue" class="primary" style="margin-top:12px">ISSUE AND ASSIGN</button></div>
      <div class="panel"><h3>Assign Existing License</h3><label for="licenseId">License ID</label><input id="licenseId" maxlength="80"><label style="text-transform:none"><input id="transfer" type="checkbox" style="width:auto;margin-right:6px">Move it from another account if already assigned</label><button id="assign" class="yellow" style="margin-top:8px">ASSIGN LICENSE</button></div>
      <div id="issuedPanel" class="panel hidden"><h3>New License Key</h3><div id="issuedKey" class="key"></div><button id="copyIssued" class="primary" style="margin-top:10px">COPY KEY</button></div>
      <div id="message" class="message"></div>
    </section>
  </div>
</main>
<script>
const $=id=>document.getElementById(id);let token=sessionStorage.getItem("vaultlink_admin_token")||"";let items=[],selected=null;$("token").value=token;
function msg(text,kind=""){const el=$("message");el.textContent=text;el.className="message "+kind}
async function api(path,options={}){token=$("token").value.trim();if(!token)throw new Error("Enter the owner admin token.");sessionStorage.setItem("vaultlink_admin_token",token);const response=await fetch(path,{...options,headers:{"Content-Type":"application/json","X-License-Admin-Token":token,...(options.headers||{})}});const data=await response.json().catch(()=>({message:"Invalid server response."}));if(!response.ok)throw new Error(data.message||"Request failed.");return data}
function render(){const q=$("search").value.trim().toLowerCase();const shown=items.filter(item=>(item.username+" "+(item.license?.license_id||"")).toLowerCase().includes(q));const body=$("accounts");body.textContent="";for(const item of shown){const tr=document.createElement("tr");if(selected?.account_id===item.account_id)tr.className="selected";for(const text of [item.username,item.license?.rank?"Rank "+item.license.rank:"None",item.status]){const td=document.createElement("td");td.textContent=text;tr.appendChild(td)}tr.onclick=()=>select(item);body.appendChild(tr)}$("count").textContent=shown.length+" / "+items.length}
function select(item){selected=item;$("selectedName").textContent=item.username;$("selectedId").textContent=item.account_id;const license=item.license||{};$("selectedAccess").textContent=license.assigned?`${license.plan_name||license.plan_id} | ${license.license_id} | ${license.status}`:"No license assigned";render();msg("")}
async function load(){try{const [accounts,plans]=await Promise.all([api("/api/v1/admin/accounts"),fetch("/api/v1/plans").then(r=>r.json())]);items=accounts.items||[];$("topStatus").textContent=accounts.count+" account(s)";const selectPlan=$("plan");selectPlan.textContent="";for(const plan of plans.items||[]){const option=document.createElement("option");option.value=plan.id;option.textContent=`Rank ${plan.rank} - ${plan.name}`;selectPlan.appendChild(option)}if(selected){selected=items.find(item=>item.account_id===selected.account_id)||null;if(selected)select(selected)}render();msg("Account list refreshed.","good")}catch(error){msg(error.message,"bad");$("topStatus").textContent="Could not load"}}
async function action(path,payload){if(!selected)throw new Error("Choose an account first.");const result=await api(path,{method:"POST",body:JSON.stringify({account_id:selected.account_id,...payload})});if(result.issued_license_key){$("issuedPanel").classList.remove("hidden");$("issuedKey").textContent=result.issued_license_key}else{$("issuedPanel").classList.add("hidden")}await load();return result}
$("load").onclick=load;$("refresh").onclick=load;$("search").oninput=render;$("issue").onclick=async()=>{try{await action("/api/v1/admin/accounts/assign",{plan_id:$("plan").value,max_devices:Number($("devices").value||1),license_note:$("note").value});msg("New rank issued and assigned.","good")}catch(error){msg(error.message,"bad")}};
$("assign").onclick=async()=>{try{await action("/api/v1/admin/accounts/assign",{license_id:$("licenseId").value.trim(),transfer:$("transfer").checked});msg("Existing license assigned.","good")}catch(error){msg(error.message,"bad")}};
$("enable").onclick=async()=>{try{await action("/api/v1/admin/accounts/status",{status:"active"});msg("Account enabled.","good")}catch(error){msg(error.message,"bad")}};$("disable").onclick=async()=>{try{await action("/api/v1/admin/accounts/status",{status:"disabled"});msg("Account disabled and sessions invalidated.","good")}catch(error){msg(error.message,"bad")}};
$("copyIssued").onclick=async()=>{await navigator.clipboard.writeText($("issuedKey").textContent);$("copyIssued").textContent="COPIED";setTimeout(()=>$("copyIssued").textContent="COPY KEY",1200)};
if(token)load();
</script></body></html>"""
    return page.replace("__STYLE__", COMMON_STYLE).replace("__VERSION__", html_escape(str(api_version)))
