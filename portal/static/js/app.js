/* AndroidINONE Portal – Mobile Security Command Center */
let ws,page='dashboard',dev=null,pkgs=[],notifs=[],selPkg='';
let _fs=[];

// ═══════════ WEBSOCKET ═══════════
function wsInit(){
  const p=location.protocol==='https:'?'wss':'ws';
  ws=new WebSocket(`${p}://${location.host}/ws`);
  ws.onopen=()=>console.warn('[WS] Connected');
  ws.onmessage=e=>{try{wsMsg(JSON.parse(e.data))}catch{}};
  ws.onclose=()=>setTimeout(wsInit,3000);
}
function wsMsg(d){
  if(d.type==='device_status'){dev=d;updTopbar()}
  else if(d.type==='scan_progress'){ntf('info',`[${d.scan_id}] ${d.percent}% ${d.message}`)}
  else if(d.type==='scan_complete'){ntf('ok',`Scan ${d.scan_id} done: ${d.findings} findings`);if(page==='target')nav('target')}
  else if(d.type==='agent_progress'){ntf('info',`${d.agent}: ${d.message}`)}
}
function updTopbar(){
  const dd=$('dev-dot'),dl=$('dev-lbl'),fd=$('fri-dot');
  if(dev?.connected){dd.className='status-dot on';dl.textContent=dev.device?.model||dev.model||'Connected'}
  else{dd.className='status-dot off';dl.textContent='No device'}
  if(fd){fd.className='status-dot '+(dev?.frida_running?'on':'off')}
}

// ═══════════ NOTIFICATIONS ═══════════
function ntf(t,m){notifs.unshift({t,m,d:new Date()});if(notifs.length>50)notifs.pop();const c=$('nc');c.style.display='inline';c.textContent=notifs.length}
function toggleNotif(){const p=$('notif-panel');p.style.display=p.style.display==='none'?'block':'none';renderNotif()}
function renderNotif(){$('notif-list').innerHTML=notifs.length?notifs.map(n=>`<div style="padding:5px 0;border-bottom:1px solid var(--bd);font-size:11px">${n.t==='ok'?'✓':n.t==='err'?'✗':'·'} ${esc(n.m)}</div>`).join(''):'<div style="color:var(--t3);text-align:center;padding:12px">No notifications</div>'}

// ═══════════ NAVIGATION ═══════════
document.querySelectorAll('.nav-item').forEach(el=>{
  el.addEventListener('click',()=>{nav(el.dataset.page)});
});
function nav(p){
  page=p;document.querySelectorAll('.nav-item').forEach(n=>{n.classList.toggle('active',n.dataset.page===p)});
  _fs=[];loadPage(p);
}
function loadPage(p){const mc=$('mc');const fn=PG[p];fn?fn(mc):mc.innerHTML=`<div class="card">Page "${p}" coming soon</div>`}

// ═══════════ PAGE MAP ═══════════
const PG={dashboard:pgDash,target:pgTarget,semgrep:pgSemgrep,drozer:pgDrozer,hunter:pgHunter,frida:pgFrida,objection:pgObjection,medusa:pgMedusa,memory:pgMem,traffic:pgTraffic,shell:pgShell,reports:pgReports};

// ────────────────── DASHBOARD ──────────────────
async function pgDash(mc){
  mc.innerHTML=loading();
  const[dv,pk,sc,ag,tl]=await Promise.all([api('/api/device'),api('/api/packages?system=false'),api('/api/scans'),api('/api/agents'),api('/api/tools')]);
  pkgs=pk?.packages||[];
  const s=sc?.scans||[];const agents=ag?.agents||[];const tools=tl?.tools||{};
  const ti=Object.values(tools).filter(v=>v===true).length;
  mc.innerHTML=`
    <div class="page-title">Dashboard</div>
    <div class="g4">
      <div class="card stat"><div class="n" style="color:${dv?.connected?'var(--green)':'var(--red)'}">${dv?.connected?'●':'○'}</div><div class="l">${esc(dv?.model||'No Device')}</div></div>
      <div class="card stat"><div class="n">${pkgs.length}</div><div class="l">Packages</div></div>
      <div class="card stat"><div class="n" style="color:var(--cyan)">${s.length}</div><div class="l">Scans</div></div>
      <div class="card stat"><div class="n" style="color:var(--purple)">${ti}/7</div><div class="l">Tools</div></div>
    </div>
    <div class="g2">
      <div class="card"><div class="card-title">Quick Scan</div>
        <div class="ig"><input id="qp" placeholder="com.example.app" list="ql"><datalist id="ql">${pkgs.map(p=>`<option value="${p}">`).join('')}</datalist><button class="btn btn-accent" onclick="qScan()">Scan</button></div>
      </div>
      <div class="card"><div class="card-title">Recent Scans</div>
        ${s.length?s.slice(0,5).map(x=>`<div style="display:flex;justify-content:space-between;padding:3px 0;font-size:11px;border-bottom:1px solid var(--bd)"><span style="font-family:var(--mono)">${esc(x.package)}</span><span class="sev sev-${x.risk_level||'INFO'}">${x.status==='completed'?x.risk_level||'done':x.status}</span></div>`).join(''):'<span style="color:var(--t3)">No scans yet</span>'}
      </div>
    </div>
    <div class="g2">
      <div class="card"><div class="card-title">CLI Tools</div>
        <table>${Object.entries(tools).filter(([k])=>!k.endsWith('_version')).map(([n,ok])=>`<tr><td><strong>${esc(n)}</strong></td><td>${ok?'<span class="tag tag-g">OK</span>':'<span class="tag tag-r">Missing</span>'}</td></tr>`).join('')}</table>
      </div>
      <div class="card"><div class="card-title">Agents</div>
        <table>${agents.map(a=>`<tr><td><strong>${esc(a.name)}</strong></td><td>${a.installed?'<span class="tag tag-g">Ready</span>':'<span class="tag tag-r">N/A</span>'}</td><td style="font-size:10px;color:var(--t3)">${esc((a.description||'').substring(0,50))}</td></tr>`).join('')}</table>
      </div>
    </div>`;
}
async function qScan(){const p=$('qp').value.trim();if(!p)return toast('Enter package','err');selPkg=p;toast('Starting scan...','info');const r=await api(`/api/scan/${p}?dynamic=true`,'POST');r?.scan_id?toast(`Scan ${r.scan_id} started`,'ok'):toast('Failed','err')}

// ────────────────── TARGET (Recon + Scanner merged) ──────────────────
async function pgTarget(mc){
  mc.innerHTML=loading();
  const[pk,sc]=await Promise.all([api('/api/packages?system=false'),api('/api/scans')]);
  pkgs=pk?.packages||[];const scans=sc?.scans||[];
  mc.innerHTML=`
    <div class="page-title">Target Analysis</div>
    <div class="card">
      <div class="ig" style="margin-bottom:6px"><input id="pf" placeholder="Filter packages..." oninput="filterPkg()"><button class="btn btn-accent" onclick="inspectPkg()">Analyze</button><button class="btn btn-green" onclick="fullScan()">Full Scan</button></div>
      <div style="max-height:200px;overflow-y:auto"><table id="ptbl"><tr><th>Packages (${pkgs.length})</th></tr>
      ${pkgs.map(p=>`<tr class="pr" data-p="${esc(p)}"><td style="font:11px var(--mono);cursor:pointer;padding:3px 8px" onclick="selPkg='${esc(p)}';document.querySelectorAll('.pr').forEach(r=>r.style.background='');this.parentElement.style.background='var(--bg3)';$('sp').textContent='${esc(p)}'">${esc(p)}</td></tr>`).join('')}</table></div>
      <div style="margin-top:4px;font-size:11px;color:var(--t3)">Selected: <strong id="sp">${esc(selPkg||'none')}</strong></div>
    </div>
    <div id="target-detail"></div>
    ${scans.length?`<div class="card"><div class="card-title">Scan History</div>
      <table><tr><th>ID</th><th>Package</th><th>Status</th><th>Findings</th><th>Risk</th><th></th></tr>
      ${scans.map(s=>`<tr><td><code style="font-size:10px">${esc(s.scan_id)}</code></td><td style="font:11px var(--mono)">${esc(s.package)}</td><td><span class="sev sev-${s.status==='completed'?'INFO':'MEDIUM'}">${s.status}</span></td><td>${s.finding_count||0}</td><td>${s.risk_level?`<span class="sev sev-${s.risk_level}">${s.risk_level}</span>`:'-'}</td><td><button class="btn btn-sm" onclick="viewScan('${esc(s.scan_id)}')">View</button> <button class="btn btn-sm" onclick="genReport('${esc(s.scan_id)}')">Report</button></td></tr>`).join('')}</table></div>`:''}`;
}
function filterPkg(){const q=$('pf').value.toLowerCase();document.querySelectorAll('.pr').forEach(r=>{r.style.display=r.dataset.p.toLowerCase().includes(q)?'':'none'})}

async function inspectPkg(){
  if(!selPkg)return toast('Select a package first','err');
  const d=$('target-detail');d.innerHTML=cardLoading(`Analyzing ${selPkg}...`);
  const[info,analysis]=await Promise.all([api(`/api/packages/${selPkg}`),api(`/api/analyze/package/${selPkg}`,'POST')]);
  const findings=analysis?.findings||[];const secrets=analysis?.secrets||[];const manifest=analysis?.manifest||{};
  const perms=info?.permissions||manifest?.permissions||[];

  d.innerHTML=`
    <div class="card"><div class="card-title">${esc(selPkg)}</div>
      <div class="g2"><div><table>
        ${[['Version',info?.version_name],['Target SDK',manifest?.target_sdk||info?.target_sdk],['Min SDK',manifest?.min_sdk||info?.min_sdk],['UID',info?.uid]].map(([k,v])=>`<tr><td style="color:var(--t3);width:90px">${k}</td><td>${esc(String(v||'-'))}</td></tr>`).join('')}
      </table></div><div><table>
        ${[['Debuggable',manifest?.debuggable?'<span class="sev sev-CRITICAL">YES</span>':'No'],['Backup',manifest?.allow_backup?'<span class="sev sev-HIGH">YES</span>':'No'],['Cleartext',manifest?.cleartext_traffic?'<span class="sev sev-HIGH">YES</span>':'No'],['Components',`${(manifest?.activities||[]).length}A/${(manifest?.services||[]).length}S/${(manifest?.receivers||[]).length}R`]].map(([k,v])=>`<tr><td style="color:var(--t3);width:90px">${k}</td><td>${v}</td></tr>`).join('')}
      </table></div></div>
    </div>
    ${perms.length?`<div class="card"><div class="card-title">Permissions (${perms.length})</div><div style="display:flex;flex-wrap:wrap;gap:2px">${perms.map(p=>`<span class="tag${isDangerousPerm(p)?' tag-r':''}">${esc(p.split('.').pop())}</span>`).join('')}</div></div>`:''}
    <div class="g5" style="margin-bottom:8px">
      ${['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(s=>{const c=findings.filter(f=>f.severity===s).length;return`<div class="card stat"><div class="n" style="color:var(--${sevColor(s)})">${c}</div><div class="l">${s}</div></div>`}).join('')}
    </div>
    ${secrets.length?`<div class="card"><div class="card-title">Secrets (${secrets.length})</div>${renderFindings(secrets.slice(0,15).map(s=>({severity:'CRITICAL',category:'Secret',title:s.type,description:s.value,location:s.location})))}</div>`:''}
    <div class="card"><div class="card-title">Findings (${findings.length})</div>${renderFindings(findings)}</div>
    <div style="display:flex;gap:6px;margin-top:8px">
      <button class="btn btn-accent" onclick="fullScan()">Full Scan</button>
      <button class="btn" onclick="runOWASP()">OWASP Top 10</button>
      <button class="btn" onclick="semgrepPkg()">Semgrep</button>
      <button class="btn" onclick="hunterPkg()">Hunter</button>
    </div><div id="extra-r"></div>`;
}

async function fullScan(){
  if(!selPkg)return toast('Select package first','err');
  toast('Starting full scan...','info');
  const r=await api(`/api/scan/${selPkg}?dynamic=true`,'POST');
  if(r?.scan_id){toast(`Scan ${r.scan_id} started`,'ok');ntf('ok',`Scan started: ${selPkg}`);pollScan(r.scan_id)}
}
async function pollScan(id){
  for(let i=0;i<30;i++){
    await sleep(2000);const r=await api(`/api/scan/${id}`);if(!r)continue;
    if(r.status==='completed'||r.status==='error'){toast(r.status==='completed'?'Scan complete!':'Scan finished with errors',r.status==='completed'?'ok':'err');nav('target');return}
  }
}
async function viewScan(id){
  const r=await api(`/api/scan/${id}`);if(!r)return toast('Not found','err');
  const f=[...(r.static_findings||[]),...(r.dynamic_findings||[]),...(r.network_findings||[]),...(r.component_findings||[]),...(r.hunter_findings||[])];
  const s=r.summary||{};const sv=s.severity_counts||{};
  openModal(`Scan: ${r.package||id}`,`
    <div class="g5" style="margin-bottom:8px">${['CRITICAL','HIGH','MEDIUM','LOW','INFO'].map(k=>`<div class="stat"><div class="n" style="color:var(--${sevColor(k)})">${sv[k]||0}</div><div class="l">${k}</div></div>`).join('')}</div>
    <div style="font-size:12px;margin-bottom:8px">Risk: <span class="sev sev-${s.risk_level||'INFO'}">${s.risk_level||'-'}</span> · Score: ${s.risk_score||0} · Duration: ${(r.duration||0).toFixed(1)}s</div>
    ${renderFindings(f)}`);
}
async function genReport(id){toast('Generating...','info');const r=await api(`/api/reports/generate?scan_id=${id}&fmt=html`,'POST');r?.path?toast('Report ready','ok')&&nav('reports'):toast('Failed','err')}
async function runOWASP(){if(!selPkg)return;const d=$('extra-r');d.innerHTML=cardLoading('OWASP Mobile Top 10...');const r=await api(`/api/agents/owasp/${selPkg}`,'POST');d.innerHTML=`<div class="card"><div class="card-title">OWASP Results (${(r?.findings||[]).length})</div>${renderFindings(r?.findings||[])}</div>`}
async function semgrepPkg(){if(!selPkg)return;const d=$('extra-r');d.innerHTML=cardLoading('Semgrep MASVS...');const r=await api(`/api/agents/semgrep/scan-apk/${selPkg}`,'POST');d.innerHTML=`<div class="card"><div class="card-title">Semgrep Results (${(r?.findings||[]).length})</div>${renderFindings(r?.findings||[])}</div>`}
async function hunterPkg(){if(!selPkg)return;const d=$('extra-r');d.innerHTML=cardLoading('Running Hunter full hunt...');const r=await api(`/api/agents/hunter/full/${selPkg}`,'POST');const f=r?.findings||[];d.innerHTML=`<div class="card"><div class="card-title">Hunter Results (${f.length})</div>${renderFindings(f)}</div>`}

// ────────────────── SEMGREP ──────────────────
async function pgSemgrep(mc){
  mc.innerHTML=loading();
  const r=await api('/api/agents/semgrep/rules');
  const rules=r?.rules||[];
  const cats=[...new Set(rules.map(r=>r.category))].sort();
  mc.innerHTML=`
    <div class="page-title">Semgrep MASVS Scanner</div>
    <div class="card">
      <div class="card-title">Scan Package</div>
      <div class="ig"><input id="sgp" placeholder="com.example.app" value="${esc(selPkg)}"><button class="btn btn-accent btn-lg" onclick="sgScan()">Run Semgrep Scan</button></div>
      <div id="sg-prog" style="margin-top:8px"></div>
    </div>
    <div class="card">
      <div class="card-title">MASVS Rules (${rules.length})</div>
      <div class="gc">
        ${cats.map(c=>{const cr=rules.filter(r=>r.category===c);return`<div class="card" style="margin-bottom:0;padding:8px 10px"><div style="display:flex;justify-content:space-between"><strong style="font-size:10px;text-transform:capitalize">${esc(c)}</strong><span class="tag" style="font-size:9px;padding:0 5px">${cr.length}</span></div><div style="margin-top:3px">${cr.map(r=>`<div style="font-size:9.5px;color:var(--t2);padding:0px 0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis" title="${esc(r.path||'')}">${esc(r.id||r.name||'')}</div>`).join('')}</div></div>`}).join('')}
      </div>
    </div>
    <div id="sg-results"></div>`;
}
async function sgScan(){
  const p=$('sgp').value.trim();if(!p)return toast('Enter package','err');
  $('sg-prog').innerHTML='<div style="color:var(--t3)">Running Semgrep analysis...</div><div class="progress"><div class="progress-bar" style="width:50%"></div></div>';
  const r=await api(`/api/agents/semgrep/scan-apk/${p}`,'POST');
  $('sg-prog').innerHTML='';
  $('sg-results').innerHTML=`<div class="card"><div class="card-title">Results (${(r?.findings||[]).length} findings)</div>${renderFindings(r?.findings||[])}</div>`;
}

// ────────────────── DROZER ──────────────────
async function pgDrozer(mc){
  mc.innerHTML=`
    <div class="page-title">Drozer – Component Security Testing</div>
    <div class="g2">
      <div class="card">
        <div class="card-title">Setup & Connection</div>
        <div style="display:flex;gap:6px;margin-bottom:8px">
          <button class="btn btn-green" onclick="drozerSetup()">Auto Setup</button>
          <button class="btn btn-accent" onclick="drozerConnect()">Connect</button>
        </div>
        <span id="dz-status" style="font-size:11px"></span>
        <div id="dz-setup-log" style="margin-top:6px"></div>
      </div>
      <div class="card">
        <div class="card-title">Setup Info</div>
        <div style="font-size:11px;color:var(--t2);line-height:1.7">
          <strong>Auto Setup</strong> will:<br>
          1. Install drozer CLI (pip)<br>
          2. Download drozer-agent APK<br>
          3. Install agent on device<br>
          4. Start agent & forward port<br>
          5. Test connection
        </div>
      </div>
    </div>
    <div class="g2">
      <div class="card">
        <div class="card-title">Full Assessment</div>
        <div class="ig"><input id="dzp" placeholder="com.example.app" value="${esc(selPkg)}"><button class="btn btn-accent" onclick="dzAssess()">Run Assessment</button></div>
      </div>
      <div class="card">
        <div class="card-title">Run Module</div>
        <div class="fg"><label class="fl">Module</label><input id="dzm" placeholder="app.activity.info" value="app.activity.info"></div>
        <div class="fg"><label class="fl">Package</label><input id="dzmp" placeholder="com.example.app" value="${esc(selPkg)}"></div>
        <div class="fg"><label class="fl">Extra args</label><input id="dza" placeholder=""></div>
        <button class="btn btn-accent" onclick="dzRun()">Run</button>
      </div>
    </div>
    <div id="dz-results"></div>
    <div class="card" style="margin-top:8px">
      <div class="card-title">Common Modules</div>
      <table>
        ${[['app.activity.info','List activities'],['app.service.info','List services'],['app.broadcast.info','List receivers'],['app.provider.info','List content providers'],['app.provider.finduri','Find content URIs'],['scanner.activity.browsable','Browsable activities'],['scanner.provider.injection','SQL injection on providers'],['scanner.provider.traversal','Path traversal on providers'],['scanner.misc.native','Native components'],['app.package.attacksurface','Attack surface analysis']].map(([m,d])=>`<tr><td><code style="font-size:10.5px;cursor:pointer;color:var(--accent)" onclick="$('dzm').value='${m}'">${m}</code></td><td style="font-size:11px;color:var(--t2)">${d}</td></tr>`).join('')}
      </table>
    </div>`;
}
async function drozerSetup(){
  $('dz-status').innerHTML='<span style="color:var(--t3)">Running auto setup...</span>';
  $('dz-setup-log').innerHTML=cardLoading('Setting up drozer (download, install, connect)...');
  const r=await api('/api/agents/drozer/setup','POST');
  const steps=r?.steps||[];
  $('dz-setup-log').innerHTML=`<div style="font-size:11px">${steps.map(s=>`<div style="padding:2px 0">${s.success?'<span style="color:var(--green)">&#10003;</span>':'<span style="color:var(--red)">&#10007;</span>'} <strong>${esc(s.step)}</strong>: ${esc(s.detail||'')}</div>`).join('')}</div>`;
  $('dz-status').innerHTML=r?.success?'<span class="tag tag-g">Connected</span>':'<span class="tag tag-r">Setup incomplete</span>';
  toast(r?.success?'Drozer setup complete':'Setup needs attention',r?.success?'ok':'err');
}
async function drozerConnect(){
  $('dz-status').innerHTML='<span style="color:var(--t3)">Connecting...</span>';
  const r=await api('/api/agents/drozer/connect','POST');
  if(r?.success){$('dz-status').innerHTML='<span class="tag tag-g">Connected</span>';toast('Drozer connected','ok')}
  else{$('dz-status').innerHTML='<span class="tag tag-r">Failed</span>';$('dz-results').innerHTML=`<div class="card" style="border-left:3px solid var(--red)"><strong>Connection Failed</strong><pre class="terminal" style="margin-top:4px">${esc(r?.message||'Cannot reach drozer Agent. Try Auto Setup first.')}</pre></div>`}
}
async function dzAssess(){
  const p=$('dzp').value.trim();if(!p)return toast('Enter package','err');
  const d=$('dz-results');d.innerHTML=cardLoading('Running full assessment (this may take a moment)...');
  const r=await api(`/api/agents/drozer/assess/${p}`,'POST');
  const res=r?.results||[];
  if(!res.length){d.innerHTML='<div class="card" style="color:var(--t3)">No results – check drozer connection</div>';return}
  const allFindings=res.flatMap(x=>x.findings||[]);
  d.innerHTML=`
    <div class="card"><div class="card-title">Assessment Results (${res.length} modules)</div>
    ${res.map(x=>`<div style="border-bottom:1px solid var(--bd);padding:6px 0">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <strong style="font-size:11px;font-family:var(--mono)">${esc(x.command||'')}</strong>
        <span class="tag ${x.success?'tag-g':'tag-r'}">${x.success?'OK':'FAIL'}</span>
      </div>
      <pre class="terminal" style="margin-top:4px;max-height:120px">${esc(x.output||'No output')}</pre>
    </div>`).join('')}
    </div>
    ${allFindings.length?`<div class="card"><div class="card-title">Findings (${allFindings.length})</div>${renderFindings(allFindings)}</div>`:''}`;
}
async function dzRun(){
  const m=$('dzm').value,p=$('dzmp').value,a=$('dza').value;
  if(!m)return toast('Enter module','err');
  const d=$('dz-results');d.innerHTML=cardLoading('Running '+m+'...');
  const r=await api(`/api/agents/drozer/run?module=${enc(m)}&package=${enc(p)}&extra_args=${enc(a)}`,'POST');
  const findings=r?.findings||[];
  d.innerHTML=`<div class="card"><div class="card-title">${esc(r?.command||m)} <span class="tag ${r?.success?'tag-g':'tag-r'}">${r?.success?'OK':'FAIL'}</span></div><pre class="terminal">${esc(r?.output||r?.error||'No output')}</pre></div>
  ${findings.length?`<div class="card"><div class="card-title">Findings</div>${renderFindings(findings)}</div>`:''}`;
}

// ────────────────── HUNTER (AndroHunter) ──────────────────
async function pgHunter(mc){
  mc.innerHTML=`
    <div class="page-title">Hunter – Comprehensive Security Testing</div>
    <div class="card">
      <div class="card-title">Full Hunt</div>
      <div style="font-size:11px;color:var(--t2);margin-bottom:8px">Run all modules: Intent Fuzzer, Provider Fuzzer, Broadcast Fuzzer, FileProvider Analyzer, StrandHogg Check, DEX Secret Scan</div>
      <div class="ig"><input id="hpkg" placeholder="com.example.app" value="${esc(selPkg)}"><button class="btn btn-green btn-lg" onclick="hunterFull()">Run Full Hunt</button></div>
      <div id="h-prog" style="margin-top:8px"></div>
    </div>
    <div class="card">
      <div class="card-title">Individual Modules</div>
      <div style="display:flex;flex-wrap:wrap;gap:6px">
        <button class="btn btn-accent" onclick="hunterMod('intents')">Intent Fuzzer</button>
        <button class="btn btn-accent" onclick="hunterMod('providers')">Provider Fuzzer</button>
        <button class="btn btn-accent" onclick="hunterMod('broadcasts')">Broadcast Fuzzer</button>
        <button class="btn btn-accent" onclick="hunterMod('fileprovider')">FileProvider</button>
        <button class="btn btn-accent" onclick="hunterMod('taskhijack')">StrandHogg</button>
        <button class="btn btn-accent" onclick="hunterMod('dex')">DEX Secrets</button>
      </div>
    </div>
    <div id="h-results"></div>
    <div class="card">
      <div class="card-title">Module Details</div>
      <table>
        <tr><td style="width:140px"><strong style="font-size:11px">Intent Fuzzer</strong></td><td style="font-size:11px;color:var(--t2)">12 payloads: LFI, SQLi, XSS, Redirect, Template Injection, Command Injection. VULN/SUSP/SAFE classification.</td></tr>
        <tr><td><strong style="font-size:11px">Provider Fuzzer</strong></td><td style="font-size:11px;color:var(--t2)">9 SQLi payloads per provider: Error-based, Boolean, UNION, Time-based. Readable provider detection.</td></tr>
        <tr><td><strong style="font-size:11px">Broadcast Fuzzer</strong></td><td style="font-size:11px;color:var(--t2)">10 broadcast payloads across 6 categories: Auth bypass, SQLi, LFI, Redirect, PrivEsc, Exfil.</td></tr>
        <tr><td><strong style="font-size:11px">FileProvider</strong></td><td style="font-size:11px;color:var(--t2)">Parse FileProvider XML paths (root/cache/external), 9 path traversal payloads incl. URL-encoded.</td></tr>
        <tr><td><strong style="font-size:11px">StrandHogg</strong></td><td style="font-size:11px;color:var(--t2)">Detect StrandHogg 1.0: custom taskAffinity, empty affinity, standard launchMode.</td></tr>
        <tr><td><strong style="font-size:11px">DEX Secrets</strong></td><td style="font-size:11px;color:var(--t2)">19 patterns: API keys, AWS, Firebase, JWT, passwords, IPs, debug flags, SQL queries. VULN/SUSP/INFO.</td></tr>
      </table>
    </div>
    <div class="card">
      <div class="card-title">Payload Engine</div>
      <div style="font-size:11px;color:var(--t2);line-height:1.7">
        <strong>Classification:</strong> <span class="sev sev-CRITICAL">VULN</span> confirmed vulnerability &nbsp; <span class="sev sev-MEDIUM">SUSP</span> suspicious behavior &nbsp; <span class="sev sev-INFO">SAFE</span> no impact<br>
        <strong>Categories:</strong> SQLi (8), XSS (6), LFI/Path Traversal (6), Open Redirect (6), Template Injection (6), Command Injection (8), IDOR (9)
      </div>
    </div>`;
}
async function hunterFull(){
  const p=$('hpkg').value.trim();if(!p)return toast('Enter package','err');
  $('h-prog').innerHTML='<div style="color:var(--t3)">Running full hunt... this may take a few minutes</div><div class="progress"><div class="progress-bar" style="width:30%;animation:pulse 1.5s infinite"></div></div>';
  const d=$('h-results');d.innerHTML='';
  const r=await api(`/api/agents/hunter/full/${p}`,'POST');
  $('h-prog').innerHTML='';
  if(!r?.success&&(r?.detail||r?.error)){d.innerHTML=`<div class="card" style="border-left:3px solid var(--red)">${esc(r.detail||r.error)}</div>`;return}
  const findings=r?.findings||[];
  const mods=r?.modules||{};
  const modNames={intent_fuzzer:'Intent Fuzzer',provider_fuzzer:'Provider Fuzzer',broadcast_fuzzer:'Broadcast Fuzzer',fileprovider:'FileProvider',task_hijack:'StrandHogg',dex_secrets:'DEX Secrets'};
  const crit=findings.filter(f=>f.severity==='CRITICAL').length;
  const high=findings.filter(f=>f.severity==='HIGH').length;
  const med=findings.filter(f=>f.severity==='MEDIUM').length;
  const low=findings.filter(f=>f.severity==='LOW'||f.severity==='INFO').length;
  d.innerHTML=`
    <div class="g4" style="margin-bottom:8px">
      <div class="card stat"><div class="n" style="color:var(--red)">${crit}</div><div class="l">Critical</div></div>
      <div class="card stat"><div class="n" style="color:var(--orange)">${high}</div><div class="l">High</div></div>
      <div class="card stat"><div class="n" style="color:var(--yellow)">${med}</div><div class="l">Medium</div></div>
      <div class="card stat"><div class="n" style="color:var(--cyan)">${low}</div><div class="l">Low/Info</div></div>
    </div>
    ${Object.entries(mods).map(([k,v])=>{const mf=v?.findings||[];const ok=v?.success;
      const vc=mf.filter(f=>f.classification==='VULN').length;
      const sc=mf.filter(f=>f.classification==='SUSP').length;
      const badge=vc?`<span class="sev sev-CRITICAL">${vc} VULN</span> `:'';
      const badge2=sc?`<span class="sev sev-MEDIUM">${sc} SUSP</span> `:'';
      return`<div class="card"><div class="card-title">${esc(modNames[k]||k)} <span class="tag ${ok?'tag-g':'tag-r'}">${mf.length} findings</span> ${badge}${badge2}</div>${mf.length?renderFindings(mf):'<span style="color:var(--t3);font-size:11px">No findings</span>'}</div>`}).join('')}`;
  toast(`Hunt complete: ${findings.length} findings`,'ok');
}
async function hunterMod(mod){
  const p=$('hpkg').value.trim();if(!p)return toast('Enter package','err');
  const d=$('h-results');d.innerHTML=cardLoading(`Running ${mod}...`);
  const r=await api(`/api/agents/hunter/${mod}/${p}`,'POST');
  if(r?.detail||r?.error){d.innerHTML=`<div class="card" style="border-left:3px solid var(--red)">${esc(r.detail||r.error)}</div>`;if(!r?.findings?.length)return}
  const findings=r?.findings||[];
  d.innerHTML=`<div class="card"><div class="card-title">${esc(mod)} Results <span class="tag ${r?.success?'tag-g':'tag-r'}">${findings.length} findings</span></div>${findings.length?renderFindings(findings):'<span style="color:var(--t3)">No findings</span>'}</div>`;
  toast(`${mod}: ${findings.length} findings`,findings.length?'ok':'info');
}

// ────────────────── FRIDA ──────────────────
async function pgFrida(mc){
  const[st,sc,dv]=await Promise.all([api('/api/frida/status'),api('/api/frida/scripts'),api('/api/device')]);
  const running=st?.running;const scripts=sc?.scripts||[];const rooted=dv?.device?.is_rooted;
  mc.innerHTML=`
    <div class="page-title">Frida Instrumentation</div>
    <div class="g2">
      <div class="card">
        <div class="card-title">Frida Server</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span>Status: <span class="sev sev-${running?'INFO':'MEDIUM'}">${running?'Running':'Stopped'}</span> ${st?.version?`<span class="tag">v${st.version}</span>`:''}</span>
          <span>${running?'<button class="btn btn-sm btn-red" onclick="fridaCtl(\'stop\')">Stop</button>':'<button class="btn btn-sm btn-green" onclick="fridaCtl(\'start\')">Start</button>'} <button class="btn btn-sm" onclick="fridaCtl(\'install\')">Install/Update</button></span>
        </div>
        <div style="font-size:10.5px;color:var(--t3)">Port: ${st?.port_listening?'<span style="color:var(--green)">27042 listening</span>':'<span style="color:var(--t3)">27042 not listening</span>'}</div>
      </div>
      <div class="card">
        <div class="card-title">Device Root</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
          <span>Root: <span class="sev sev-${rooted?'INFO':'MEDIUM'}">${rooted?'Yes':'No'}</span></span>
          <button class="btn btn-sm btn-accent" onclick="rootDevice()">ADB Root</button>
        </div>
        <div id="root-msg" style="font-size:10.5px;color:var(--t3)">Runs 'adb root' to restart adbd as root</div>
      </div>
    </div>
    <div class="g2">
      <div class="card">
        <div class="card-title">Run Script</div>
        <div class="fg"><label class="fl">Package</label><input id="fpkg" value="${esc(selPkg)}" placeholder="com.example.app"></div>
        <div class="fg"><label class="fl">Script</label><select id="fscr">${scripts.map(s=>`<option value="${esc(s.key)}">${esc(s.name)}</option>`).join('')}</select></div>
        <button class="btn btn-accent" onclick="fridaRun()">Run</button>
      </div>
      <div class="card">
        <div class="card-title">Custom Script</div>
        <textarea id="fcustom" rows="5" style="font:11px var(--mono)" placeholder="Java.perform(function(){ ... })"></textarea>
        <button class="btn btn-accent" style="margin-top:4px" onclick="fridaCustom()">Execute</button>
      </div>
    </div>
    <div class="card"><div class="card-title">Output</div><div id="fout" class="terminal">Ready.</div></div>`;
}
async function rootDevice(){$('root-msg').innerHTML='<span style="color:var(--t3)">Running adb root...</span>';const r=await api('/api/device/root','POST');$('root-msg').innerHTML=r?.success?'<span style="color:var(--green)">Rooted successfully</span>':'<span style="color:var(--red)">'+(esc(r?.message||'Failed'))+'</span>'}
async function fridaCtl(a){toast(`Frida ${a}...`,'info');const r=await api(`/api/frida/${a}`,'POST');toast(r?.message||'Done',r?.success!==false?'ok':'err');nav('frida')}
async function fridaRun(){const p=$('fpkg').value,s=$('fscr').value;if(!p||!s)return toast('Fill fields','err');$('fout').textContent='Running...';const r=await api(`/api/frida/run?package=${enc(p)}&script=${enc(s)}&spawn=true`,'POST');$('fout').textContent=(r?.logs||[]).join('\n')||r?.message||'No output'}
async function fridaCustom(){const p=$('fpkg')?.value,c=$('fcustom').value;if(!p||!c)return toast('Fill fields','err');$('fout').textContent='Running...';const r=await api(`/api/frida/run-custom?package=${enc(p)}&code=${enc(c)}&spawn=true`,'POST');$('fout').textContent=(r?.logs||[]).join('\n')||r?.message||'No output'}

// ────────────────── OBJECTION (persistent session) ──────────────────
let _objConnected=false,_objPkg='';
async function pgObjection(mc){
  mc.innerHTML=`
    <div class="page-title">Objection – Runtime Mobile Exploration</div>
    <div class="card">
      <div class="card-title">Session</div>
      <div class="ig">
        <input id="obpkg" placeholder="com.example.app" value="${esc(selPkg)}">
        <button class="btn btn-accent" id="ob-explore-btn" onclick="objExplore()">Explore</button>
        <button class="btn btn-red" id="ob-stop-btn" onclick="objStop()" style="display:none">Stop</button>
      </div>
      <div id="ob-session" style="margin-top:6px;font-size:11px;color:var(--t3)">Not connected</div>
    </div>
    <div class="card" id="ob-cmd-card" style="${_objConnected?'':'opacity:0.5'}">
      <div class="card-title">Run Command</div>
      <div class="ig"><input id="obcmd" placeholder="android sslpinning disable" ${_objConnected?'':'disabled'}><button class="btn btn-accent" onclick="objRun()" ${_objConnected?'':'disabled'}>Run</button></div>
      <div id="ob-cmd-out" style="margin-top:6px"></div>
    </div>
    <div class="card">
      <div class="card-title">Common Commands</div>
      <table>
        ${[['env','Show app environment info'],['android sslpinning disable','Disable SSL pinning'],['android root disable','Bypass root detection'],['android hooking list activities','List all activities'],['android hooking list services','List all services'],['android hooking list receivers','List broadcast receivers'],['android hooking list classes','List loaded classes (slow)'],['android hooking search classes <keyword>','Search classes by keyword'],['android hooking watch class <class>','Hook all methods in class'],['android keystore list','List keystore items'],['android clipboard monitor','Monitor clipboard'],['memory list modules','List loaded native modules'],['memory dump all <dir>','Dump all memory to directory'],['sqlite connect <db>','Connect to SQLite database'],['android intent launch_activity <activity>','Launch activity']].map(([c,d])=>`<tr><td><code style="font-size:10.5px;cursor:pointer;color:var(--accent)" onclick="$('obcmd').value='${esc(c)}'">${esc(c)}</code></td><td style="font-size:11px;color:var(--t2)">${esc(d)}</td></tr>`).join('')}
      </table>
    </div>
    <div id="ob-results"></div>`;
  if(_objConnected&&_objPkg)_showObjConnected();
}
function _showObjConnected(){
  const s=$('ob-session');if(s)s.innerHTML=`<span class="tag tag-g">Connected</span> to <strong>${esc(_objPkg)}</strong>`;
  const eb=$('ob-explore-btn');if(eb)eb.style.display='none';
  const sb=$('ob-stop-btn');if(sb)sb.style.display='';
  const cc=$('ob-cmd-card');if(cc)cc.style.opacity='1';
  const ci=$('obcmd');if(ci)ci.disabled=false;
  const cb=cc?.querySelector('button');if(cb)cb.disabled=false;
}
async function objExplore(){
  const p=$('obpkg').value.trim();if(!p)return toast('Enter package','err');
  const s=$('ob-session');s.innerHTML='<span style="color:var(--t3)">Connecting to '+esc(p)+' (requires frida-server + app running)...</span>';
  const d=$('ob-results');d.innerHTML=cardLoading('Exploring...');
  const r=await api(`/api/agents/objection/explore/${p}`,'POST');
  if(r?.detail){s.innerHTML='<span class="tag tag-r">Failed</span>';d.innerHTML=`<div class="card" style="border-left:3px solid var(--red)">${esc(r.detail)}</div>`;return}
  if(!r?.connected){s.innerHTML='<span class="tag tag-r">Failed</span> '+esc(r?.error||'');d.innerHTML='';return}
  _objConnected=true;_objPkg=p;
  _showObjConnected();
  const res=r?.results||{};
  d.innerHTML=Object.entries(res).map(([k,v])=>`<div class="card"><div class="card-title">${esc(k)} <span class="tag ${v?.success?'tag-g':'tag-r'}">${v?.success?'OK':'FAIL'}</span></div><pre class="terminal" style="max-height:180px">${esc(v?.output||'No output')}</pre></div>`).join('');
}
async function objStop(){
  if(_objPkg)await api(`/api/agents/objection/stop/${_objPkg}`,'POST');
  _objConnected=false;_objPkg='';
  toast('Objection session stopped','ok');nav('objection');
}
async function objRun(){
  const p=_objPkg||$('obpkg').value.trim(),c=$('obcmd').value.trim();
  if(!p||!c)return toast('Fill fields','err');
  const isHeavy=c.includes('dump')||c.includes('list classes')||c.includes('memory');
  const timeout=isHeavy?300:30;
  const d=$('ob-cmd-out');d.innerHTML=cardLoading(`Running: ${c}${isHeavy?' (extended timeout)':''}...`);
  const r=await api(`/api/agents/objection/run?package=${enc(p)}&command=${enc(c)}&timeout=${timeout}`,'POST');
  const ok=r?.success;
  d.innerHTML=`<div style="border:1px solid var(--bd);border-radius:var(--r);padding:8px;margin-top:4px">
    <div style="display:flex;justify-content:space-between;margin-bottom:4px"><strong style="font-size:11px">${esc(c)}</strong><span class="tag ${ok?'tag-g':'tag-r'}">${ok?'OK':'FAIL'}</span></div>
    ${r?.output?`<pre class="terminal" style="max-height:200px">${esc(r.output)}</pre>`:''}
    ${r?.error?`<pre class="terminal" style="color:var(--red)">${esc(r.error)}</pre>`:''}
  </div>`;
}

// ────────────────── MEDUSA (stash → compile → run) ──────────────────
async function pgMedusa(mc){
  mc.innerHTML=loading();
  const[mods,snips,staged]=await Promise.all([api('/api/agents/medusa/modules'),api('/api/agents/medusa/snippets'),api('/api/agents/medusa/staged')]);
  const modules=mods?.modules||[];const snippets=snips?.snippets||[];const stashed=staged?.staged||[];
  const cats=[...new Set(modules.map(m=>m.category))].sort();
  mc.innerHTML=`
    <div class="page-title">Medusa – Dynamic Analysis Framework</div>
    <div class="g2">
      <div class="card">
        <div class="card-title">① Stashed Modules <span class="tag">${stashed.length}</span></div>
        <div id="md-stashed" style="min-height:40px">${stashed.length?stashed.map(s=>`<div style="display:flex;justify-content:space-between;align-items:center;padding:3px 0;border-bottom:1px solid var(--bd)"><code style="font-size:10.5px">${esc(s.name)}</code><button class="btn btn-sm btn-red" onclick="mdUnstash('${esc(s.path)}')">✕</button></div>`).join(''):'<span style="color:var(--t3);font-size:11px">No modules stashed. Click + on modules below to add.</span>'}</div>
        <div style="display:flex;gap:6px;margin-top:8px">
          <button class="btn btn-sm" onclick="mdReset()">Reset All</button>
        </div>
      </div>
      <div class="card">
        <div class="card-title">② Compile & Run</div>
        <div class="fg"><label class="fl">Package</label><input id="mdpkg" placeholder="com.example.app" value="${esc(selPkg)}"></div>
        <div class="fg" style="margin-top:4px"><label class="fl">Timeout (sec)</label><input id="mdtimeout" type="number" value="60" min="10" max="300" style="width:80px"></div>
        <div style="display:flex;gap:6px;margin-top:6px">
          <button class="btn btn-accent" onclick="mdCompileAll()">Compile</button>
          <button class="btn btn-green" onclick="mdRunSession()">Run Session</button>
        </div>
        <div id="md-status" style="margin-top:6px"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Quick Run (single module)</div>
      <div class="g2">
        <div class="fg"><label class="fl">Module</label><input id="mdmod" placeholder="Click a module below"></div>
        <div style="display:flex;gap:6px;align-items:end;padding-bottom:8px"><button class="btn btn-accent" onclick="mdQuickRun()">Quick Run</button></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Modules (${modules.length})</div>
      <div class="md-tabs-wrap" id="md-tabs">${cats.map((c,i)=>`<div class="md-tab${i===0?' active':''}" onclick="mdTab('${esc(c)}',this)">${esc(c)} <span class="tag" style="font-size:9px;padding:0 4px">${modules.filter(m=>m.category===c).length}</span></div>`).join('')}</div>
      <div id="md-list" style="max-height:340px;overflow-y:auto;margin-top:8px">${renderMedusaList(modules,cats[0]||'')}</div>
    </div>
    ${snippets.length?`<div class="card"><div class="card-title">Snippets (${snippets.length})</div><table>${snippets.map(s=>`<tr><td><code style="font-size:10.5px;cursor:pointer;color:var(--accent)" onclick="$('mdmod').value='${esc(s.filename||'')}'">${esc(s.name||'')}</code></td><td style="font-size:10.5px;color:var(--t2)">${s.lines||0} lines</td></tr>`).join('')}</table></div>`:''}
    <div id="md-results"></div>`;
  window._mdModules=modules;window._mdCats=cats;
}
function renderMedusaList(modules,cat){
  const filtered=modules.filter(m=>m.category===cat);
  return `<table>${filtered.map(m=>`<tr>
    <td style="width:24px"><button class="btn btn-sm" style="padding:1px 5px;font-size:9px" onclick="mdStash('${esc(m.path)}')">+</button></td>
    <td><code style="font-size:10.5px;cursor:pointer;color:var(--accent)" onclick="$('mdmod').value='${esc(m.path||'')}'" title="${esc(m.help||'')}">${esc(m.name||'')}</code></td>
    <td style="font-size:10.5px;color:var(--t2)">${esc((m.description||'').substring(0,60))}</td>
  </tr>`).join('')}</table>`;
}
function mdTab(cat,el){document.querySelectorAll('#md-tabs .md-tab').forEach(t=>t.classList.remove('active'));el.classList.add('active');$('md-list').innerHTML=renderMedusaList(window._mdModules||[],cat)}

async function mdStash(path){const r=await api(`/api/agents/medusa/stash?module_path=${enc(path)}`,'POST');if(r?.success){toast(r.message,'ok');_refreshStaged(r.staged)}else{toast(r?.message||'Failed','err')}}
async function mdUnstash(path){const r=await api(`/api/agents/medusa/unstash?module_path=${enc(path)}`,'POST');_refreshStaged(r?.staged||[])}
async function mdReset(){await api('/api/agents/medusa/reset','POST');toast('Stash cleared','ok');nav('medusa')}
function _refreshStaged(staged){
  const el=$('md-stashed');if(!el)return;
  el.innerHTML=staged.length?staged.map(s=>`<div style="display:flex;justify-content:space-between;align-items:center;padding:3px 0;border-bottom:1px solid var(--bd)"><code style="font-size:10.5px">${esc(s.name)}</code><button class="btn btn-sm btn-red" onclick="mdUnstash('${esc(s.path)}')">✕</button></div>`).join(''):'<span style="color:var(--t3);font-size:11px">Empty</span>';
  const badge=el.parentElement?.querySelector('.card-title .tag');
  if(badge)badge.textContent=staged.length;
}

async function mdCompileAll(){
  $('md-status').innerHTML='<span style="color:var(--t3)">Compiling stashed modules...</span>';
  const r=await api('/api/agents/medusa/compile','POST');
  if(r?.success){
    $('md-status').innerHTML='<span class="tag tag-g">Compiled</span>';
    $('md-results').innerHTML=`<div class="card"><div class="card-title">Compiled Script</div><pre class="terminal" style="max-height:250px">${esc((r.script||'').substring(0,3000))}</pre></div>`;
  }else{$('md-status').innerHTML='<span class="tag tag-r">'+(esc(r?.script||'Failed'))+'</span>'}
}
async function mdRunSession(){
  const p=$('mdpkg').value.trim();if(!p)return toast('Enter package','err');
  const t=parseInt($('mdtimeout')?.value)||60;
  $('md-status').innerHTML=`<span style="color:var(--t3)">Compiling & running session (${t}s)...</span>`;
  const c=await api('/api/agents/medusa/compile','POST');
  if(!c?.success){$('md-status').innerHTML='<span class="tag tag-r">'+(esc(c?.script||'Compile failed'))+'</span>';return}
  $('md-status').innerHTML=`<span style="color:var(--t3)">Running on ${esc(p)} for ${t}s... hooks will capture activity</span>`;
  const r=await api(`/api/agents/medusa/run?package=${enc(p)}&spawn=true&timeout=${t}`,'POST');
  const ok=r?.success;
  $('md-status').innerHTML=ok?'<span class="tag tag-g">Done</span>':'<span class="tag tag-r">Error</span>';
  $('md-results').innerHTML=`<div class="card"><div class="card-title">Session Output <span class="tag ${ok?'tag-g':'tag-r'}">${ok?'OK':'FAIL'}</span> · ${r?.modules_count||0} modules</div><pre class="terminal" style="max-height:500px">${esc(r?.output||r?.error||'No output')}</pre></div>`;
}
async function mdQuickRun(){
  const p=$('mdpkg').value.trim(),m=$('mdmod').value.trim();
  if(!p||!m)return toast('Fill package and module','err');
  const t=parseInt($('mdtimeout')?.value)||60;
  $('md-status').innerHTML=`<span style="color:var(--t3)">Quick running ${esc(m)} (${t}s)...</span>`;
  const r=await api(`/api/agents/medusa/run?module_path=${enc(m)}&package=${enc(p)}&spawn=true&timeout=${t}`,'POST');
  const ok=r?.success;
  $('md-status').innerHTML=ok?'<span class="tag tag-g">Done</span>':'<span class="tag tag-r">Error</span>';
  $('md-results').innerHTML=`<div class="card"><div class="card-title">Output <span class="tag ${ok?'tag-g':'tag-r'}">${ok?'OK':'FAIL'}</span></div><pre class="terminal" style="max-height:500px">${esc(r?.output||r?.error||'No output')}</pre></div>`;
}

// ────────────────── MEMORY ──────────────────
const _sensPresets={
  'Auth Tokens':'auth|token|access_token|refresh_token|bearer|session|cookie',
  'Credentials':'password|passwd|secret|credential|login|username',
  'JWT/Keys':'jwt|private.key|api.key|apikey|secret.key|signing',
  'Database':'sqlite|sql|room|database|INSERT|SELECT|CREATE TABLE',
  'URLs':'https?://|ftp://|ws://|wss://',
  'PII':'email|phone|ssn|credit.card|address',
  'Crypto':'AES|RSA|SHA|HMAC|encrypt|decrypt|cipher|iv=|nonce',
};
async function pgMem(mc){
  mc.innerHTML=`
    <div class="page-title">Memory Analysis (fridump)</div>
    <div class="card">
      <div class="card-title">Dump Process Memory</div>
      <div class="g2">
        <div class="fg"><label class="fl">Process / Package</label><input id="mpkg" value="${esc(selPkg)}" placeholder="com.example.app"></div>
        <div style="display:flex;gap:12px;align-items:end;padding-bottom:8px">
          <label style="font-size:11px"><input type="checkbox" id="mstr" checked> Extract strings</label>
          <label style="font-size:11px"><input type="checkbox" id="mro"> Read-only regions</label>
        </div>
      </div>
      <button class="btn btn-accent btn-lg" onclick="fridump()">Dump Memory</button>
      <div id="mp" style="margin-top:8px"></div>
    </div>
    <div id="mr"></div>`;
}
async function fridump(){
  const p=$('mpkg').value.trim();if(!p)return toast('Enter process','err');
  $('mp').innerHTML='<div style="color:var(--t3)">Dumping memory... this may take a while (up to 5 min)</div><div class="progress"><div class="progress-bar" style="width:20%;animation:pulse 1.5s infinite"></div></div>';
  const r=await api(`/api/agents/fridump/${p}?strings=${$('mstr').checked}&read_only=${$('mro').checked}`,'POST');
  $('mp').innerHTML='';
  const d=$('mr');
  if(r?.detail){d.innerHTML=`<div class="card" style="border-left:3px solid var(--red)"><strong>Prerequisite:</strong> ${esc(r.detail)}</div>`;return}
  if(!r?.success){d.innerHTML=`<div class="card" style="border-left:3px solid var(--red)"><strong>Error:</strong> ${esc(r?.error||'Unknown')}<pre class="terminal" style="margin-top:4px">${esc(r?.output||'')}</pre><div style="margin-top:6px;font-size:11px;color:var(--t3)">Make sure:<br>1. frida-server is running on device<br>2. The app/process is currently running<br>3. Package name matches a running process</div></div>`;return}
  d.innerHTML=`
    <div class="g3"><div class="card stat"><div class="n">${r.dump_files}</div><div class="l">Regions</div></div><div class="card stat"><div class="n">${fmtB(r.total_size)}</div><div class="l">Total</div></div><div class="card stat"><div class="n" style="color:var(--red)">${(r.findings||[]).length}</div><div class="l">Secrets Found</div></div></div>
    ${r.findings?.length?`<div class="card"><div class="card-title">Secret Detection (${r.findings.length} findings)</div>${renderFindings(r.findings)}</div>`:'<div class="card" style="border-left:3px solid var(--green)"><strong>No secrets detected</strong> in memory dump. Use the Search below to look for specific patterns.</div>'}
    ${r.sensitive_strings?.length?`<div class="card"><div class="card-title">Detected Secrets</div><table><tr><th>Type</th><th style="width:100%">Value</th></tr>${r.sensitive_strings.map(s=>{const crit=['JWT','AuthToken','RefreshToken','Password','PrivateKey','AWSAccessKey','AWSSecretKey','URLCredentials','DBConnection'];const hi=['Secret/Key','GoogleAPIKey','FirebaseKey','SessionCookie','Base64Token','KeystorePass','GitHubToken'];const sev=crit.includes(s.type)?'CRITICAL':hi.includes(s.type)?'HIGH':'MEDIUM';return`<tr><td><span class="sev sev-${sev}">${esc(s.type)}</span></td><td style="font:11px var(--mono);word-break:break-all;max-width:600px;overflow:hidden">${esc(s.value.length>200?s.value.slice(0,200)+'...':s.value)}</td></tr>`}).join('')}</table></div>`:''}
    <div class="card"><div class="card-title">Search Strings</div>
      <div class="ig"><input id="msq" placeholder="password, token, key..."><button class="btn btn-accent" onclick="fdSearch('${esc(r.dump_dir||'')}')">Search</button></div>
      <div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:4px">${Object.entries(_sensPresets).map(([k,v])=>`<button class="btn btn-sm" onclick="$('msq').value='${v}';fdSearch('${esc(r.dump_dir||'')}')">${k}</button>`).join('')}</div>
      <div id="msr" style="margin-top:6px"></div>
    </div>`;
}
async function fdSearch(dir){const q=$('msq').value.trim();if(!q)return;const r=await api(`/api/agents/fridump/search?output_dir=${enc(dir)}&query=${enc(q)}`,'POST');$('msr').innerHTML=r?.results?.length?`<div class="terminal" style="max-height:180px">${r.results.map(s=>esc(s)).join('\n')}</div>`:'<span style="color:var(--t3)">No results</span>'}

// ────────────────── TRAFFIC INSPECTOR ──────────────────
async function pgTraffic(mc){
  mc.innerHTML=loading();
  const[proxy,cert]=await Promise.all([api('/api/traffic/proxy'),api('/api/traffic/cert/status')]);
  const isSet=proxy?.configured;
  const parts=(proxy?.proxy||'').split(':');
  const curHost=parts.slice(0,-1).join(':')||'';
  const curPort=parts[parts.length-1]||'';
  mc.innerHTML=`
    <div class="page-title">Traffic Inspector</div>
    <div class="g2">
      <div class="card">
        <div class="card-title">Proxy Configuration</div>
        <div style="margin-bottom:8px">
          <span>Status: </span>${isSet?`<span class="tag tag-g">Active</span> <code style="font-size:11px">${esc(proxy.proxy)}</code>`:'<span class="tag tag-r">Not configured</span>'}
        </div>
        <div class="fg"><label class="fl">Host (your machine IP)</label><input id="px-host" value="${esc(curHost||'192.168.1.')}" placeholder="192.168.1.100"></div>
        <div class="fg"><label class="fl">Port</label><input id="px-port" value="${esc(curPort||'8080')}" placeholder="8080" type="number"></div>
        <div style="display:flex;gap:6px;margin-top:8px">
          <button class="btn btn-accent" onclick="pxSet()">Set Proxy</button>
          <button class="btn btn-red" onclick="pxReset()">Clear Proxy</button>
          <button class="btn" onclick="pxCheck()">Refresh Status</button>
        </div>
        <div id="px-msg" style="margin-top:6px;font-size:11px"></div>
      </div>
      <div class="card">
        <div class="card-title">Burp Suite CA Certificate</div>
        <div style="margin-bottom:8px;font-size:11px;color:var(--t2)">
          System certs: <strong>${cert?.system_certs_count||0}</strong>
          ${cert?.user_certs?` · User certs: <code>${esc(cert.user_certs)}</code>`:''}
        </div>
        <div style="display:flex;gap:6px;margin-bottom:8px">
          <button class="btn btn-accent" onclick="certInstall()">Auto Install from Burp</button>
          <label class="btn" style="cursor:pointer">Upload Cert <input type="file" id="cert-file" accept=".der,.cer,.pem,.crt" style="display:none" onchange="certUpload()"></label>
        </div>
        <div id="cert-msg" style="font-size:11px"></div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Setup Guide</div>
      <div style="font-size:12px;line-height:1.8">
        <strong>Step 1:</strong> Start Burp Suite and configure the proxy listener (Proxy → Options → Listeners)<br>
        <strong>Step 2:</strong> Set your machine's local IP and port (default 8080)<br>
        <strong>Step 3:</strong> Click <strong>Set Proxy</strong> above to configure the device<br>
        <strong>Step 4:</strong> Click <strong>Auto Install from Burp</strong> to download and install the CA cert as a system certificate<br>
        <strong>Step 5:</strong> Reboot device if needed for cert changes to take effect<br>
        <div style="margin-top:8px;padding:8px;background:var(--bg2);border-radius:var(--r);font-size:11px">
          <strong style="color:var(--orange)">Requirements:</strong><br>
          · Rooted device or emulator with writable /system for system cert install<br>
          · Burp Suite running and accessible from device network<br>
          · <code>openssl</code> available on host for cert conversion<br>
          · Device and host on the same network
        </div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Quick ADB Commands</div>
      <table>
        ${[
          ['Check current proxy','settings get global http_proxy'],
          ['List system CAs','ls /system/etc/security/cacerts/ | head -20'],
          ['Check connectivity','ping -c 1 google.com'],
          ['List WiFi info','dumpsys wifi | grep -i "ssid\\|ip\\|proxy"'],
          ['Reboot device','reboot'],
        ].map(([d,c])=>`<tr><td style="font-size:11px;color:var(--t2);width:160px">${esc(d)}</td><td><code style="font-size:10.5px;cursor:pointer;color:var(--accent)" onclick="pxShell('${esc(c)}')">${esc(c)}</code></td></tr>`).join('')}
      </table>
      <div id="px-shell-out" style="margin-top:6px"></div>
    </div>`;
}
async function pxSet(){
  const h=$('px-host').value.trim(),p=$('px-port').value.trim();
  if(!h||!p)return toast('Fill host and port','err');
  $('px-msg').innerHTML='<span style="color:var(--t3)">Setting proxy...</span>';
  const r=await api(`/api/traffic/proxy/set?host=${enc(h)}&port=${enc(p)}`,'POST');
  $('px-msg').innerHTML=r?.success?'<span style="color:var(--green)">Proxy set to '+esc(r.proxy)+'</span>':'<span style="color:var(--red)">Failed: '+esc(r?.output||'')+'</span>';
  if(r?.success)toast('Proxy configured','ok');
}
async function pxReset(){
  $('px-msg').innerHTML='<span style="color:var(--t3)">Clearing proxy...</span>';
  const r=await api('/api/traffic/proxy/reset','POST');
  $('px-msg').innerHTML=r?.success?'<span style="color:var(--green)">Proxy cleared</span>':'<span style="color:var(--red)">Failed</span>';
  toast('Proxy cleared','ok');
}
async function pxCheck(){nav('traffic')}
async function certInstall(){
  const m=$('cert-msg');
  m.innerHTML='<span style="color:var(--t3)">Downloading cert from Burp proxy and installing...</span>';
  const r=await api('/api/traffic/cert/install','POST');
  if(r?.success){
    m.innerHTML='<span style="color:var(--green)">✓ CA cert installed as system certificate</span>';
    toast('Burp CA installed','ok');
  }else{
    const steps=(r?.steps||[]).map(s=>`<div style="padding:2px 0">${s.success?'<span style="color:var(--green)">✓</span>':'<span style="color:var(--red)">✗</span>'} <strong>${esc(s.step)}</strong>: ${esc(s.detail||'')}</div>`).join('');
    m.innerHTML=`<div style="border-left:3px solid var(--red);padding-left:8px">${steps}<div style="margin-top:4px;color:var(--red)">${esc(r?.error||'Installation failed')}</div></div>`;
  }
}
async function certUpload(){
  const f=$('cert-file').files[0];if(!f)return;
  const m=$('cert-msg');m.innerHTML='<span style="color:var(--t3)">Uploading and installing cert...</span>';
  const fd=new FormData();fd.append('file',f);
  try{
    const r=await fetch('/api/traffic/cert/upload',{method:'POST',body:fd}).then(r=>r.json());
    m.innerHTML=r?.success?'<span style="color:var(--green)">✓ '+esc(r.message)+'</span>':'<span style="color:var(--red)">'+esc(r?.message||r?.error||'Failed')+'</span>';
  }catch(e){m.innerHTML='<span style="color:var(--red)">Upload failed</span>'}
}
async function pxShell(cmd){
  const d=$('px-shell-out');d.innerHTML=cardLoading('Running...');
  const r=await api(`/api/device/shell?cmd=${enc(cmd)}`,'POST');
  d.innerHTML=`<pre class="terminal" style="max-height:150px">${esc(r?.output||'No output')}</pre>`;
}

// ────────────────── SHELL ──────────────────
let shHistory=[], shIdx=-1;
function pgShell(mc){
  mc.innerHTML=`
    <div class="page-title">ADB Shell</div>
    <div class="card">
      <div id="sho" class="terminal" style="min-height:300px;max-height:500px">Welcome to AndroidINONE ADB Shell.\nType a command below or click an example.\n\n</div>
      <div class="term-input"><span>$</span><input id="shc" placeholder="type command..." onkeydown="shKey(event)"></div>
    </div>
    <div class="card">
      <div class="card-title">Quick Commands</div>
      <div class="g3">
        <div>
          <div class="fl">Device Info</div>
          ${['id','getprop ro.build.version.release','getprop ro.product.model','uname -a','cat /proc/version','getenforce','mount | grep /data'].map(c=>`<code class="sh-ex" onclick="shSet('${esc(c)}')">${esc(c)}</code>`).join('')}
        </div>
        <div>
          <div class="fl">App Analysis</div>
          ${['pm list packages -3','pm list packages -f','dumpsys activity activities','dumpsys meminfo','ps -A | grep -i com.','logcat -d -t 50','content query --uri content://settings/secure --projection name:value'].map(c=>`<code class="sh-ex" onclick="shSet('${esc(c)}')">${esc(c)}</code>`).join('')}
        </div>
        <div>
          <div class="fl">Security Checks</div>
          ${['cat /system/build.prop | grep debug','which su','ls -la /data/local/tmp/','netstat -tlnp','ls /data/data/','cat /proc/net/tcp','settings get secure android_id'].map(c=>`<code class="sh-ex" onclick="shSet('${esc(c)}')">${esc(c)}</code>`).join('')}
        </div>
      </div>
    </div>`;
}
function shSet(c){$('shc').value=c;$('shc').focus()}
function shKey(e){if(e.key==='Enter')shExec();else if(e.key==='ArrowUp'){e.preventDefault();if(shIdx<shHistory.length-1){shIdx++;$('shc').value=shHistory[shIdx]}}else if(e.key==='ArrowDown'){e.preventDefault();if(shIdx>0){shIdx--;$('shc').value=shHistory[shIdx]}else{shIdx=-1;$('shc').value=''}}}
async function shExec(){const i=$('shc'),c=i.value.trim();if(!c)return;i.value='';shHistory.unshift(c);shIdx=-1;const o=$('sho');o.textContent+=`$ ${c}\n`;const r=await api(`/api/device/shell?cmd=${enc(c)}`,'POST');o.textContent+=(r?.output||'(no output)')+'\n';o.scrollTop=o.scrollHeight}

// ────────────────── REPORTS ──────────────────
async function pgReports(mc){
  const r=await api('/api/reports');const reps=r?.reports||[];
  mc.innerHTML=`
    <div class="page-title">Reports</div>
    <div class="card">
      ${reps.length?`<table><tr><th>File</th><th>Format</th><th>Size</th><th></th></tr>
      ${reps.map(r=>`<tr><td style="font:11px var(--mono)">${esc(r.filename)}</td><td>${esc(r.format?.toUpperCase()||'')}</td><td>${fmtB(r.size||0)}</td><td><button class="btn btn-sm btn-accent" onclick="previewRpt('${esc(r.filename)}')">Preview</button> <button class="btn btn-sm" onclick="window.open('/api/reports/${esc(r.filename)}')">Download</button></td></tr>`).join('')}</table>`:'<span style="color:var(--t3)">No reports yet. Run a scan and click Report to generate.</span>'}
    </div>
    <div id="rpc"></div>`;
}
function previewRpt(f){$('rpc').innerHTML=`<div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px"><strong>Preview: ${esc(f)}</strong><button class="btn btn-sm" onclick="$('rpc').innerHTML=''">Close</button></div><div class="rp-frame"><iframe src="/api/reports/preview/${esc(f)}"></iframe></div></div>`}

// ═══════════ INLINE EXPAND/COLLAPSE FINDINGS ═══════════
function renderFindings(fs){
  if(!fs?.length)return'<span style="color:var(--t3)">No findings</span>';
  const order={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
  fs.sort((a,b)=>(order[a.severity]??5)-(order[b.severity]??5));
  const base=_fs.length;_fs.push(...fs);
  return'<div class="findings-list">'+fs.map((f,i)=>{
    const idx=base+i;
    return`<div class="finding-wrap" id="fw${idx}"><div class="finding" onclick="toggleFinding(${idx})"><span class="sev sev-${f.severity||'INFO'}">${f.severity||'INFO'}</span><div style="flex:1;min-width:0"><div class="finding-title">${esc(f.title||'')}</div><div class="finding-meta">${esc(f.category||'')}${f.location?' · '+esc(f.location):''}</div></div><span class="finding-arrow" id="fa${idx}">▸</span></div></div>`;
  }).join('')+'</div>';
}
function toggleFinding(idx){
  const wrap=document.getElementById('fw'+idx);
  const arrow=document.getElementById('fa'+idx);
  const existing=wrap.querySelector('.finding-detail');
  const fEl=wrap.querySelector('.finding');
  if(existing){existing.remove();fEl.classList.remove('expanded');arrow.textContent='▸';return}
  fEl.classList.add('expanded');arrow.textContent='▾';
  const f=_fs[idx];if(!f)return;
  const det=document.createElement('div');det.className='finding-detail';
  det.innerHTML=`<table>
    <tr><td class="fd-label">Severity</td><td><span class="sev sev-${f.severity||'INFO'}">${f.severity||'INFO'}</span>${f.cvss?` <span class="tag">CVSS ${f.cvss}</span>`:''}</td></tr>
    <tr><td class="fd-label">Category</td><td>${esc(f.category||'-')}</td></tr>
    <tr><td class="fd-label">Location</td><td style="font:11px var(--mono)">${esc(f.location||'-')}</td></tr>
    <tr><td class="fd-label">Description</td><td>${esc(f.description||'-')}</td></tr>
    ${f.evidence?`<tr><td class="fd-label">Evidence</td><td><pre class="terminal" style="max-height:100px;margin:0">${esc(f.evidence)}</pre></td></tr>`:''}
    ${f.recommendation?`<tr><td class="fd-label">Fix</td><td style="color:var(--green)">${esc(f.recommendation)}</td></tr>`:''}
    ${f.owasp?`<tr><td class="fd-label">OWASP</td><td>${esc(f.owasp)}</td></tr>`:''}
  </table>`;
  wrap.appendChild(det);
}

// ═══════════ MODAL (used only for scan view) ═══════════
function openModal(title,body){$('modal-body').innerHTML=`<div class="modal-head"><h3>${esc(title)}</h3><button class="modal-close" onclick="closeModal()">×</button></div>${body}`;$('modal-overlay').style.display='flex'}
function closeModal(){$('modal-overlay').style.display='none'}

// ═══════════ UTILS ═══════════
async function api(u,m='GET'){try{const r=await fetch(u,{method:m});return await r.json()}catch(e){console.error(e);return null}}
function $(id){return document.getElementById(id)}
function esc(s){if(typeof s!=='string')return'';const d=document.createElement('div');d.textContent=s;return d.innerHTML}
function enc(s){return encodeURIComponent(s)}
function toast(m,t='info'){const c=$('toasts'),e=document.createElement('div');e.className=`toast toast-${t}`;e.textContent=m;c.appendChild(e);setTimeout(()=>e.remove(),4000);return true}
function fmtB(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB'}
function sleep(ms){return new Promise(r=>setTimeout(r,ms))}
function loading(){return'<div style="color:var(--t3);padding:20px">Loading...</div>'}
function cardLoading(m){return`<div class="card" style="color:var(--t3)">${esc(m)}</div>`}
function sevColor(s){return{CRITICAL:'red',HIGH:'orange',MEDIUM:'yellow',LOW:'cyan',INFO:'accent'}[s]||'accent'}
function isDangerousPerm(p){return['CAMERA','CONTACTS','LOCATION','MICROPHONE','PHONE','SMS','STORAGE','CALENDAR','BODY_SENSORS','CALL_LOG'].some(d=>p.toUpperCase().includes(d))}

// ═══════════ INIT ═══════════
wsInit();
pgDash($('mc'));
(async()=>{const r=await api('/api/packages?system=false');pkgs=r?.packages||[]})();
