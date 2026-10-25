/* Asset inventory workspace; local, ephemeral browser state. */
(function(){
"use strict";
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;};
let assets=[],result=null,currentCVEs=[];
const api=()=>window.ZeroGuardMatcher;
function feedback(message){$("asset-feedback").textContent=message;}
function csvCell(value){let s=String(value??"");if(/^[=+@\-]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';}
function download(name,body){const url=URL.createObjectURL(new Blob([body],{type:"text/csv;charset=utf-8"}));const a=el("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function setVulnerabilities(items){currentCVEs=Array.isArray(items)?items:[];if(assets.length)run();}
async function upload(e){
 const files=Array.from(e.target.files||[]);if(!files.length)return;
 const imported=[];const errors=[];
 for(const file of files){try{
  if(file.size>5*1024*1024)throw Error("File exceeds 5 MB.");
  let rows;
  if(/\.xlsx$/i.test(file.name)){if(!window.ZeroGuardXLSX)throw Error("Excel parser not loaded.");rows=await window.ZeroGuardXLSX.parse(await file.arrayBuffer(),file.name);}
  else rows=api().parseInventory(await file.text(),file.name);
  imported.push(...rows);
 }catch(err){errors.push(file.name+": "+err.message);}}
 if(imported.length){
  const map=new Map([...assets,...imported].map(x=>[x.id,x]));assets=Array.from(map.values());
  if(assets.length>api().MAX_ASSETS){feedback("Too many assets; maximum 5,000.");return;}
  result=null;
  if(imported.some(x=>x.site))$("asset-mode").value="ot-screen";
 }
 const sites=new Set(assets.map(x=>x.site).filter(Boolean));
 const qty=assets.reduce((n,x)=>n+(Number(x.quantity)||1),0);
 feedback(assets.length+" equipment lines / "+qty+" reported devices"+(sites.size?" across "+sites.size+" substations":"")+(errors.length?". Import issues: "+errors.join("; "):"")+". Run assessment.");
 render();e.target.value="";
}
function add(){try{const name=$("asset-name").value.trim(),version=$("asset-version").value.trim(),host=$("asset-host").value.trim();if(!name)throw Error("Enter a product name.");if(assets.length>=api().MAX_ASSETS)throw Error("Asset limit reached.");assets.push({id:"manual-"+(assets.length+1),name,version,host,vendor:"",purl:"",cpe:"",criticality:"medium",exposure:"unknown"});result=null;feedback(assets.length+" assets in current workspace.");$("asset-name").value="";$("asset-version").value="";$("asset-host").value="";render();}catch(err){feedback(err.message);}}
function run(){if(!assets.length){feedback("Import or add at least one asset.");return;}const mode=$("asset-mode").value;
 result=api().scan(assets,currentCVEs,{discovery:mode==="discovery",otScreen:mode==="ot-screen"});feedback("Assessed "+assets.length+" assets against "+currentCVEs.length+" loaded CVEs. The inventory remains in this browser session.");render();}
function filtered(){const text=$("asset-filter").value.toLowerCase().trim(),status=$("asset-status").value;return(result?.findings||[]).filter(f=>(status==="all"||f.status===status)&&(!text||[f.assetName,f.host,f.cve,f.evidence.system].join(" ").toLowerCase().includes(text)));}
function render(){const stats=$("asset-stats"),root=$("asset-findings");stats.replaceChildren();root.replaceChildren();
for(const [label,val] of [["Assets",assets.length],["CVEs evaluated",currentCVEs.length],["Version matches",result?.confirmed||0],["OT model leads",result?.modelLeads||0]]){const card=el("div",undefined,"stat");card.append(el("label",label),el("strong",val));stats.append(card);}
if(!result){root.append(el("div","Import inventory then run assessment. No data leaves your browser.","empty"));return;}
const items=filtered();root.append(el("p",items.length+" displayed matches; "+(assets.length-result.matchedAssets)+" assets have no match in current feed. Absence of results does NOT prove safety.","muted"));
const box=el("div",undefined,"tablebox"),wrap=el("div",undefined,"table-scroll"),table=el("table",undefined,"datatable"),header=el("tr");
for(const label of ["Substation / equipment","CVE","Assessment","Evidence","Priority"])header.append(el("th",label));
const thead=el("thead");thead.append(header);table.append(thead);const tbody=el("tbody");
for(const f of items.slice(0,250)){const tr=el("tr"),asset=el("td");asset.append(el("strong",(f.site?f.site+" · ":"")+f.assetName),el("div",(f.quantity?"Qty "+f.quantity+" · ":"")+(f.room||f.host||f.assetId),"muted"));tr.append(asset);
const cv=el("td"),button=el("button",f.cve,"cve-link");button.addEventListener("click",()=>document.dispatchEvent(new CustomEvent("zeroguard:open-cve",{detail:{id:f.cve}})));cv.append(button);tr.append(cv);
tr.append(el("td",f.status==="model-lead"?"Model referenced · firmware unverified":f.status==="vendor-lead"?"Vendor-level lead · verify product":f.status==="discovery"?"Vendor research lead · NOT an affected asset":f.status==="version-match"?"Version match · verify applicability":"Needs verification"));
const evid=el("td");evid.append(el("div",f.evidence.system),el("small",(f.evidence.range||"Version unknown")+" · "+f.evidence.source,"muted"));
if(/^https:\/\//.test(f.evidence.url)){const a=el("a","Evidence ↗");a.href=f.evidence.url;a.target="_blank";a.rel="noopener noreferrer";evid.append(a);}tr.append(evid);tr.append(el("td",f.priority));tbody.append(tr);}
table.append(tbody);wrap.append(table);box.append(wrap);root.append(box);
if(items.length>250)root.append(el("p","Showing first 250 matches; CSV export includes all filtered findings.","muted"));}
function exportCSV(){const columns=["assetId","site","room","panel","assetType","quantity","assetName","host","cve","status","priority","kev","cvss","epss","system","affectedRange","source","evidenceUrl","identityMatch","versionCheck"];
const rows=filtered().map(f=>[f.assetId,f.site,f.room,f.panel,f.assetType,f.quantity,f.assetName,f.host,f.cve,f.status,f.priority,f.kev,f.cvss,f.epss,f.evidence.system,f.evidence.range,f.evidence.source,f.evidence.url,f.evidence.identity,f.evidence.versionResult]);
download("zeroguard-asset-findings.csv",[columns.join(","),...rows.map(r=>r.map(csvCell).join(","))].join("\r\n"));}
function quickDiscovery(){
 const q=$("asset-quick-query").value.trim(),root=$("asset-quick-results");root.replaceChildren();
 if(q.length<3){root.append(el("div","Enter at least three characters to discover vendor CVEs.","empty"));return;}
 const search=api().scan([{id:"vendor-lookup",name:q,version:"",vendor:""}],currentCVEs,{discovery:true});
 root.append(el("p",search.discovery+" matching CVE research leads for '"+q+"'. This is NOT proof your specific product/version is affected.","muted"));
 const wrap=el("div",undefined,"table-scroll"),table=el("table",undefined,"datatable");
 const head=el("tr");for(const label of ["CVE","Affected system / product","CISA KEV","CVSS","Investigate"])head.append(el("th",label));const thead=el("thead");thead.append(head);table.append(thead);
 const tbody=el("tbody");
 for(const f of search.findings.slice(0,100)){
  const row=el("tr");row.append(el("td",f.cve),el("td",f.evidence.system),el("td",f.kev?"Known exploited":"Not confirmed"),el("td",f.cvss??"Unscored"));
  const cell=el("td"),btn=el("button","Open CVE →","textbutton");btn.addEventListener("click",()=>document.dispatchEvent(new CustomEvent("zeroguard:open-cve",{detail:{id:f.cve}})));cell.append(btn);row.append(cell);tbody.append(row);
 }
 table.append(tbody);wrap.append(table);root.append(wrap);
 if(search.findings.length>100)root.append(el("p","Showing top 100 by triage priority. Use Search all for further research.","muted"));
 if(!search.discovery)root.append(el("div","No matching CVEs in the loaded dataset. This does not mean the vendor has no vulnerabilities.","empty"));
}
$("asset-quick-button").addEventListener("click",quickDiscovery);
$("asset-quick-query").addEventListener("keydown",e=>{if(e.key==="Enter")quickDiscovery();});
$("asset-file").addEventListener("change",upload);$("asset-add").addEventListener("click",add);$("asset-scan").addEventListener("click",run);
$("asset-mode").addEventListener("change",()=>{result=null;feedback("Assessment mode changed. Run assessment to update findings.");render();});
$("asset-filter").addEventListener("input",render);$("asset-status").addEventListener("change",render);
$("asset-clear").addEventListener("click",()=>{assets=[];result=null;feedback("Inventory cleared from the active browser session.");render();});
$("asset-export").addEventListener("click",exportCSV);
$("asset-template").addEventListener("click",()=>download("zeroguard-asset-template.csv",'id,name,vendor,version,purl,cpe,host,criticality,exposure\r\nexample-01,example-app,example,1.2.3,pkg:npm/example-app@1.2.3,,host-01,high,internal\r\n'));
document.addEventListener("zeroguard:feed",e=>setVulnerabilities(e.detail?.vulnerabilities));
render();
})();