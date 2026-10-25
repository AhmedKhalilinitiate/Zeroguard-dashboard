/* Asset inventory workspace; local, ephemeral browser state. */
(function(){
"use strict";
const $=id=>document.getElementById(id);
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;};
let assets=[],result=null,currentCVEs=[];
let reviews=new Map(),intelligenceDate="";
const api=()=>window.ZeroGuardMatcher;
function feedback(message){$("asset-feedback").textContent=message;}
function csvCell(value){let s=String(value??"");if(/^[=+@\-]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';}
function download(name,body){const url=URL.createObjectURL(new Blob([body],{type:"text/csv;charset=utf-8"}));const a=el("a");a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
function setVulnerabilities(items,generatedAt){currentCVEs=Array.isArray(items)?items:[];intelligenceDate=generatedAt||"";if(assets.length)run();}
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
function render(){renderOT();const stats=$("asset-stats"),root=$("asset-findings");stats.replaceChildren();root.replaceChildren();
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

const ot=()=>window.ZeroGuardOT;
function downloadJSON(name,obj){const link=URL.createObjectURL(new Blob([JSON.stringify(obj,null,2)],{type:"application/json"}));const a=el("a");a.href=link;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(link),1000);}
function renderOT(){
 const siteEl=$("ot-site"),priorEl=$("ot-priority"),sum=$("ot-summary"),root=$("ot-investigations");
 if(!root)return;
 const old=siteEl.value,sites=[...new Set(assets.map(a=>a.site).filter(Boolean))].sort();
 siteEl.replaceChildren();for(const site of ["all",...sites]){const opt=el("option",site==="all"?"All substations":site);opt.value=site;siteEl.append(opt);}siteEl.value=sites.includes(old)?old:"all";
 sum.replaceChildren();root.replaceChildren();
 const candidates=result?.findings||[],byId=new Map(assets.map(a=>[a.id,a]));
 const applicable=candidates.map(f=>({f,a:byId.get(f.assetId)||{},triage:ot().priority(f,byId.get(f.assetId)||{})}))
  .filter(x=>(siteEl.value==="all"||x.a.site===siteEl.value)&&(priorEl.value==="all"||x.triage.tier===priorEl.value));
 const missing=assets.filter(a=>ot().inventoryGaps(a).length>0).length;
 for(const [label,n] of [["Assets missing evidence",missing],["Visible research leads",applicable.length],["Reviewed cases",Array.from(reviews.values()).filter(r=>r.status!=="Not assessed").length],["Version-confirmed vulnerabilities",0]]){
  const card=el("div",undefined,"stat");card.append(el("label",label),el("strong",n));sum.append(card);
 }
 if(!assets.length){root.append(el("p","Import assets to build an evidence-gap register. Firmware and exposure remain unknown until verified.","empty"));return;}
 const gapHead=el("h3","Inventory evidence gaps");root.append(gapHead);
 const gapStats=ot().EVIDENCE.map(spec=>[spec.title,assets.filter(a=>ot().inventoryGaps(a).some(g=>g.field===spec.field)).length]);
 const panel=el("div",undefined,"panel spaced");
 for(const [label,n] of gapStats){const row=el("div",undefined,"compact-row");row.append(el("span",label),el("strong",n+" / "+assets.length));panel.append(row);}root.append(panel);
 if(!result){root.append(el("p","Run assessment to create individual investigation cases.","muted"));return;}
 const list=el("div",undefined,"tablebox"),scroll=el("div",undefined,"table-scroll"),table=el("table",undefined,"datatable"),head=el("tr");
 for(const name of ["Substation / equipment","CVE","Applicability","Investigation priority","Workflow","Review"])head.append(el("th",name));
 const thead=el("thead");thead.append(head);table.append(thead);const body=el("tbody");
 for(const {f,a,triage} of applicable.slice(0,150)){
  const row=el("tr"),key=ot().caseKey(f),review=reviews.get(key)||ot().sanitizeReview();
  row.append(el("td",(a.site||"Unassigned")+" · "+f.assetName),el("td",f.cve),el("td",ot().confidence(f)),el("td",triage.tier),el("td",review.status));
  const cell=el("td"),button=el("button","Investigate","textbutton");button.addEventListener("click",()=>showCase(f,a));cell.append(button);row.append(cell);body.append(row);
 }
 table.append(body);scroll.append(table);list.append(scroll);root.append(list);
 if(applicable.length>150)root.append(el("p","Showing the first 150 cases. Filter by site or priority, or export the full register.","muted"));
}
function showCase(f,asset){
 const key=ot().caseKey(f),saved=reviews.get(key)||ot().sanitizeReview();
 const backdrop=document.createElement("dialog");backdrop.className="ot-case-dialog";
 const form=el("form");form.method="dialog";
 const close=el("button","✕ Close","button secondary");close.type="button";close.addEventListener("click",()=>backdrop.close());
 form.append(close,el("h2",f.cve+" · "+f.assetName),el("p",(asset.site||"No site")+" · "+ot().confidence(f),"muted"));
 const pr=ot().priority(f,asset);form.append(el("h3",pr.tier),el("p",pr.rationale,"muted"));
 const rec=ot().recommendations(f,asset);
 form.append(el("h3","Missing evidence"));
 for(const item of rec.gaps)form.append(el("p",item.title+" — "+item.sources,"muted"));
 form.append(el("h3","Nonintrusive investigation"));
 for(const item of rec.steps)form.append(el("p","• "+item,"muted"));
 const fields={};
 function field(label,key,type="text"){const section=el("div",undefined,"ot-form-line");const lab=el("label",label);const input=type==="textarea"?el("textarea"):el("input");if(type!=="textarea")input.type=type;input.value=saved[key]||"";lab.append(input);section.append(lab);form.append(section);fields[key]=input;}
 const state=el("select");for(const option of ot().STATUSES){const node=el("option",option);node.value=option;state.append(node);}state.value=saved.status;const wrapper=el("label","Investigation status");wrapper.append(state);form.append(wrapper);
 field("Assigned OT reviewer","owner");field("Review due date","dueDate","date");field("Evidence references (document IDs, ticket numbers)","evidence","textarea");field("Review notes and decision rationale","notes","textarea");
 form.append(el("h3","Compensating-control evidence"));
 const ctl={};
 for(const control of ot().CONTROL_CATALOG){
  const box=el("div",undefined,"ot-control-row"),title=el("label",control.label),select=el("select");
  for(const option of ot().CONTROL_STATUSES){const item=el("option",option);item.value=option;select.append(item);}
  select.value=saved.controls[control.id].status;
  const proof=el("input");proof.placeholder="Evidence / approved reference";proof.value=saved.controls[control.id].evidence;
  box.append(title,el("p",control.note,"muted"),select,proof);form.append(box);ctl[control.id]={select,proof};
 }
 const save=el("button","Save review locally","button primary");save.type="button";
 save.addEventListener("click",()=>{
  const controls={};for(const [id,v] of Object.entries(ctl))controls[id]={status:v.select.value,evidence:v.proof.value};
  const review=ot().sanitizeReview({status:state.value,owner:fields.owner.value,dueDate:fields.dueDate.value,notes:fields.notes.value,evidence:fields.evidence.value,controls,updatedAt:new Date().toISOString()});
  reviews.set(key,review);backdrop.close();renderOT();feedback("Review saved in browser memory. Export assessment JSON to retain it after closing.");
 });form.append(save);backdrop.append(form);document.body.append(backdrop);backdrop.addEventListener("close",()=>backdrop.remove());backdrop.showModal();
}
$("ot-site").addEventListener("change",renderOT);$("ot-priority").addEventListener("change",renderOT);
$("ot-export-package").addEventListener("click",()=>{if(!assets.length){feedback("Import assets first.");return;}downloadJSON("zeroguard-ot-assessment.json",ot().makePackage(assets,reviews,intelligenceDate));});
$("ot-export-register").addEventListener("click",()=>{
 if(!result){feedback("Run assessment first.");return;}
 const byId=new Map(assets.map(a=>[a.id,a]));
 const keys=["site","room","panel","assetId","assetName","quantity","cve","matchConfidence","triagePriority","investigationStatus","owner","dueDate","missingEvidence","source","action","evidenceReference"];
 const rows=result.findings.map(f=>{const a=byId.get(f.assetId)||{},r=reviews.get(ot().caseKey(f))||ot().sanitizeReview();return [
 a.site||"",a.room||"",a.panel||"",f.assetId,f.assetName,a.quantity||1,f.cve,ot().confidence(f),ot().priority(f,a).tier,r.status,r.owner,r.dueDate,ot().inventoryGaps(a).map(g=>g.title).join("; "),f.evidence.source,r.notes,r.evidence
 ];});
 download("zeroguard-ot-investigation-register.csv",[keys.join(","),...rows.map(r=>r.map(csvCell).join(","))].join("\r\n"));
});
$("ot-import-trigger").addEventListener("click",()=>$("ot-import-file").click());
$("ot-import-file").addEventListener("change",async event=>{
 const file=event.target.files?.[0];if(!file)return;
 try{if(file.size>5*1024*1024)throw Error("Assessment exceeds 5MB.");const obj=ot().loadPackage(JSON.parse(await file.text()));
 assets=obj.assets;reviews=obj.cases;$("asset-mode").value=assets.some(a=>a.site)?"ot-screen":"assessment";result=null;feedback("Restored "+assets.length+" assets and "+reviews.size+" investigation cases. Re-run assessment against current CVEs.");render();
 }catch(e){feedback("Restore failed: "+e.message);}event.target.value="";
});

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
$("asset-clear").addEventListener("click",()=>{assets=[];result=null;reviews.clear();feedback("Inventory cleared from the active browser session.");render();});
$("asset-export").addEventListener("click",exportCSV);
$("asset-template").addEventListener("click",()=>download("zeroguard-asset-template.csv",'id,name,vendor,version,purl,cpe,host,criticality,exposure\r\nexample-01,example-app,example,1.2.3,pkg:npm/example-app@1.2.3,,host-01,high,internal\r\n'));
document.addEventListener("zeroguard:feed",e=>setVulnerabilities(e.detail?.vulnerabilities,e.detail?.generatedAt));
render();
})();