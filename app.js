/* ZeroGuard Pro 6 — static, evidence-aware intelligence client. No CORS proxies. */
(() => {
"use strict";
const DATA_URL = "data/intelligence.json";
const POLL_INTERVAL = 15 * 60 * 1000;
const WATCHLIST_KEY = "zg_watchlist_v6";
const KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog";
const $ = id => document.getElementById(id);
const state = {data:null,view:"overview",filters:{},pages:{},busy:false,selected:null};
let watchlist = new Set();
try { watchlist = new Set(JSON.parse(localStorage.getItem(WATCHLIST_KEY)||"[]")); } catch { watchlist = new Set(); }
const safe = val => String(val ?? "");
const date = val => val ? String(val).slice(0,10) : "—";
const number = val => typeof val === "number" && Number.isFinite(val) ? val : null;
const score = val => number(val) === null ? "N/A" : number(val).toFixed(1);
const probability = val => number(val) === null ? "N/A" : (val*100).toFixed(2)+"%";
const href = value => {try{const u=new URL(value);return u.protocol==="https:" ? u.href : null;}catch{return null;}};
const element = (tag,cls,txt) => {const el=document.createElement(tag);if(cls)el.className=cls;if(txt!==undefined)el.textContent=safe(txt);return el;};
function append(node,...children){for(const c of children)if(c)node.append(c);return node;}
function empty(text){return element("div","empty",text);}
function clear(el){el.replaceChildren();}
function status(fresh,message){
  $("sync-pill").textContent=message;
  $("sync-pill").className="pill "+(fresh?"good":"bad");
  $("status-dot").className="dot "+(fresh?"good":"bad");
  $("status-name").textContent=message;
}
function newestDate(){return state.data?.generatedAt || "";}
function freshness(){
 const t=Date.parse(newestDate());
 return Number.isFinite(t)?Date.now()-t:Infinity;
}
function verify(d){
 if(!d||d.schema!==1||!Array.isArray(d.vulnerabilities)||!Array.isArray(d.articles)||!Array.isArray(d.advisories)||!Array.isArray(d.indicators)||!d.sources)throw Error("Invalid dataset schema");
 if(!Date.parse(d.generatedAt))throw Error("Missing valid snapshot timestamp");
 for(const v of d.vulnerabilities.slice(0,5000)){if(!/^CVE-\d{4}-\d{4,}$/.test(v.id))throw Error("Invalid CVE identity");}
 return d;
}
async function fetchData(manual=false){
 if(state.busy)return;
 state.busy=true;$("refresh-button").disabled=true;
 if(manual)$("notice").textContent="";
 try{
  const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),12000);
  let res;
  try{res=await fetch(DATA_URL+"?v="+Date.now(),{cache:"no-store",signal:controller.signal});}finally{clearTimeout(timer);}
  if(!res.ok)throw Error("HTTP "+res.status);
  const data=verify(await res.json());
  state.data=data;render();
  document.dispatchEvent(new CustomEvent("zeroguard:feed",{detail:{vulnerabilities:data.vulnerabilities}}));
  const hours=freshness()/3600000;
  status(hours<12,"Snapshot "+(hours<12?"current":"outdated"));
  $("last-updated").textContent="Last ingested: "+date(data.generatedAt)+" UTC";
  $("overview-time").textContent=data.generatedAt.replace("T"," ").replace(/:\d{2}Z$/," UTC");
  const unavailable=Object.entries(data.sources).filter(([key,val])=>key!=="rss"&&!val.ok).map(([key])=>key);
  $("notice").textContent=hours>=12?"Warning: snapshot is "+Math.floor(hours)+" hours old. Source health may show why.":unavailable.length?"Partial refresh: unavailable feeds: "+unavailable.join(", ")+". Existing enrichment may be older than the snapshot.":"";
 } catch(e){
  if(state.data){status(false,"Previously loaded · offline");$("notice").textContent="Could not retrieve a new snapshot: "+e.message+". Showing previously loaded data.";}
  else {status(false,"Data unavailable");$("notice").textContent="Intelligence snapshot unavailable. GitHub Actions must complete the first ingestion. Check Source health or repository Actions.";render();}
 } finally{state.busy=false;$("refresh-button").disabled=false;}
}
function priority(v){
 // Sorting convenience only; never an asserted official risk score.
 return (v.inKEV?50:0)+(number(v.epss)||0)*20+(number(v.cvss)||0)*2;
}
function vulnerabilityList(){
 return (state.data?.vulnerabilities||[]).slice().sort((a,b)=>safe(b.published||b.displayDate||b.date).localeCompare(safe(a.published||a.displayDate||a.date))||b.id.localeCompare(a.id));
}
function category(v){return v.category||"it";}
function sourceTag(v){
 return v.inKEV?badge("Confirmed KEV","red"):badge("NVD","orange");
}
function badge(text,cls){return element("span","tag "+(cls||""),text);}
function bookmarkButton(id){
 const b=element("button","textbutton",watchlist.has(id)?"★ Saved":"☆ Save");
 b.type="button";b.setAttribute("aria-label","Toggle bookmark "+id);
 b.addEventListener("click",event=>{event.stopPropagation();if(watchlist.has(id))watchlist.delete(id);else watchlist.add(id);localStorage.setItem(WATCHLIST_KEY,JSON.stringify([...watchlist]));render();});
 return b;
}
function goto(view){
 state.view=view;
 document.querySelectorAll(".page").forEach(el=>el.classList.toggle("active",el.id===view));
 document.querySelectorAll(".nav").forEach(el=>el.classList.toggle("active",el.dataset.view===view));
 const names={overview:"Executive overview",vulnerabilities:"Vulnerability explorer",assets:"Asset exposure assessment",exploited:"Known exploited",ot:"OT / ICS intelligence",advisories:"News & advisories",search:"Research search",emerging:"Emerging reports",iocs:"IOC intelligence",bookmarks:"Your watchlist",health:"Source health",about:"About ZeroGuard"};
 $("view-title").textContent=names[view]||"ZeroGuard";
 $("sidebar").classList.remove("open");
 if(view!=="overview")renderView(view);
}
function stat(label,count,subtitle,color){
 const div=element("div","stat");append(div,element("label","",label),element("strong",color||"",count.toLocaleString("en-US")),element("small","",subtitle));return div;
}
function renderOverview(){
 const d=state.data;
 const records=d?.vulnerabilities||[];
 const exploited=records.filter(v=>v.inKEV);
 const high=records.filter(v=>number(v.cvss)!==null&&v.cvss>=9);
 const trending=records.filter(v=>number(v.epss)!==null&&v.epss>=.5);
 const ot=records.filter(v=>category(v)==="ot");
 const stats=$("stats");clear(stats);
 append(stats,stat("Tracked CVEs",records.length,"NVD + CISA KEV"),stat("Confirmed exploited",exploited.length,"CISA KEV","risk"),stat("Critical CVSS",high.length,"CVSS 9.0–10.0","warning"),stat("High EPSS",trending.length,"≥ 50% model probability","good"));
 const highest=$("priority-list");clear(highest);
 if(!records.length)highest.append(empty("No intelligence snapshot loaded."));
 for(const v of vulnerabilityList().slice(0,7)){
  const row=element("div","compact-row");const a=element("div");const link=element("button","textbutton",v.id);link.addEventListener("click",()=>openDetail(v.id));
  append(a,link,element("small","",safe(v.vendor||"Unspecified")+" · "+safe(v.product||"Product not established")));
  append(row,a,append(element("div"),badge("CVSS "+score(v.cvss),number(v.cvss)>=9?"red":""),element("small","",v.inKEV?"Known exploited":"NVD")));
  highest.append(row);
 }
 const preview=$("source-preview");clear(preview);
 const sources=Object.entries(d?.sources||{}).filter(([k])=>k!=="rss").slice(0,7);
 if(!sources.length)preview.append(empty("No source status yet."));
 for(const [name,val] of sources){const row=element("div","health-row");append(row,element("span","",name.replace("rss_","")),badge(val.ok?"Responded":"Failed",val.ok?"green":"red"));preview.append(row);}
 const news=$("advisory-preview");clear(news);
 const recent=(d?.advisories?.length?d.advisories:d?.articles||[]).slice(0,5);
 if(!recent.length)news.append(empty("No current articles available."));
 for(const a of recent){const row=element("div","compact-row");const link=href(a.url);const title=element(link?"a":"span","",a.title);if(link){title.href=link;title.target="_blank";title.rel="noopener noreferrer";}append(row,append(element("div"),title,element("small","",a.source+" · "+date(a.date))));news.append(row);}
 const counts=[["Critical",records.filter(v=>number(v.cvss)!==null&&v.cvss>=9).length,"critical"],["High",records.filter(v=>number(v.cvss)!==null&&v.cvss>=7&&v.cvss<9).length,"high"],["Medium",records.filter(v=>number(v.cvss)!==null&&v.cvss>=4&&v.cvss<7).length,"medium"],["Low",records.filter(v=>number(v.cvss)!==null&&v.cvss<4).length,"low"],["Unscored",records.filter(v=>number(v.cvss)===null).length,""]];
 const chart=$("severity-chart");clear(chart);
 for(const [name,count,col] of counts){const row=element("div","chartrow");const track=element("div","track");const fill=element("div","fill "+col);fill.style.width=(records.length?Math.max(count/records.length*100,0):0)+"%";append(track,fill);append(row,element("span","",name),track,element("strong","",String(count)));chart.append(row);}
}
function toolbar(scope){
 const bar=element("div","toolbar");
 const search=element("input");search.type="search";search.placeholder="Search CVE, vendor, product, description…";search.setAttribute("aria-label","Search vulnerabilities");search.value=state.filters[scope]?.query||"";
 const select=element("select");select.setAttribute("aria-label","Filter severity");for(const [v,t] of [["all","All severities"],["critical","Critical"],["high","High"],["medium","Medium"],["low","Low"],["unscored","Unscored"]]){const opt=element("option","",t);opt.value=v;select.append(opt);}select.value=state.filters[scope]?.severity||"all";
 const order=element("select");order.setAttribute("aria-label","Sort vulnerabilities");for(const [v,t] of [["date","Newest first"],["priority","Priority"],["cvss","CVSS"],["epss","EPSS"]]){const opt=element("option","",t);opt.value=v;order.append(opt);}order.value=state.filters[scope]?.sort||"priority";
 function change(){state.filters[scope]={query:search.value,severity:select.value,sort:order.value};state.pages[scope]=1;renderView(scope);const fresh=document.querySelector("#"+scope+"-table input");if(fresh){fresh.focus();fresh.setSelectionRange(search.selectionStart||fresh.value.length,search.selectionEnd||fresh.value.length);}}
 // Search is debounced to avoid focus churn and slow re-render on each keystroke.
 let timer;search.addEventListener("input",()=>{clearTimeout(timer);timer=setTimeout(change,180);});
 select.addEventListener("change",change);order.addEventListener("change",change);
 append(bar,search,select,order);return bar;
}
function severity(v){if(number(v.cvss)===null)return "unscored";if(v.cvss>=9)return "critical";if(v.cvss>=7)return "high";if(v.cvss>=4)return "medium";return "low";}
function renderTable(scope,rows,target){
 const el=$(target);clear(el);
 const settings=state.filters[scope]||{};const query=(settings.query||"").trim().toLowerCase();
 let filtered=rows.filter(v=>(!query||[v.id,v.vendor,v.product,v.description,...(v.affectedSystems||[]).flatMap(a=>[a.name,a.version,a.source]),...(v.cwe||[])].some(t=>safe(t).toLowerCase().includes(query)))&&(!settings.severity||settings.severity==="all"||severity(v)===settings.severity));
 const sort=settings.sort||"date";
 filtered.sort((a,b)=>sort==="cvss"?(number(b.cvss)??-1)-(number(a.cvss)??-1):sort==="epss"?(number(b.epss)??-1)-(number(a.epss)??-1):sort==="date"?safe(b.published||b.displayDate||b.date).localeCompare(safe(a.published||a.displayDate||a.date))||b.id.localeCompare(a.id):priority(b)-priority(a));
 el.append(toolbar(scope));
 const wrap=element("div","tablebox");
 const scroll=element("div","table-scroll");const table=element("table","datatable");const thead=element("thead");const tr=element("tr");
 for(const field of ["CVE / actions","Product","Affected systems","CVSS","EPSS 30d","Exploitation","Date","Source"])tr.append(element("th","",field));thead.append(tr);table.append(thead);
 const tbody=element("tbody");const per=25;const page=Math.max(1,Math.min(state.pages[scope]||1,Math.ceil(filtered.length/per)||1));state.pages[scope]=page;
 for(const v of filtered.slice((page-1)*per,page*per)){
 const row=element("tr");
 const first=element("td");const id=element("button","cve-link",v.id);id.addEventListener("click",()=>openDetail(v.id));append(first,id,element("div","",null));first.lastChild.append(bookmarkButton(v.id));
 const vendor=element("td");append(vendor,element("span","vendor",v.vendor||"Unspecified"),element("span","product",v.product||"Not established"));
 const sys=element("td");const systems=v.affectedSystems||[];
 append(sys,element("span","vendor",v.affectedSystemLabel||"Not identified in connected sources"),element("span","product",systems.length?(systems[0].version||"")+" · "+systems[0].source:"Source evidence unavailable"));
 if(systems.length>1)sys.append(element("small","muted","+"+(systems.length-1)+" more; open CVE"));
 append(row,first,vendor,sys,element("td","",score(v.cvss)),element("td","",probability(v.epss)));
 const exploited=element("td");exploited.append(v.inKEV?badge("Confirmed", "red"):badge("Not established", ""));row.append(exploited);
 append(row,element("td","",date(v.published||v.displayDate||v.date)),element("td","",Array.isArray(v.source)?v.source.join(", "):"—"));tbody.append(row);
 }
 if(!filtered.length){const row=element("tr");const cell=element("td","empty","No matching vulnerabilities in the loaded snapshot.");cell.colSpan=8;row.append(cell);tbody.append(row);}
 table.append(tbody);scroll.append(table);wrap.append(scroll);
 const foot=element("div","footbar");const buttons=element("div","pagebuttons");const prev=element("button","", "← Previous"),next=element("button","","Next →");prev.disabled=page===1;next.disabled=page*per>=filtered.length;prev.addEventListener("click",()=>{state.pages[scope]=page-1;renderView(scope);});next.addEventListener("click",()=>{state.pages[scope]=page+1;renderView(scope);});append(buttons,prev,next);append(foot,element("span","",filtered.length+" results · Page "+page+" of "+(Math.ceil(filtered.length/per)||1)),buttons);wrap.append(foot);el.append(wrap);
}
function openDetail(id){
 const v=state.data?.vulnerabilities.find(row=>row.id===id);if(!v)return;
 const dialog=$("detail"),body=$("detail-body");clear(body);
 body.append(element("div","eyebrow","VULNERABILITY INTELLIGENCE"),element("h2","",v.id),element("p","muted",(v.vendor||"Unspecified vendor")+" · "+(v.product||"Product not established")));
 const grid=element("div","detail-grid");
 for(const [name,value] of [["CVSS",score(v.cvss)],["EPSS 30-day",probability(v.epss)],["Known exploitation",v.inKEV?"CISA KEV confirmed":"Not confirmed by connected KEV"],["Category",v.category||"Unknown"],["Published",date(v.published||v.displayDate||v.date)],["Agency due date",date(v.dueDate)],["Ransomware use",v.ransomwareUse||"Not assessed"],["Patch deployed?","Not assessed — requires asset evidence"]]){
 const cell=element("div");append(cell,element("small","",name),element("strong","",value));grid.append(cell);
 }body.append(grid);
 for(const [title,content] of [["Description",v.description],["Verified vendor remediation",v.remediation?.details||"No vendor-specific remediation verified from connected advisories. Consult the vendor bulletin and CISA recommendations."],["CWE",Array.isArray(v.cwe)?v.cwe.join(", "):""]]){
 if(content){body.append(element("h3","spaced",title),element("p","wrap",content));}}
 if(v.remediation?.details){
  body.append(element("p","muted","Source: "+(v.remediation.source||"CISA CSAF")+" · "+(v.remediation.category||"not classified")+" · Published/updated: "+date(v.remediation.updated)));
  for(const [label,url] of [["Vendor advisory / patch instructions",v.remediation.vendorUrl],["Official CISA CSAF evidence",v.remediation.advisoryUrl]]){
   if(href(url)){const link=element("a","button secondary",label+" ↗");link.href=href(url);link.target="_blank";link.rel="noopener noreferrer";link.style.marginRight="8px";body.append(link);}
  }
 }
 body.append(element("h3","spaced","Affected systems and versions"));
 const affected=v.affectedSystems||[];
 if(!affected.length)body.append(element("p","muted","Not identified in connected sources. Check the primary vendor advisory; this does not indicate safety."));
 for(const system of affected){const block=element("div","compact-row");const info=element("div");append(info,element("strong","",system.name),element("small","",(system.version||"Version unknown")+" · "+system.source));block.append(info);if(href(system.url)){const a=element("a","textbutton","Evidence ↗");a.href=href(system.url);a.target="_blank";a.rel="noopener noreferrer";block.append(a);}body.append(block);}
 if(v.kevAction){body.append(element("h3","spaced","CISA KEV required action (agency guidance)"),element("p","wrap",v.kevAction),element("p","muted","CISA catalog guidance may be generic and does not establish an applicable vendor patch."));}
 const links=element("div","spaced");for(const [title,url] of [["Official NVD record","https://nvd.nist.gov/vuln/detail/"+id],["CISA KEV catalog",KEV_URL],["FIRST EPSS","https://www.first.org/epss/"]]){
 const link=element("a","button secondary",title+" ↗");link.href=url;link.target="_blank";link.rel="noopener noreferrer";link.style.marginRight="8px";links.append(link);
 }body.append(links);dialog.showModal();
}
function renderArticles(target,articles){
 const root=$(target);clear(root);if(!articles.length){root.append(empty("No articles available from the latest successful collector run."));return;}
 for(const item of articles){const card=element("article","article");append(card,element("span","",item.source||"Publisher"),element("h3","",item.title),element("small","",date(item.date)));
 if(item.status)card.append(element("p","muted",item.status));
 if(item.reportedZeroDay)card.append(element("p","muted","Reported zero-day mention · not independently verified."));
 const url=href(item.url);if(url){const a=element("a","", "Read original source ↗");a.href=url;a.target="_blank";a.rel="noopener noreferrer";card.append(element("div"),a);}root.append(card);}
}
function renderReports(){
 renderArticles("emerging-list",state.data?.reports||[]);
}
function renderIOCs(){
 const root=$("ioc-list");clear(root);const data=state.data?.indicators||[];
 root.append(element("p","muted",data.length+" source-attributed reported indicators. Reputation feeds are not proof of compromise; verify locally before taking action. Indicators are intentionally not clickable."));
 const items=element("div","panel");if(!data.length)items.append(empty("No published IOC reputation indicators in this snapshot. Check Source health for retrieval errors."));
 for(const ioc of data.slice(0,100)){const row=element("div","compact-row");const left=element("div","wrap");append(left,element("strong","",ioc.value),element("small","",ioc.threat+" · "+date(ioc.date)+" · "+ioc.source));const controls=element("div");const copy=element("button","textbutton","Copy");copy.addEventListener("click",()=>navigator.clipboard?.writeText(ioc.value));const link=href(ioc.evidence);append(controls,copy);if(link){const a=element("a","textbutton"," Evidence ↗");a.href=link;a.target="_blank";a.rel="noopener noreferrer";controls.append(a);}append(row,left,controls);items.append(row);}root.append(items);
}
function renderHealth(){
 const root=$("health-list");clear(root);const d=state.data;if(!d){root.append(empty("No snapshot loaded. Check the GitHub Actions workflow and publish a validated snapshot."));return;}
 const header=element("div","panel");append(header,element("h3","","Dataset freshness"),element("p","muted","Ingested at "+d.generatedAt+" · "+(freshness()/3600000).toFixed(1)+" hours ago"),element("p","muted","A source failure doesn't erase past enrichment; check individual source outcomes and timestamps before taking decisions."));root.append(header);
 for(const [name,details] of Object.entries(d.sources)){const panel=element("div","panel spaced");append(panel,element("h3","",name),element("p",details.ok?"good":"risk",details.ok?"Collection successful":"Collection failed"),element("p","muted",details.error||""));if(details.count!==undefined)panel.append(element("p","muted","Items: "+details.count));if(details.url&&href(details.url)){const a=element("a","", "Official source ↗");a.href=href(details.url);a.target="_blank";a.rel="noopener noreferrer";panel.append(a);}root.append(panel);}
}
function renderView(view){
 const all=state.data?.vulnerabilities||[];
 if(view==="vulnerabilities")renderTable(view,all,"vulnerability-table");
 else if(view==="exploited")renderTable(view,all.filter(v=>v.inKEV),"exploited-table");
 else if(view==="ot"){renderTable(view,all.filter(v=>category(v)==="ot"),"ot-table");const root=$("ics-list");clear(root);for(const a of (state.data?.advisories||[]).slice(0,15)){const row=element("div","compact-row");const link=element("a","",a.title);link.href=href(a.url)||"#";link.target="_blank";link.rel="noopener noreferrer";append(row,append(element("div"),link,element("small","",date(a.date))));root.append(row);}if(!root.childNodes.length)root.append(empty("CISA ICS RSS feed not available."));}
 else if(view==="advisories")renderArticles("article-list",state.data?.articles||[]);
 else if(view==="iocs")renderIOCs();
 else if(view==="emerging")renderReports();
 else if(view==="bookmarks")renderTable(view,all.filter(v=>watchlist.has(v.id)),"watchlist-table");
 else if(view==="health")renderHealth();
 else if(view==="search")renderGlobalSearch();
}
function render(){renderOverview();renderView(state.view);}
function exportCSV(){
 const records=state.data?.vulnerabilities||[];if(!records.length)return;
 const columns=["id","vendor","product","affectedSystemLabel","affectedSystemCount","category","cvss","epss","inKEV","published","date","dueDate","actionStatus","action","kevAction","description"];
 function quoted(val){let s=String(val??"");if(/^[=+\-@\t\r]/.test(s))s="'"+s;return '"'+s.replaceAll('"','""')+'"';}
 const csv=[columns.join(","),...records.map(v=>columns.map(k=>quoted(v[k])).join(","))].join("\r\n");
 const blob=new Blob([csv],{type:"text/csv;charset=utf-8"}),url=URL.createObjectURL(blob);
 const a=document.createElement("a");a.href=url;a.download="zeroguard-intelligence-"+date(new Date().toISOString())+".csv";document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}

function globalMatches(term,limit=100){
 const tokens=term.toLowerCase().trim().split(/\s+/).filter(Boolean);
 if(!tokens.length)return [];
 const items=[];
 function push(kind,label,subtitle,url,view,ref,fields){
  const str=fields.map(s=>safe(s)).join(" ").toLowerCase();
  if(!tokens.every(t=>str.includes(t)))return;
  let weight=0;for(const t of tokens){if(label.toLowerCase().includes(t))weight+=15;else if(fields.slice(0,4).join(" ").toLowerCase().includes(t))weight+=8;else weight+=2;}
  items.push({kind,label,subtitle,url,view,ref,weight});
 }
 const d=state.data||{};
 for(const v of d.vulnerabilities||[]){
  const systems=v.affectedSystems||[];
  push("CVE",v.id,(v.affectedSystemLabel||"Affected system unknown")+" · CVSS "+score(v.cvss),null,"vulnerabilities",v.id,
   [v.id,v.vendor,v.product,v.affectedSystemLabel,v.description,v.action,v.kevAction,
    ...systems.flatMap(a=>[a.name,a.version,a.source]),...(v.cwe||[])]);
 }
 for(const [kind,entries,view] of [["Advisory",d.advisories,"ot"],["News",d.articles,"advisories"],["Emerging",d.reports,"emerging"]]){
  for(const item of entries||[])push(kind,item.title,item.source+" · "+date(item.date),item.url,view,null,
   [item.title,item.source,item.advisoryId,item.ecosystem,item.status,...(item.cves||[])]);
 }
 for(const ioc of d.indicators||[])push("IOC",ioc.value,ioc.source+" · "+ioc.threat,ioc.evidence,"iocs",ioc.value,[ioc.value,ioc.type,ioc.threat,ioc.source,ioc.tags]);
 const rank={CVE:5,Advisory:4,Emerging:3,News:2,IOC:1};
 return items.sort((a,b)=>b.weight-a.weight||(rank[b.kind]||0)-(rank[a.kind]||0)).slice(0,limit);
}
function renderGlobalSearch(){
 const root=$("global-results");clear(root);
 const input=$("global-query");const term=input.value.trim();
 if(!term){root.append(empty("Enter a keyword or product name to search all dashboard intelligence."));return;}
 const results=globalMatches(term);
 const counts={};for(const r of results)counts[r.kind]=(counts[r.kind]||0)+1;
 root.append(element("p","muted",results.length+" matching entries (top 100) · "+Object.entries(counts).map(([k,v])=>k+": "+v).join(" · ")));
 if(!results.length){root.append(empty("No indexed matches. A missing match does not prove a system is secure."));return;}
 for(const result of results){
  const row=element("div","compact-row"),left=element("div","wrap");
  append(left,badge(result.kind,result.kind==="CVE"?"orange":""),element("strong","", " "+result.label),element("small","",result.subtitle));
  const btn=element("button","textbutton",result.kind==="CVE"?"Open CVE →":"Open entry →");
  btn.addEventListener("click",()=>{
   if(result.kind==="CVE"){goto("vulnerabilities");openDetail(result.ref);return;}
   goto(result.view);
   if(result.kind==="IOC"){const q=$("ioc-list");q.querySelectorAll(".compact-row").forEach(el=>{if(el.textContent.includes(result.ref)){el.scrollIntoView?.({block:"center"});el.style.outline="1px solid var(--blue)";}});}
   else if(href(result.url)){window.open(href(result.url),"_blank","noopener,noreferrer");}
  });
  append(row,left,btn);root.append(row);
 }
}
function doGlobalSearch(){goto("search");renderGlobalSearch();}
$("global-search-open").addEventListener("click",()=>{goto("search");$("global-query").focus();});
$("global-search-button").addEventListener("click",doGlobalSearch);
$("global-query").addEventListener("keydown",event=>{if(event.key==="Enter")doGlobalSearch();});
document.addEventListener("keydown",event=>{if((event.ctrlKey||event.metaKey)&&event.key.toLowerCase()==="k"){event.preventDefault();goto("search");$("global-query").focus();}});

document.addEventListener("zeroguard:open-cve",e=>{goto("vulnerabilities");openDetail(e.detail.id);});
document.querySelectorAll(".nav").forEach(b=>b.addEventListener("click",()=>goto(b.dataset.view)));
document.querySelectorAll("[data-go]").forEach(b=>b.addEventListener("click",()=>goto(b.dataset.go)));
$("mobile-menu").addEventListener("click",()=>$("sidebar").classList.toggle("open"));
$("refresh-button").addEventListener("click",()=>fetchData(true));
$("export-button").addEventListener("click",exportCSV);
fetchData();
setInterval(fetchData,POLL_INTERVAL);
})();
