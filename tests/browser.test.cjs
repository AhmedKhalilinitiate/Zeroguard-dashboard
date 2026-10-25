const assert=require('node:assert/strict');
const fs=require('node:fs');
const {JSDOM}=require('jsdom');
const html=fs.readFileSync('index.html','utf8');
const app=fs.readFileSync('app.js','utf8');
const fixture={
 schema:1,generatedAt:new Date().toISOString(),
 vulnerabilities:[
  {id:"CVE-2026-99999",published:"2026-10-22",date:"2026-10-22",vendor:"Node.js",product:"runtime",description:"Example recent",source:["NVD"],inKEV:false,category:"it",cvss:8.2,epss:.2},
  {id:"CVE-2025-12345",published:"2025-02-05",date:"2025-02-05",vendor:"Siemens",product:"PLC",description:"Older",source:["CISA KEV"],inKEV:true,category:"ot",cvss:9.3,epss:.82,action:"Install vendor update"}
 ],
 sources:{kev:{ok:true,count:1},nvd:{ok:true,count:2},ioc_ipsum:{ok:true,count:1}},
 articles:[{title:"PHP security patch",url:"https://example.org/php",date:"2026-10-22",source:"Test source"}],
 advisories:[{title:"OT advisory",url:"https://example.org/ot",date:"2026-10-22",source:"CISA CSAF OT"}],
 indicators:[{type:"ip",value:"8.8.8.8",date:"2026-10-22",source:"IPsum",threat:"Reputation signal",evidence:"https://github.com/stamparm/ipsum"}],
 reports:[{title:"Node.js update under investigation",url:"https://github.com/advisories/GHSA-aaaa-bbbb-cccc",date:"2026-10-22",source:"GHSA",status:"GHSA; CVE not assigned"}]
};
(async()=>{
 const dom=new JSDOM(html,{url:"https://example.test/",runScripts:"outside-only",pretendToBeVisual:true});
 const {window:w}=dom;
 w.fetch=async()=>({ok:true,json:async()=>fixture});
 w.document.getElementById("detail").showModal=function(){this.open=true;};
 w.localStorage.clear();
 w.eval(app);
 await new Promise(resolve=>setTimeout(resolve,100));
 assert.match(w.document.getElementById("stats").textContent,/2/,"Overview should load");
 const expected={
  overview:"stats",search:"global-results", vulnerabilities:"vulnerability-table",exploited:"exploited-table",
  ot:"ot-table",advisories:"article-list",emerging:"emerging-list",iocs:"ioc-list",
  bookmarks:"watchlist-table",health:"health-list",about:"about"
 };
 for(const [view,container] of Object.entries(expected)){
  const nav=w.document.querySelector('[data-view="'+view+'"]');
  assert.ok(nav,"Missing sidebar navigation: "+view);
  nav.click();
  assert.equal(w.document.getElementById(view).classList.contains("active"),true,"Inactive tab "+view);
  const content=w.document.getElementById(container);
  assert.ok(content,"Missing tab container "+view);
  assert.ok(content.textContent.trim().length>0,"Empty render for "+view);
 }
 w.document.querySelector('[data-view="vulnerabilities"]').click();
 const rows=w.document.querySelectorAll("#vulnerability-table tbody tr");
 assert.equal(rows[0].textContent.includes("CVE-2026-99999"),true,"Newest CVE must display first despite lower priority");
 w.document.getElementById("global-search-open").click();
 const q=w.document.getElementById("global-query");q.value="Node.js";
 w.document.getElementById("global-search-button").click();
 assert.match(w.document.getElementById("global-results").textContent,/CVE-2026-99999/);
 w.document.querySelector('[data-view="iocs"]').click();
 assert.match(w.document.getElementById("ioc-list").textContent,/8.8.8.8/,"IOC source must render");
 w.document.querySelector('[data-view="emerging"]').click();
 assert.match(w.document.getElementById("emerging-list").textContent,/Node.js/,"Emerging reports must render");
 console.log("All tabs, global search, sorting, IOC rendering and emerging advisories: PASS");
 w.close();
})().catch(e=>{console.error(e);process.exitCode=1;});
