/* ZeroGuard asset matcher — local-only, dependency-free, conservative. */
(function(root,factory){const api=factory();if(typeof module!=="undefined"&&module.exports)module.exports=api;if(root)root.ZeroGuardMatcher=api;})(typeof window!=="undefined"?window:null,function(){
"use strict";
const MAX_ASSETS=5000,MAX_BYTES=5*1024*1024;
const str=x=>String(x??"").trim();
function norm(x){return str(x).toLowerCase().replace(/[_\s-]+/g," ").replace(/[^a-z0-9.+@/ ]/g,"").replace(/\s+/g," ").trim();}
function purl(value){const s=str(value);const m=/^pkg:([a-z0-9.+-]+)\/([^?#]+?)(?:@([^?#]+))?(?:\?[^#]*)?(?:#.*)?$/i.exec(s);if(!m)return null;try{return{type:m[1].toLowerCase(),name:decodeURIComponent(m[2]).toLowerCase(),version:decodeURIComponent(m[3]||"")};}catch{return null;}}
function cpe(value){const x=str(value).split(":");return x.length>=6&&x[0]==="cpe"&&x[1]==="2.3"?{part:x[2],vendor:x[3].toLowerCase(),product:x[4].toLowerCase(),version:x[5]}:null;}
function comparable(version){const v=str(version).replace(/^v/i,"").split("+")[0].split("-")[0];return /^\d+(?:\.\d+){0,3}$/.test(v)?v.split(".").map(Number):null;}
function compare(a,b){const x=comparable(a),y=comparable(b);if(!x||!y)return null;for(let i=0;i<Math.max(x.length,y.length);i++){const d=(x[i]||0)-(y[i]||0);if(d)return d<0?-1:1;}return 0;}
function versionRange(version,rule){
 const v=str(version),r=str(rule);
 if(!v||!r||/not specified|see advisory|unknown/i.test(r))return "unknown";
 if(/^Version /i.test(r))return compare(v,r.slice(8))===0?"match":compare(v,r.slice(8))===null?"unknown":"exclude";
 const sets=r.split(/\s*\|\|\s*/);
 let uncertain=false;
 for(const clause of sets){
  const constraints=clause.split(/\s*,\s*|\s+(?=[<>]=?|=)/).filter(Boolean);
  if(!constraints.length)continue;
  let all=true,bad=false;
  for(const raw of constraints){
   const m=/^(>=|<=|>|<|=|==|\^|~)?\s*v?(\d+(?:\.\d+){0,3})(?:\.x|\.\*)?$/.exec(raw.trim());
   if(!m){uncertain=true;all=false;break;}
   const op=m[1]||"=";const cmp=compare(v,m[2]);
   if(cmp===null){uncertain=true;all=false;break;}
   if(op==="^"||op==="~"){uncertain=true;all=false;break;}
   const ok=op===">="?cmp>=0:op==="<="?cmp<=0:op===">"?cmp>0:op==="<"?cmp<0:cmp===0;
   if(!ok){all=false;bad=true;break;}
  }
  if(all)return "match";
  if(!bad)uncertain=true;
 }
 return uncertain?"unknown":"exclude";
}
function csv(text){
 const rows=[],line=[];let cell="",quote=false;
 for(let i=0;i<text.length;i++){const ch=text[i];if(ch==='"'){if(quote&&text[i+1]==='"'){cell+='"';i++;}else quote=!quote;}else if(ch===","&&!quote){line.push(cell);cell="";}else if((ch==="\n"||ch==="\r")&&!quote){if(ch==="\r"&&text[i+1]==="\n")i++;line.push(cell);if(line.some(v=>v.trim()))rows.push(line.slice());line.length=0;cell="";}else cell+=ch;}
 if(quote)throw Error("CSV contains an unclosed quoted field.");
 line.push(cell);if(line.some(v=>v.trim()))rows.push(line);
 if(rows.length<2)throw Error("CSV requires a header and at least one asset.");
 const headers=rows.shift().map(x=>norm(x).replace(/\s/g,""));
 return rows.map(c=>Object.fromEntries(headers.map((h,i)=>[h,c[i]||""])));
}
function asAsset(raw,i){
 const read=(...keys)=>{for(const k of keys){if(raw[k]!==undefined&&raw[k]!==null&&str(raw[k]))return str(raw[k]);}return"";};
 const obj={id:read("id","assetid","asset_id","bom-ref")||"asset-"+(i+1),name:read("name","product","software","component","package"),vendor:read("vendor","publisher","manufacturer","supplier"),version:read("version","installedversion","installed_version"),purl:read("purl","packageurl"),cpe:read("cpe","cpe23"),host:read("host","hostname","device","asset","system"),criticality:read("criticality","businesscriticality")||"medium",exposure:read("exposure","internetfacing")||"unknown",site:read("site","substation"),room:read("room"),panel:read("panel"),assetType:read("assettype","asset_type"),quantity:Number(read("quantity","assetqty","qty"))||1};
 if(!obj.name&&obj.purl){const p=purl(obj.purl);if(p)obj.name=p.name;}
 if(!obj.name&&obj.cpe){const c=cpe(obj.cpe);if(c)obj.name=c.product;}
 if(!obj.name)throw Error("Asset row "+(i+1)+" has no product, name, PURL or CPE.");
 return obj;
}
function parseInventory(text,filename){
 if(text.length>MAX_BYTES)throw Error("Inventory exceeds 5 MB.");
 let raw;
 if(/\.csv$/i.test(filename))raw=csv(text);
 else{const o=JSON.parse(text);if(Array.isArray(o))raw=o;else if(Array.isArray(o.components))raw=o.components.map(x=>({...x,vendor:x.publisher||x.supplier?.name||x.vendor,cpe:x.cpe||x.cpes?.[0]}));else if(Array.isArray(o.packages))raw=o.packages.map(x=>({name:x.name||x.PackageName,version:x.versionInfo||x.VersionInfo,purl:(x.externalRefs||[]).find(e=>/purl/i.test(e.referenceType||""))?.referenceLocator, cpe:(x.externalRefs||[]).find(e=>/cpe/i.test(e.referenceType||""))?.referenceLocator}));else if(Array.isArray(o.assets))raw=o.assets;else throw Error("Expected an asset array, CycloneDX components, or SPDX packages.");}
 if(raw.length>MAX_ASSETS)throw Error("Maximum 5,000 assets per scan.");
 return raw.map(asAsset);
}
function vendorDiscovery(asset,vuln){
 const q=norm(asset.name),vendor=norm(asset.vendor);
 const family=q||vendor;
 if(!family||family.length<4)return null;
 const words=[vuln.vendor,vuln.product,...(vuln.affectedSystems||[]).map(x=>x.name)].map(norm);
 const aliases=family==="fortinet"?["fortinet","fortios","fortigate","fortimail","fortiweb","forticlient","fortimanager","fortianalyzer","fortiproxy","fortiswitch","fortiauthenticator"]:null;
 const found=words.some(w=>w===family||w.startsWith(family+" ")||(aliases&&aliases.some(a=>w===a||w.startsWith(a+" ")||w.includes(" "+a+" "))));
 if(!found)return null;
 return {assetId:asset.id,assetName:asset.name,host:asset.host,cve:vuln.id,status:"discovery",evidence:{system:vuln.affectedSystemLabel||vuln.product||vuln.vendor||"Vendor advisory",range:"Check affected product and version",source:(vuln.source||[]).join(", "),url:(vuln.references||[])[0]||"",identity:"vendor discovery",versionResult:"unknown"},kev:!!vuln.inKEV,cvss:vuln.cvss,epss:vuln.epss,priority:(vuln.inKEV?50:0)+(Number(vuln.cvss)||0)*3+(Number(vuln.epss)||0)*10};
}
function identity(asset,system){
 const aP=purl(asset.purl),sName=str(system.name);
 const sP=purl(sName.startsWith("pkg:")?sName:"");
 if(aP&&sP&&aP.type===sP.type&&aP.name===sP.name)return{kind:"package",strength:3};
 const pkg=/^(npm|composer):\s*(.+)$/i.exec(sName);
 if(aP&&pkg&&aP.type===pkg[1].toLowerCase()&&norm(aP.name)===norm(pkg[2]))return{kind:"package",strength:3};
 const aC=cpe(asset.cpe);const sC=cpe(system.cpe||"");
 if(aC&&sC&&aC.vendor===sC.vendor&&aC.product===sC.product)return{kind:"cpe",strength:3};
 const n=norm(asset.name),sn=norm(sName),vendor=norm(asset.vendor);
 if(!n||!sn||n.length<3)return null;
 if(n===sn||(vendor&&sn===(vendor+" "+n)))return{kind:"name",strength:1};
 if(vendor&&norm(sName)===(vendor+" "+n))return{kind:"name",strength:1};
 return null;
}
function assess(asset,vuln){
 let best=null;
 for(const system of vuln.affectedSystems||[]){
  const id=identity(asset,system);if(!id)continue;
  const v=versionRange(asset.version||purl(asset.purl)?.version,system.version);
  if(v==="exclude")continue;
  // A product-name-only match is never confirmed; CPE and PURL still need careful applicability.
  const status=id.strength===3&&v==="match"?"version-match":"review";
  const evidence={system:system.name,range:system.version,source:system.source,url:system.url||"",identity:id.kind,versionResult:v};
  const candidate={assetId:asset.id,assetName:asset.name,host:asset.host,cve:vuln.id,status,evidence,kev:!!vuln.inKEV,cvss:vuln.cvss,epss:vuln.epss,
   priority:(vuln.inKEV?50:0)+(Number(vuln.cvss)||0)*3+(Number(vuln.epss)||0)*10+(asset.criticality==="critical"?15:asset.criticality==="high"?8:0)+(asset.exposure==="internet"?12:0)};
  if(!best||candidate.status==="version-match"&&best.status!=="version-match"||candidate.priority>best.priority&&candidate.status===best.status)best=candidate;
 }
 return best;
}

function squish(value){return norm(value).replace(/[^a-z0-9]/g,"");}
function manufacturerName(name){
 const key=squish(name);
 const aliases={sel:"schweitzerengineeringlaboratories",generalelectric:"ge",gevernova:"ge",hirshman:"hirschmann",hirschman:"hirschmann",alcatel:"alcatellucent",juniper:"junipernetworks"};
 return aliases[key]||key;
}
function otScreen(assets,vulns){
 const findings=[],covered=new Set(),modelCounts={};
 for(const asset of assets){
  const manufacturer=manufacturerName(asset.vendor);
  const model=squish(asset.name);
  if(!manufacturer||manufacturer.length<2)continue;
  let added=0;
  for(const v of vulns||[]){
   const vend=[v.vendor,...(v.affectedSystems||[]).map(x=>x.name)].map(manufacturerName);
   const vendMatched=vend.some(x=>x===manufacturer||(manufacturer.length>=4&&(x.startsWith(manufacturer)||x.includes(manufacturer))));
   if(!vendMatched)continue;
   const strings=[v.product,v.description,...(v.affectedSystems||[]).map(x=>x.name)].map(squish);
   const modelMatch=model.length>=5&&/\d/.test(model)&&strings.some(x=>x.includes(model));
   const source=(v.affectedSystems||[]).find(x=>modelMatch&&squish(x.name).includes(model))||(v.affectedSystems||[])[0];
   const evidence={system:source?.name||v.product||asset.vendor,range:source?.version||"Firmware version not recorded",source:source?.source||(v.source||[]).join(", "),url:source?.url||(v.references||[])[0]||"",identity:modelMatch?"OT model reference":"manufacturer only",versionResult:"unknown"};
   const status=modelMatch?"model-lead":"vendor-lead";
   findings.push({assetId:asset.id,assetName:asset.name,host:asset.host,site:asset.site||"",room:asset.room||"",panel:asset.panel||"",assetType:asset.assetType||"",quantity:asset.quantity||1,cve:v.id,status,evidence,kev:!!v.inKEV,cvss:v.cvss,epss:v.epss,priority:(v.inKEV?50:0)+(Number(v.cvss)||0)*3+(Number(v.epss)||0)*10+(modelMatch?25:0)});
   covered.add(asset.id);added++;
  }
  modelCounts[asset.id]=added;
 }
 findings.sort((a,b)=>(a.status==="model-lead"?0:1)-(b.status==="model-lead"?0:1)||b.priority-a.priority||a.cve.localeCompare(b.cve));
 return{assets:assets.length,matchedAssets:covered.size,findings,confirmed:0,review:0,discovery:0,modelLeads:findings.filter(x=>x.status==="model-lead").length,vendorLeads:findings.filter(x=>x.status==="vendor-lead").length};
}

function scan(assets,vulns,options={}){
 if(options.otScreen)return otScreen(assets,vulns);
 const findings=[],covered=new Set();const index=new Map();
 for(const v of vulns||[])for(const s of v.affectedSystems||[]){
  const keys=[norm(s.name)];const pkg=/^(npm|composer):\s*(.+)$/i.exec(s.name);if(pkg)keys.push(norm(pkg[2]));
  for(const key of keys){if(!key)continue;if(!index.has(key))index.set(key,new Set());index.get(key).add(v);}
 }
 for(const asset of assets){const candidates=new Set();for(const key of [norm(asset.name),norm(asset.vendor+" "+asset.name),norm(purl(asset.purl)?.name)]){
  for(const v of index.get(key)||[])candidates.add(v);}
  if(asset.cpe){const c=cpe(asset.cpe);if(c)for(const v of index.get(norm(c.vendor+" "+c.product))||[])candidates.add(v);}
  if(options.discovery){for(const v of vulns||[]){const f=vendorDiscovery(asset,v);if(f){findings.push(f);covered.add(asset.id);}}}
  else for(const v of candidates){const f=assess(asset,v);if(f){findings.push(f);covered.add(asset.id);}}
 }
 findings.sort((a,b)=>b.priority-a.priority||a.cve.localeCompare(b.cve));
 return{assets:assets.length,matchedAssets:covered.size,findings,confirmed:findings.filter(x=>x.status==="version-match").length,review:findings.filter(x=>x.status==="review").length,discovery:findings.filter(x=>x.status==="discovery").length};
}
return{parseInventory,scan,assess,versionRange,compare,purl,cpe,identity,vendorDiscovery,otScreen,MAX_ASSETS};
});
