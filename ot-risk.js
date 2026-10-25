/* ZeroGuard: evidence-first, non-intrusive OT risk triage.
 * No network traffic, firmware inference, confirmed-exposure assertions,
 * or automatic claims about implementation of controls. */
(function(root,factory){
 const api=factory();
 if(root)root.ZeroGuardOT=api;
 if(typeof module!=="undefined"&&module.exports)module.exports=api;
})(typeof window!=="undefined"?window:null,function(){
"use strict";
const EVIDENCE=[
 {field:"vendor",title:"Manufacturer",sources:"Approved equipment BOM, asset registers, nameplate photographs already on file"},
 {field:"name",title:"Equipment model/family",sources:"FAT/SAT package, commissioning records, engineering drawings, purchase documentation"},
 {field:"version",title:"Firmware/software version",sources:"Configuration backups, existing NMS/export, vendor service documentation; otherwise scheduled authorized maintenance"},
 {field:"criticality",title:"Operational impact",sources:"OT owner classification, protection function, dependency drawings, impact assessment"},
 {field:"exposure",title:"Network reachability",sources:"Approved network topology, existing firewall rules/logs, passive telemetry and change records"},
 {field:"owner",title:"Responsible OT owner",sources:"Operations ownership records, maintenance contract, RACI matrix"}
];
const CONTROL_CATALOG=[
 {id:"segmentation",label:"Review segmentation and allowed conduits",note:"Use existing drawings, switch configurations, and firewall policy evidence; do not change traffic paths without change approval."},
 {id:"monitoring",label:"Review existing passive monitoring and alerts",note:"Use already-authorized monitoring/log records; do not introduce active discovery on live control networks."},
 {id:"access",label:"Review remote/vendor access restrictions",note:"Validate jump-host, MFA and access approvals using available records; do not disconnect active engineering sessions."},
 {id:"backup",label:"Confirm offline/verified configuration backup availability",note:"Use existing commissioning/backup records; avoid live controller exports outside approved maintenance."},
 {id:"vendor",label:"Obtain vendor advisory and mitigation applicability",note:"Verify device family, vulnerable features, end-of-support, available patch and vendor-supported workaround."},
 {id:"change",label:"Plan approved maintenance, testing and rollback",note:"Any firmware update requires engineering sign-off, test evidence, outage coordination and a rollback strategy."}
];
const txt=x=>String(x??"").trim();
function known(v){const s=txt(v).toLowerCase();return !!s&&!["unknown","n/a","na","not available","not specified","to be confirmed","tbc","none","-"].includes(s);}
function assetKey(asset){return txt(asset.id);}
function caseKey(f){return txt(f.assetId)+"::"+txt(f.cve);}
function inventoryGaps(asset){
 return EVIDENCE.filter(p=>{
  if(p.field==="criticality")return !known(asset.criticality)||txt(asset.criticality).toLowerCase()==="medium"&&asset.impactVerified!==true;
  if(p.field==="owner")return !known(asset.owner);
  return !known(asset[p.field]);
 });
}
function priority(f,asset={}){
 const rank=txt(f.status);
 const impact=txt(asset.criticality).toLowerCase();
 const exposure=txt(asset.exposure).toLowerCase();
 const highImpact=["critical","high"].includes(impact);
 const external=["internet","internet-facing","public"].includes(exposure);
 const matched=rank==="model-lead"||rank==="version-match";
 // This is a queue priority, NOT a vulnerability probability / severity rating.
 let tier="Routine research";
 let rationale="Manufacturer or product-family research lead; validate device applicability.";
 if(rank==="version-match"){
  tier="Focused validation";
  rationale="Comparable affected-version rule matched; confirm exact configuration and CPE/CSAF applicability.";
 }
 if(rank==="model-lead"){
  tier="Focused validation";
  rationale="Manufacturer and recognizable model reference coincide; installed firmware and affected features remain unverified.";
 }
 if(!!f.kev&&matched){
  tier="Expedited review";
  rationale="CISA KEV reports known exploitation and model/version evidence warrants OT owner review; this is not confirmed asset impact.";
 }
 if((highImpact||external)&&matched&&!!f.kev){
  tier="Priority investigation";
  rationale="Source-reported exploitation plus a model/version lead and user-declared high impact or exposure merit prompt investigation.";
 }
 return{tier,rationale,impactEvidence:highImpact?"Owner-provided impact level":"Impact unverified or not rated",
       networkEvidence:external?"Owner-provided external exposure":"External exposure not established"};
}
function confidence(f){
 const types={"version-match":"Version-rule candidate (not confirmed)","model-lead":"Model referenced; firmware unknown",
              "vendor-lead":"Manufacturer-only lead","discovery":"Manufacturer research lead","review":"Product candidate; applicability unknown"};
 return types[f.status]||"Unclassified research lead";
}
function recommendations(f,asset){
 const gaps=inventoryGaps(asset),steps=[];
 steps.push("Confirm vendor advisory, affected variants and required configuration before any remediation.");
 if(gaps.some(g=>g.field==="version"))steps.push("Seek firmware evidence from approved records; defer live interrogation to an authorized maintenance window.");
 if(gaps.some(g=>g.field==="exposure"))steps.push("Review existing zone/conduit diagrams, ACLs and passive monitoring to characterize reachability.");
 if(gaps.some(g=>g.field==="criticality"))steps.push("Ask the OT system owner to classify operational/safety consequences; do not infer them from device type.");
 steps.push("Review suitable compensating controls and document evidence before changing their status.");
 return{gaps,steps,controls:CONTROL_CATALOG};
}
const STATUSES=["Not assessed","Under investigation","Waiting on vendor","Awaiting maintenance","Mitigation planned","Evidence reviewed","Closed - not applicable"];
const CONTROL_STATUSES=["Not assessed","Proposed","Existing - unverified","Evidence verified","Not applicable"];
function sanitizeReview(input={}){
 const read=(value,max=4000)=>txt(value).slice(0,max);
 const controls={};
 for(const item of CONTROL_CATALOG){const value=input.controls?.[item.id]||{};
  controls[item.id]={status:CONTROL_STATUSES.includes(value.status)?value.status:"Not assessed",
                     evidence:read(value.evidence,1200)};
  if(controls[item.id].status==="Evidence verified"&&!controls[item.id].evidence)
   controls[item.id].status="Existing - unverified";
 }
 return{
  status:STATUSES.includes(input.status)?input.status:"Not assessed",
  owner:read(input.owner,160),dueDate:/^\d{4}-\d\d-\d\d$/.test(read(input.dueDate))?read(input.dueDate):"",
  notes:read(input.notes),evidence:read(input.evidence,1800),
  updatedAt:/^\d{4}-\d\d-\d\dT/.test(read(input.updatedAt))?read(input.updatedAt):"",
  controls
 };
}
function makePackage(assets,cases,intelligenceAt,generatedAt){
 const list=Array.from(cases instanceof Map?cases.entries():Object.entries(cases||{})).map(([key,value])=>[txt(key),sanitizeReview(value)]);
 return{zeroguardOTAssessment:1,generatedAt:generatedAt||new Date().toISOString(),
   intelligenceGeneratedAt:txt(intelligenceAt),
   warning:"Asset-to-CVE records are screening leads only; no live OT device validation was performed.",
   assets:(assets||[]).map(x=>({...x})),caseReviews:Object.fromEntries(list)};
}
function loadPackage(raw){
 if(!raw||raw.zeroguardOTAssessment!==1||!Array.isArray(raw.assets)||raw.assets.length>5000)throw Error("Invalid ZeroGuard OT assessment package.");
 if(raw.assets.some(x=>!x||typeof x!=="object"||!known(x.name)))throw Error("Assessment contains incomplete asset rows.");
 const cases=new Map();
 for(const [key,value] of Object.entries(raw.caseReviews||{})){if(!/^.+::CVE-\d{4}-\d{4,}$/i.test(key))continue;cases.set(key,sanitizeReview(value));}
 return{assets:raw.assets.map(x=>({...x})),cases};
}
return{EVIDENCE,CONTROL_CATALOG,STATUSES,CONTROL_STATUSES,inventoryGaps,priority,confidence,recommendations,
  caseKey,assetKey,sanitizeReview,makePackage,loadPackage};
});
