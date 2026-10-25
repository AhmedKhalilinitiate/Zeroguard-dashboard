const assert=require("node:assert/strict");
const fs=require("node:fs");
const {JSDOM}=require("jsdom");
const dom=new JSDOM("",{url:"https://example.test",runScripts:"outside-only"});
dom.window.DecompressionStream=globalThis.DecompressionStream;
dom.window.eval(fs.readFileSync("xlsx.js","utf8"));
const xlsx=dom.window.ZeroGuardXLSX;
const sample=[
 {index:3,values:["Substation Name:","9005 380/132KV BSP SUBSTATION"]},
 {index:4,values:["Substation Location:","CENTRAL OPERATING AREA, RIYADH"]},
 {index:8,values:["Sr. no.","Asset Type","Asset Qty.","Vendor Name","Model Number","Firmware Number","Panel Name","Panel Qty."]},
 {index:9,values:["TELECOM ROOM"]},
 {index:10,values:["1","SWITCH","6","SIEMENS","RUGGEDCOM RSG2100","","WAN PANEL"]},
 {index:11,values:["2","RTU","2","ABB","560PSU01","","RTU PANEL"]},
 {index:18,values:["CONTROL ROOM"]},
 {index:19,values:["3","IED","3","SEL","SEL 411L","","PROTECTION"]},
 {index:20,values:["CONTRCTOR SCOPE"]}
];
const assets=xlsx.detectOT(sample,"9005 SUBSTATION.xlsx");
assert.equal(assets.length,3);
assert.equal(assets[0].quantity,6);
assert.equal(assets[2].room,"CONTROL ROOM");
assert.equal(assets[1].version,"");
assert.equal(assets[0].site,"9005 380/132KV BSP SUBSTATION");
const m=require("../matcher.js");
const vulns=[
 {id:"CVE-2026-12345",vendor:"Siemens",product:"RUGGEDCOM RSG2100",affectedSystems:[{name:"Siemens RUGGEDCOM RSG2100",version:"Version not specified",source:"CISA KEV"}],inKEV:true},
 {id:"CVE-2026-12346",vendor:"Siemens",product:"SIMATIC",affectedSystems:[{name:"Siemens SIMATIC",version:"Version not specified",source:"CISA KEV"}],inKEV:false},
 {id:"CVE-2026-12347",vendor:"Other Vendor",product:"RSG2100",affectedSystems:[],inKEV:false}
];
const scan=m.scan(assets,vulns,{otScreen:true});
assert.equal(scan.modelLeads,1,"Exact model reference must be surfaced");
assert.equal(scan.vendorLeads,1,"Other Siemens product should be unconfirmed vendor-level lead");
assert.equal(scan.findings.some(f=>f.cve==="CVE-2026-12347"),false,"Model without same vendor is not a match");
assert.equal(scan.findings.find(f=>f.cve==="CVE-2026-12345").status,"model-lead");
assert.equal(scan.confirmed,0,"Missing firmware cannot confirm a vulnerability");
console.log("OT Excel row parser and conservative model-screening checks passed");
