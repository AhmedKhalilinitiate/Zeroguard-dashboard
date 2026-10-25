const assert=require("node:assert/strict");
const fs=require("node:fs");
const {JSDOM}=require("jsdom");
const dom=new JSDOM("",{url:"https://example.test",runScripts:"outside-only"});
dom.window.DecompressionStream=globalThis.DecompressionStream;
dom.window.TextDecoder=require("node:util").TextDecoder;
dom.window.Response=globalThis.Response;
dom.window.Blob=globalThis.Blob;
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

function storedZip(parts,compressed=false){
 const local=[],directory=[];let pos=0;
 for(const [name,content] of Object.entries(parts)){
  const nb=Buffer.from(name),payload=Buffer.from(content),compressedPayload=compressed?require("node:zlib").deflateRawSync(payload):payload;
  const h=Buffer.alloc(30);h.writeUInt32LE(0x04034b50,0);h.writeUInt16LE(20,4);h.writeUInt16LE(nb.length,26);h.writeUInt16LE(compressed?8:0,8);h.writeUInt32LE(compressedPayload.length,18);h.writeUInt32LE(payload.length,22);
  local.push(h,nb,compressedPayload);
  const cd=Buffer.alloc(46);cd.writeUInt32LE(0x02014b50,0);cd.writeUInt16LE(20,4);cd.writeUInt16LE(20,6);cd.writeUInt16LE(compressed?8:0,10);cd.writeUInt32LE(compressedPayload.length,20);cd.writeUInt32LE(payload.length,24);cd.writeUInt16LE(nb.length,28);cd.writeUInt32LE(pos,42);
  directory.push(cd,nb);pos+=h.length+nb.length+compressedPayload.length;
 }
 const dir=Buffer.concat(directory),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(directory.length/2,8);end.writeUInt16LE(directory.length/2,10);end.writeUInt32LE(dir.length,12);end.writeUInt32LE(pos,16);
 const out=Buffer.concat([...local,dir,end]);return out.buffer.slice(out.byteOffset,out.byteOffset+out.byteLength);
}
const worksheet='<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'+
'<row r="3"><c r="A3" t="inlineStr"><is><t>Substation Name:</t></is></c><c r="B3" t="inlineStr"><is><t>9005 SUBSTATION</t></is></c></row>'+
'<row r="8">'+[['B8','Asset Type'],['C8','Asset Qty.'],['D8','Vendor Name'],['E8','Model Number']].map(([cell,value])=>'<c r="'+cell+'" t="inlineStr"><is><t>'+value+'</t></is></c>').join('')+'</row>'+
'<row r="9"><c r="A9" t="inlineStr"><is><t>TELECOM ROOM</t></is></c></row>'+
'<row r="10"><c r="B10" t="inlineStr"><is><t>IED</t></is></c><c r="C10"><v>24</v></c><c r="D10" t="inlineStr"><is><t>SIEMENS</t></is></c><c r="E10" t="inlineStr"><is><t>SWT3000</t></is></c></row>'+
'</sheetData></worksheet>';
(async()=>{
 const parsed=await xlsx.parse(storedZip({'xl/worksheets/sheet1.xml':worksheet}),"9005 SUBSTATION.xlsx");
 assert.equal(parsed.length,1);
 assert.equal(parsed[0].quantity,24);
 assert.equal(parsed[0].name,"SWT3000");
 const deflated=await xlsx.parse(storedZip({"xl/worksheets/sheet1.xml":worksheet},true),"9005 SUBSTATION.xlsx");
 assert.equal(deflated[0].name,"SWT3000");
 console.log("Complete stored and deflated OOXML XLSX imports passed");
 dom.window.close();
})().catch(e=>{console.error(e);dom.window.close();process.exitCode=1;});
