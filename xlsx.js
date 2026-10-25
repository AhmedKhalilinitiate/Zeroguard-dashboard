/* Local-only OOXML reader for tabular OT substation inventories (no network or uploads).
 * Supports ordinary .xlsx ZIP/Deflate worksheets and sharedStrings/inlineStr.
 * This is NOT a general Excel formula evaluator. Formula-only cells have no reliable
 * calculated values unless a cached <v> exists.
 */
(function(root,factory){const api=factory();if(root)root.ZeroGuardXLSX=api;if(typeof module!=="undefined"&&module.exports)module.exports=api;})(typeof window!=="undefined"?window:null,function(){
"use strict";
const decoder=new TextDecoder(),MAX_FILE=5*1024*1024,MAX_PART=14*1024*1024;
function u16(d,p){return d.getUint16(p,true);}
function u32(d,p){return d.getUint32(p,true);}
function zipEntries(buffer){
 if(buffer.byteLength>MAX_FILE)throw Error("Workbook exceeds 5 MB.");
 const d=new DataView(buffer),bytes=new Uint8Array(buffer);let end=-1;
 for(let i=bytes.length-22;i>=Math.max(0,bytes.length-65557);i--){if(u32(d,i)===0x06054b50){end=i;break;}}
 if(end<0)throw Error("Not a valid XLSX ZIP archive.");
 const count=u16(d,end+10),offset=u32(d,end+16);
 if(count>600)throw Error("Too many ZIP entries.");
 let pos=offset;const entries=new Map();
 for(let i=0;i<count;i++){
  if(pos+46>bytes.length||u32(d,pos)!==0x02014b50)throw Error("Invalid ZIP directory.");
  const method=u16(d,pos+10),compressed=u32(d,pos+20),length=u32(d,pos+24);
  const namelen=u16(d,pos+28),extra=u16(d,pos+30),comment=u16(d,pos+32),local=u32(d,pos+42);
  const name=decoder.decode(bytes.subarray(pos+46,pos+46+namelen));
  if(!name.includes("..")&&name.startsWith("xl/")&&!name.endsWith("/")&&length<=MAX_PART)
   entries.set(name,{method,compressed,length,local});
  pos+=46+namelen+extra+comment;
 }
 return {d,bytes,entries};
}
async function get(zip,path){
 const e=zip.entries.get(path);if(!e)return null;
 const p=e.local;
 if(p+30>zip.bytes.length||u32(zip.d,p)!==0x04034b50)throw Error("Invalid ZIP entry "+path);
 const start=p+30+u16(zip.d,p+26)+u16(zip.d,p+28);
 if(start+e.compressed>zip.bytes.length)throw Error("Truncated ZIP entry "+path);
 const compressed=zip.bytes.subarray(start,start+e.compressed);
 if(e.method===0)return decoder.decode(compressed);
 if(e.method!==8)throw Error("Unsupported XLSX compression method "+e.method);
 if(typeof DecompressionStream==="undefined")throw Error("This browser cannot decompress XLSX. Use the CSV template instead.");
 const stream=new Blob([compressed]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
 const buffer=await new Response(stream).arrayBuffer();
 if(buffer.byteLength>MAX_PART)throw Error("XLSX worksheet too large.");
 return decoder.decode(buffer);
}
function xml(source){const doc=new DOMParser().parseFromString(source,"application/xml");if(doc.getElementsByTagName("parsererror").length)throw Error("Malformed XLSX XML.");return doc;}
function nodes(obj,tag){return Array.from(obj.getElementsByTagNameNS("*",tag));}
function col(ref){const code=/^[A-Z]+/.exec(ref||"")?.[0]||"";let n=0;for(const ch of code)n=n*26+ch.charCodeAt(0)-64;return n-1;}
function sheetRows(raw,strings){
 const doc=xml(raw),rows=[];
 for(const row of nodes(doc,"row")){
  const index=Number(row.getAttribute("r"))||rows.length+1;
  const values=[];
  for(const cell of nodes(row,"c")){
   const offset=col(cell.getAttribute("r"));if(offset<0||offset>80)continue;
   let value=nodes(cell,"v")[0]?.textContent||"";
   if(cell.getAttribute("t")==="s")value=strings[Number(value)]||"";
   else if(cell.getAttribute("t")==="inlineStr")value=nodes(cell,"is")[0]?.textContent||"";
   values[offset]=String(value).trim();
  }
  rows.push({index,values});
 }
 return rows;
}
const text=x=>String(x??"").trim();
function detectOT(rows,filename){
 const headers=rows.find(r=>/^asset\s*type$/i.test(text(r.values[1]))&&/vendor/i.test(text(r.values[3]))&&/model/i.test(text(r.values[4])));
 if(!headers)throw Error("This Excel sheet has no recognized OT inventory header (Asset Type, Vendor Name, Model Number).");
 const site=rows.find(r=>/substation name/i.test(text(r.values[0])))?.values[1]||filename.replace(/\.xlsx$/i,"");
 const location=rows.find(r=>/substation location/i.test(text(r.values[0])))?.values[1]||"";
 const code=/\b\d{4,6}\b/.exec(site)?.[0]||text(site).replace(/\s+/g,"-").slice(0,24);
 const result=[];let room="";
 for(const row of rows.filter(r=>r.index>headers.index)){
  const cells=row.values,section=text(cells[0]),type=text(cells[1]);
  if(/CONTR[A-Z]*CTOR\s+SCOPE/i.test(section))break;
  if(section&&!type&&/ROOM|TELECOM/i.test(section)){room=section;continue;}
  if(!type||/asset\s*type/i.test(type))continue;
  const model=text(cells[4]),vendor=text(cells[3]);
  if(!model&&!vendor)continue;
  const qty=Number(cells[2]);const quantity=Number.isFinite(qty)&&qty>0?qty:1;
  result.push({id:code+"-"+String(row.index).padStart(3,"0"),name:model||type,vendor,version:text(cells[5]),
   host:[site,room,text(cells[6])].filter(Boolean).join(" | "),site,location,room,panel:text(cells[6]),
   assetType:type,quantity,sourceRow:row.index,sourceFile:filename,
   criticality:"unknown",exposure:"unknown",purl:"",cpe:""});
 }
 if(!result.length)throw Error("No recognizable equipment inventory rows found.");
 return result;
}
async function parse(buffer,filename){
 const zip=zipEntries(buffer),stringsRaw=await get(zip,"xl/sharedStrings.xml");
 const strings=stringsRaw?nodes(xml(stringsRaw),"si").map(el=>el.textContent||""):[];
 const sheets=Array.from(zip.entries.keys()).filter(p=>/^xl\/worksheets\/sheet\d+\.xml$/.test(p)).sort();
 if(!sheets.length)throw Error("No supported XLSX worksheet found.");
 const all=[],issues=[];
 for(const path of sheets){try{
  const rows=sheetRows(await get(zip,path),strings);
  all.push(...detectOT(rows,filename));
 }catch(err){issues.push(err.message);}}
 if(!all.length)throw Error("No OT inventory found: "+issues.join("; "));
 return all;
}
return{parse,detectOT,sheetRows,MAX_FILE};
});
