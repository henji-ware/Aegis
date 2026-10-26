'use strict';
const{parseClamSummary}=require('./validation.cjs');
class ClamOutput{
 constructor(limit=2000){this.tail='';this.threats=[];this.limit=limit;this.detectedLines=0;this.partial=false;this.seen=new Set();}
 accept(line){
  this.tail=(this.tail+line+'\n').slice(-131072);
  if(/Heuristics\.Limits\.Exceeded|size limit reached|Scanning limit reached|ERROR:|Permission denied|Access is denied|Can't open file/i.test(line))this.partial=true;
  const match=line.match(/^(.+): (.+) FOUND$/);
  if(match){
   const id=match[1]+'\0'+match[2];
   if(!this.seen.has(id)){this.detectedLines++;if(this.threats.length<this.limit){this.threats.push({path:match[1],name:match[2]});this.seen.add(id);}}
  }
 }
 result(code){
  const parsed=parseClamSummary(this.tail,code);
  const infected=Math.max(parsed.infected||0,this.detectedLines);
  const partial=this.partial||parsed.limited||parsed.errors>0||code===2||parsed.scanned===null;
  return{...parsed,infected,threats:this.threats,threatsTruncated:infected>this.threats.length,partial,state:infected>0?'threats':code===0&&!partial?'completed':'error'};
 }
}
module.exports={ClamOutput};

