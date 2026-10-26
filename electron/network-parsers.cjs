'use strict';
function endpoint(value){
 const index=value.lastIndexOf(':');if(index<0)return null;
 const address=value.slice(0,index).replace(/^\[|\]$/g,''),part=value.slice(index+1);
 if(part!=='*'&&!/^\d+$/.test(part))return null;
 const port=part==='*'?0:Number(part);if(port>65535)return null;
 return{address,port};
}
function parseSs(text){
 const result=[];
 for(const line of text.split(/\r?\n/)){
  const fields=line.trim().split(/\s+/);if(fields.length<5)continue;
  const [state,,,localText,remoteText]=fields;
  if(!['LISTEN','ESTAB'].includes(state))continue;
  const local=endpoint(localText),remote=endpoint(remoteText);if(!local||!remote)continue;
  const pid=Number(line.match(/pid=(\d+)/)?.[1]||0);
  result.push({id:pid+'-'+localText+'-'+remoteText,protocol:'TCP',pid,process:line.match(/users:\(\("([^"]+)"/)?.[1]||'Não identificado',localAddress:local.address,localPort:local.port,remoteAddress:remote.address,remotePort:remote.port,state:state==='LISTEN'?'Listen':'Established'});
  if(result.length>=350)break;
 }return result;
}
function parseLsof(text){
 let pid=0,process='',record=null;const result=[];
 const flush=()=>{
  if(!record||!['LISTEN','ESTABLISHED'].includes(record.state))return;
  const [localText,remoteText='*:0']=record.name.split('->'),local=endpoint(localText),remote=endpoint(remoteText);
  if(!local||!remote)return;
  result.push({id:record.pid+'-'+localText+'-'+remoteText,protocol:'TCP',pid:record.pid,process:record.process,localAddress:local.address,localPort:local.port,remoteAddress:remote.address,remotePort:remote.port,state:record.state==='LISTEN'?'Listen':'Established'});
 };
 for(const line of text.split(/\r?\n/)){
  if(line[0]==='p'){flush();record=null;pid=Number(line.slice(1));}
  else if(line[0]==='c')process=line.slice(1);
  else if(line[0]==='f'){flush();record=null;}
  else if(line[0]==='n'){if(record?.name)flush();record={pid,process,name:line.slice(1),state:''};}
  else if(line.startsWith('TST=')&&record)record.state=line.slice(4);
 }
 flush();return result.slice(0,350);
}
module.exports={endpoint,parseSs,parseLsof};

