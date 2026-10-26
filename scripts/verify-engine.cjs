const fs=require('node:fs');
const path=require('node:path');
const{Store}=require('../electron/store.cjs');
const{Antivirus}=require('../electron/antivirus.cjs');
const root=path.resolve(__dirname,'..');
const dir=path.join(root,'.aegis-test','engine');
let last='',av;
av=new Antivirus({store:new Store(dir),resources:path.join(root,'resources'),emit:(type,job)=>{const line=job?.lines?.at(-1)||'';if(line!==last){console.log(line.slice(0,180));last=line;}if(job&&!['running','cancelling'].includes(job.state)){console.log('RESULT',JSON.stringify({state:job.state,error:job.error,summary:job.summary}));process.exitCode=job.state==='completed'?0:1;}}});
av.status().then(async status=>{console.log(JSON.stringify(status));await av.startUpdate();}).catch(e=>{console.error(e);process.exitCode=1;});

