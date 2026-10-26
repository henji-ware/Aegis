const path=require('node:path');
const{Store}=require('../electron/store.cjs');
const{Privacy}=require('../electron/privacy.cjs');
const root=path.resolve(__dirname,'..');
let timer,done=false,last='';
const privacy=new Privacy({store:new Store(path.join(root,'.aegis-test','tor')),resources:path.join(root,'resources'),safeStorage:{isEncryptionAvailable:()=>false},emit:(type,data)=>{
 const line=data.lines?.at(-1)||'';if(line!==last){console.log(line);last=line;}
 if(data.state==='ready'&&!done){done=true;clearTimeout(timer);console.log('TOR READY',JSON.stringify({progress:data.progress,port:data.port,scope:'loopback SOCKS only'}));privacy.stopTor();}
 if(data.state==='error'&&!done){done=true;clearTimeout(timer);process.exitCode=1;console.error(data.error);privacy.stopTor();}
}});
privacy.startTor().then(()=>{timer=setTimeout(()=>{if(!done){console.log('TOR TIMEOUT',JSON.stringify(privacy.tor));done=true;privacy.stopTor();process.exitCode=1;}},90000);}).catch(error=>{console.error(error);process.exitCode=1;});

