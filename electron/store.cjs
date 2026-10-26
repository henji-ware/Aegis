'use strict';
const fs=require('node:fs'),path=require('node:path');
const{randomUUID}=require('node:crypto');
function defaults(){return{version:1,settings:{reducedMotion:false,liveNetwork:false},history:[],audits:[],scans:[],rules:[],firewallBackup:null,profiles:[],quarantine:[],activeVpn:null,activeScan:null};}
function parseState(text){
 const value=JSON.parse(text.replace(/^\uFEFF/,''));
 if(!value||value.version!==1)throw new Error('Versão desconhecida do armazenamento local.');
 for(const key of ['history','audits','scans','rules','profiles'])if(!Array.isArray(value[key]))throw new Error('Coleção local inválida: '+key);
 if(!value.settings||typeof value.settings.reducedMotion!=='boolean'||typeof value.settings.liveNetwork!=='boolean')throw new Error('Preferências locais inválidas.');
 return{...defaults(),...value};
}
class Store{
 constructor(dir){
  this.dir=path.resolve(dir);fs.mkdirSync(this.dir,{recursive:true,mode:0o700});
  this.file=path.join(this.dir,'state.json');this.backup=this.file+'.bak';this.state=defaults();this.recoveryMessage=null;
  if(fs.existsSync(this.file)){
   try{this.state=parseState(fs.readFileSync(this.file,'utf8'));}
   catch(error){
    if(!fs.existsSync(this.backup))throw new Error('O arquivo de dados local está inválido. Preserve state.json antes de recuperar: '+error.message);
    this.state=parseState(fs.readFileSync(this.backup,'utf8'));
    const preserved=path.join(this.dir,'state.corrupt-'+Date.now()+'.json');fs.copyFileSync(this.file,preserved);
    this.recoveryMessage='Dados locais recuperados da cópia anterior. O arquivo inválido foi preservado.';
    this.save();this.event('system','Recuperação de dados',this.recoveryMessage,'warning');
   }
  }
 }
 save(){
  const json=JSON.stringify(this.state,null,2);parseState(json);
  const temp=path.join(this.dir,'state-'+randomUUID()+'.tmp');
  const handle=fs.openSync(temp,'wx',0o600);
  try{fs.writeFileSync(handle,json);fs.fsyncSync(handle);}finally{fs.closeSync(handle);}
  try{if(fs.existsSync(this.file)){try{parseState(fs.readFileSync(this.file,'utf8'));fs.copyFileSync(this.file,this.backup);}catch(error){if(error.code)throw error;}}fs.renameSync(temp,this.file);}
  catch(error){try{fs.unlinkSync(temp);}catch{}throw error;}
 }
 event(type,title,detail='',status='info'){
  const event={id:randomUUID(),type,title,detail,status,at:new Date().toISOString()};
  this.state.history.unshift(event);this.state.history=this.state.history.slice(0,500);this.save();return event;
 }
 audit(result){this.state.audits.unshift(result);this.state.audits=this.state.audits.slice(0,30);this.save();}
}
module.exports={Store,parseState};

