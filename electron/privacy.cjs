'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os'),net=require('node:net');
const{randomUUID}=require('node:crypto');
const runner=require('./runner.cjs');
const{spawn,findTool,exists}=runner;
const{validateProfile,publicError}=require('./validation.cjs');
const{protectScript}=require('./dpapi.cjs');
class Privacy{
 constructor({store,safeStorage,resources,emit,platform=process.platform,operations=runner,io=fs,networkInterfaces=os.networkInterfaces}){
  Object.assign(this,{store,safeStorage,resources,emit,platform,ops:operations,io,networkInterfaces});
  this.changing=false;this.torChild=null;this.tor={state:'stopped',progress:0,port:null,lines:[]};
 }
 secureStorage(){return this.safeStorage.isEncryptionAvailable()&&(this.platform!=='linux'||this.safeStorage.getSelectedStorageBackend()!=='basic_text');}
 async wgTools(){
  if(this.platform==='win32'){
   const dir=path.join(process.env.ProgramFiles||'C:\\Program Files','WireGuard'),bundled=path.join(this.resources,'wireguard');
   return{client:await this.ops.findTool('wireguard',[path.join(bundled,'wireguard.exe'),path.join(dir,'wireguard.exe')]),wg:await this.ops.findTool('wg',[path.join(bundled,'wg.exe'),path.join(dir,'wg.exe')])};
  }
  return{client:await this.ops.findTool('wg-quick'),wg:await this.ops.findTool('wg')};
 }
 fileFor(active){
  if(!active||!/^ag[a-f0-9]{10}$/.test(active.tunnel))throw new Error('Referência de túnel local inválida.');
  const file=path.join(this.store.dir,'tunnels',active.tunnel+'.conf'+(this.platform==='win32'?'.dpapi':''));
  if(active.file&&path.resolve(active.file)!==path.resolve(file))throw new Error('O arquivo de configuração não pertence a este túnel.');
  return file;
 }
 async importProfile(file){
  if(!this.secureStorage())throw new Error('O cofre do sistema não está disponível. Configure um chaveiro seguro antes de importar chaves VPN.');
  const info=await this.io.stat(file);if(!info.isFile()||info.size>65536)throw new Error('Selecione um arquivo .conf de até 64 KB.');
  const{text,meta}=validateProfile(await this.io.readFile(file,'utf8'));
  const id=randomUUID(),name=path.basename(file,'.conf').replace(/[^\p{L}\p{N} _.-]/gu,'').slice(0,48)||'VPN';
  this.store.state.profiles.push({id,name,meta,encrypted:this.safeStorage.encryptString(text).toString('base64'),at:new Date().toISOString()});
  this.store.event('vpn','Perfil VPN importado',name,'success');return{id,name,meta};
 }
 async observe(active){
  this.fileFor(active);
  try{
   if(this.platform==='win32'){
    const name=this.ops.psQuote('WireGuardTunnel$'+active.tunnel);
    const script="try {$s=Get-Service -Name "+name+" -ErrorAction Stop; [pscustomobject]@{present=$true;running=($s.Status -eq 'Running')} | ConvertTo-Json -Compress} catch {if ($_.FullyQualifiedErrorId -match '^NoServiceFoundForGivenName') {'{\"present\":false,\"running\":false}'} else {throw}}";
    const data=await this.ops.psJSON(script);
    if(typeof data?.present!=='boolean'||typeof data?.running!=='boolean')throw new Error('Resposta do serviço inválida.');
    return{present:data.present,interfaceActive:data.running,interfaceName:active.tunnel};
   }
   let actual=active.tunnel;
   if(this.platform==='darwin'){
    try{actual=(await this.io.readFile('/var/run/wireguard/'+active.tunnel+'.name','utf8')).trim();}
    catch(error){if(error.code==='ENOENT')return{present:false,interfaceActive:false,interfaceName:null};throw error;}
    if(!/^utun[0-9]{1,6}$/.test(actual))throw new Error('Mapeamento utun inválido.');
   }
   const present=Object.hasOwn(this.networkInterfaces(),actual);
   return{present,interfaceActive:present,interfaceName:actual};
  }catch(error){return{present:null,interfaceActive:null,interfaceName:null,observationError:publicError(error)};}
 }
 async vpnStatus(){
  const tools=await this.wgTools(),active=this.store.state.activeVpn;
  const profiles=this.store.state.profiles.map(p=>({id:p.id,name:p.name,meta:p.meta,at:p.at}));
  const state=active?{id:active.id,name:active.name,tunnel:active.tunnel,startedAt:active.startedAt,pending:Boolean(active.pending),error:active.error||null,...await this.observe(active)}:null;
  return{installed:Boolean(tools.client),secureStorage:this.secureStorage(),profiles,active:state,verification:'A interface ativa não confirma handshake recente, rotas, DNS ou ausência de vazamentos.'};
 }
 async elevateClient(client,args){
  if(this.platform==='darwin')return this.ops.elevate('/usr/bin/env',['PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin',client,...args]);
  return this.ops.elevate(client,args);
 }
 async connect(id){
  if(this.changing)throw new Error('Aguarde a operação VPN atual.');
  this.changing=true;
  try{
   if(this.store.state.activeVpn)throw new Error('Desconecte ou limpe o túnel anterior antes de conectar outro.');
   const profile=this.store.state.profiles.find(p=>p.id===id);if(!profile)throw new Error('Perfil não encontrado.');
   if(!this.secureStorage())throw new Error('Cofre do sistema indisponível.');
   const{client}=await this.wgTools();if(!client)throw new Error('Instale WireGuard ou wireguard-tools para conectar.');
   const clean=validateProfile(this.safeStorage.decryptString(Buffer.from(profile.encrypted,'base64')));
   const active={id,tunnel:'ag'+id.replace(/-/g,'').slice(0,10),name:profile.name,startedAt:new Date().toISOString(),pending:true};
   const file=this.fileFor(active);active.file=file;
   await this.io.mkdir(path.dirname(file),{recursive:true,mode:0o700});
   if(this.platform==='win32'){
    const protected64=await this.ops.ps(protectScript(active.tunnel),{input:Buffer.from(clean.text,'utf8').toString('base64')});
    if(!/^[A-Za-z0-9+/=\s]+$/.test(protected64)||protected64.length<64)throw new Error('Não foi possível proteger a configuração WireGuard.');
    await this.io.writeFile(file,Buffer.from(protected64.trim(),'base64'),{mode:0o600,flag:'wx'});
   }else await this.io.writeFile(file,clean.text,{mode:0o600,flag:'wx'});
   this.store.state.activeVpn=active;this.store.save();
   try{
    if(this.platform==='win32')await this.ops.elevatedPS('& '+this.ops.psQuote(client)+' /installtunnelservice '+this.ops.psQuote(file)+"; if ($LASTEXITCODE -ne 0) {throw 'WireGuard falhou'}");
    else await this.elevateClient(client,['up',file]);
   }catch(error){
    const observation=await this.observe(active);
    if(observation.present===false){await this.io.unlink(file).catch(()=>{});this.store.state.activeVpn=null;}
    else{active.pending=true;active.error='A ativação não foi confirmada. Use Desconectar para recuperar o estado antes de tentar novamente.';}
    this.store.event('vpn','Falha ao ativar VPN',publicError(error),'warning');throw error;
   }
   active.pending=false;this.store.event('vpn','Ativação VPN solicitada',profile.name,'info');return this.vpnStatus();
  }finally{this.changing=false;}
 }
 async disconnect(){
  if(this.changing)throw new Error('Aguarde a operação VPN atual.');this.changing=true;
  try{
   const active=this.store.state.activeVpn;if(!active)throw new Error('Nenhum túnel gerenciado pelo Aegis.');
   const file=this.fileFor(active),observed=await this.observe(active);
   if(observed.present!==false){
    const{client}=await this.wgTools();if(!client)throw new Error('WireGuard não encontrado.');
    if(this.platform==='win32')await this.ops.elevatedPS('& '+this.ops.psQuote(client)+' /uninstalltunnelservice '+this.ops.psQuote(active.tunnel)+"; if ($LASTEXITCODE -ne 0) {throw 'WireGuard falhou'}");
    else await this.elevateClient(client,['down',file]);
    const after=await this.observe(active);
    if(after.present!==false)throw new Error('A remoção do túnel não pôde ser confirmada. O perfil foi preservado para recuperação.');
   }
   await this.io.unlink(file).catch(error=>{if(error.code!=='ENOENT')throw error;});
   this.store.state.activeVpn=null;this.store.event('vpn','Túnel VPN removido',active.name,'success');return this.vpnStatus();
  }finally{this.changing=false;}
 }
 removeProfile(id){
  if(this.store.state.activeVpn?.id===id)throw new Error('Desconecte o perfil antes de removê-lo.');
  if(!this.store.state.profiles.some(p=>p.id===id))throw new Error('Perfil não encontrado.');
  this.store.state.profiles=this.store.state.profiles.filter(p=>p.id!==id);this.store.save();return true;
 }

  async torBinary(){return findTool('tor',[path.join(this.resources,'tor','tor',process.platform==='win32'?'tor.exe':'tor'),path.join(this.resources,'tor',process.platform==='win32'?'tor.exe':'tor')]);}
  async torStatus(){return {...this.tor,installed:Boolean(await this.torBinary())};}
  async startTor(){if(this.torStarting||this.torChild)throw new Error('O Tor já está iniciado ou conectando.');this.torStarting=true;this.torCancelRequested=false;try{return await this._startTor();}finally{this.torStarting=false;}}
  async _startTor(){
    if(this.torChild)throw new Error('O Tor já está iniciado.');
    const binary=await this.torBinary();if(!binary)throw new Error('O mecanismo Tor não está disponível para esta plataforma.');
    const dir=path.join(this.store.dir,'tor');await fs.mkdir(dir,{recursive:true,mode:0o700});
    // Reserve an ephemeral loopback port, then let Tor bind it. Failure is reported rather than hidden.
    const port=await new Promise((resolve,reject)=>{const server=net.createServer();server.on('error',reject);server.listen(0,'127.0.0.1',()=>{const p=server.address().port;server.close(()=>resolve(p));});});
    const config=path.join(dir,'torrc'); await fs.writeFile(config,'# Configuração isolada do Aegis\n',{mode:0o600});
    const args=['-f',config,'--DataDirectory',dir,'--SocksPort','127.0.0.1:'+port,'--ClientOnly','1','--AvoidDiskWrites','1','--Log','notice stdout'];
    const geo=path.join(this.resources,'tor','data','geoip'),geo6=path.join(this.resources,'tor','data','geoip6');
    if(await exists(geo))args.push('--GeoIPFile',geo);if(await exists(geo6))args.push('--GeoIPv6File',geo6);
    if(this.torCancelRequested)throw new Error('Operação cancelada.');
    this.tor={state:'starting',progress:0,port,lines:[]};
    const child=spawn(binary,args,{windowsHide:true,stdio:['ignore','pipe','pipe']});this.torChild=child;
    let pending='';
    const accept=chunk=>{
      pending+=chunk.toString();const parts=pending.split(/\r?\n/);pending=parts.pop()||'';
      for(const line of parts){this.tor.lines.push(line.slice(0,500));const match=line.match(/Bootstrapped (\d+)%/);if(match){this.tor.progress=Number(match[1]);if(this.tor.progress===100)this.tor.state='ready';}}
      this.tor.lines=this.tor.lines.slice(-30);this.emit('tor',this.tor);
    };
    child.stdout.on('data',accept);child.stderr.on('data',accept);
    child.on('error',error=>{if(this.torChild!==child)return;this.torChild=null;this.tor.state='error';this.tor.error=publicError(error);this.emit('tor',this.tor);});
    child.on('close',code=>{if(this.torChild!==child)return;this.torChild=null;if(this.tor.state!=='stopped'){this.tor.state=code===0?'stopped':'error';this.tor.error=code===0?null:'Tor encerrou com código '+code;}this.emit('tor',this.tor);});
    this.store.event('tor','Conexão Tor iniciada','Proxy SOCKS local. Apenas aplicativos configurados usam este proxy.','info');
    this.emit('tor',this.tor);return this.tor;
  }
  stopTor(){this.torCancelRequested=true;this.tor.state='stopped';this.tor.progress=0;if(this.torChild)this.torChild.kill();this.emit('tor',this.tor);return this.tor;}
}
module.exports={Privacy};


