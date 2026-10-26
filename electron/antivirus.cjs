'use strict';
const path=require('node:path');
const os=require('node:os');
const fs=require('node:fs/promises');
const {randomUUID}=require('node:crypto');
const {spawn,run,exists,findTool}=require('./runner.cjs');
const {publicError}=require('./validation.cjs');
const {ClamOutput}=require('./clam-output.cjs');
const {StringDecoder}=require('node:string_decoder');
class Antivirus {
  constructor({store, resources, emit,quickTargets}) {
    this.store=store; this.resources=resources; this.emit=emit;
    this.db=path.join(store.dir,'signatures');
    this.job=null; this.child=null; this.pending='';this.starting=false;this.quickTargets=quickTargets;
  }
  env() { const env={...process.env}; if(process.platform==='linux')env.LD_LIBRARY_PATH=[path.join(this.resources,'clamav','lib'),path.join(this.resources,'clamav','lib64'),path.join(this.resources,'clamav','usr','local','lib'),env.LD_LIBRARY_PATH].filter(Boolean).join(':'); if(process.platform==='darwin')env.DYLD_LIBRARY_PATH=[path.join(this.resources,'clamav','lib'),env.DYLD_LIBRARY_PATH].filter(Boolean).join(':'); return env; }
  async binaries() {
    const ext=process.platform==='win32'?'.exe':'';
    const directories=[path.join(this.resources,'clamav'), path.join(this.resources,'clamav','bin'), path.join(this.resources,'clamav','usr','local','bin')];
    const scanner=await findTool('clamscan',directories.map(d=>path.join(d,'clamscan'+ext)));
    const updater=await findTool('freshclam',directories.map(d=>path.join(d,'freshclam'+ext)));
    return {scanner,updater};
  }
  async signatureInfo() {
    const names=['daily.cvd','daily.cld','main.cvd','main.cld'];
    const files=[];
    for(const name of names) {
      const file=path.join(this.db,name);
      if(await exists(file)) {
        const stat=await fs.stat(file),handle=await fs.open(file,'r');
        const buffer=Buffer.alloc(512);
        try {await handle.read(buffer,0,512,0);} finally {await handle.close();}
        const header=buffer.toString('utf8').replace(/\0/g,'').trim().split(':');
        files.push({name,bytes:stat.size,updatedAt:stat.mtime.toISOString(),databaseDate:header[1]||'',version:header[2]||'',signatures:Number(header[3])||0,validHeader:header[0]==='ClamAV-VDB'});
      }
    }
    const daily=files.find(f=>f.name.startsWith('daily')&&f.validHeader),main=files.find(f=>f.name.startsWith('main')&&f.validHeader);
    return {ready:Boolean(daily&&main),files,updatedAt:daily?.updatedAt||null,count:files.reduce((n,f)=>n+f.signatures,0)};
  }
  async status() {
    const binaries=await this.binaries();
    let version=this.version||null;
    if(binaries.scanner&&!version) {try{version=await run(binaries.scanner,['--version'],{timeout:10000,env:this.env()});this.version=version;}catch{}}
    return {engine:'ClamAV',installed:Boolean(binaries.scanner),updaterAvailable:Boolean(binaries.updater),version,runnable:Boolean(version),signatures:await this.signatureInfo(),job:this.job,scans:this.store.state.scans.slice(0,20),realtime:false};
  }
  snapshot() {this.emit('antivirus',this.job);}
  async reserve(fn){if(this.child||this.starting)throw new Error('Aguarde a tarefa do antivírus terminar.');this.starting=true;try{return await fn();}finally{this.starting=false;}}
  startUpdate(){return this.reserve(()=>this._startUpdate());}
  startScan(type,selected){return this.reserve(()=>this._startScan(type,selected));}
  async _startUpdate() {
    if(this.child) throw new Error('Aguarde a tarefa do antivírus terminar.');
    const {updater}=await this.binaries();
    if(!updater) throw new Error('FreshClam não está disponível. Prepare o mecanismo ClamAV para esta plataforma.');
    await fs.mkdir(this.db,{recursive:true,mode:0o700});
    const config=path.join(this.store.dir,'freshclam.conf');
    const q=value=>'"'+String(value).replace(/\\/g,'/').replace(/"/g,'')+'"';
    await fs.writeFile(config,['DatabaseDirectory '+q(this.db),'DatabaseMirror database.clamav.net','DNSDatabaseInfo current.cvd.clamav.net','ScriptedUpdates yes','TestDatabases yes','ConnectTimeout 30','ReceiveTimeout 120','MaxAttempts 2','Bytecode yes',process.platform==='win32'?'':'DatabaseOwner '+q(os.userInfo().username)].filter(Boolean).join('\n')+'\n',{mode:0o600});
    return this.launch(updater,['--config-file='+config,'--stdout'],'update',null);
  }
  async _startScan(type, selected) {
    if(this.child) throw new Error('Já existe uma tarefa do antivírus em execução.');
    if(!['quick','full','custom'].includes(type)) throw new Error('Tipo de varredura inválido.');
    const {scanner}=await this.binaries();
    if(!scanner) throw new Error('O mecanismo ClamAV ainda não está disponível.');
    const signatures=await this.signatureInfo();
    if(!signatures.ready) throw new Error('Prepare a base de assinaturas antes de iniciar a varredura.');
    let targets;
    if(type==='custom') {
      if(!selected||!path.isAbsolute(selected)) throw new Error('Selecione uma pasta ou arquivo para verificar.');
      targets=[selected];
    } else if(type==='quick') {
      targets=(await Promise.all((this.quickTargets||['Downloads','Desktop'].map(name=>path.join(os.homedir(),name))).map(async p=>await exists(p)?p:null))).filter(Boolean);
      if(!targets.length) targets=[os.homedir()];
    } else targets=[process.platform==='win32'?path.parse(os.homedir()).root:'/'];
    const args=['--database='+this.db,'--recursive','--infected','--stdout','--official-db-only=yes','--alert-exceeds-max=yes','--max-filesize=100M','--max-scansize=400M','--follow-dir-symlinks=0','--follow-file-symlinks=0','--cross-fs=no'];
    if(process.platform!=='win32') args.push('--exclude-dir=^/proc(/|$)','--exclude-dir=^/sys(/|$)','--exclude-dir=^/dev(/|$)','--exclude-dir=^/run(/|$)');
    // Targets come from native picker or fixed local folders; no shell is invoked.
    args.push(...targets);
    return this.launch(scanner,args,type,targets);
  }
  launch(file,args,type,targets) {
    this.job={id:randomUUID(),type,state:'running',startedAt:new Date().toISOString(),endedAt:null,targets,lines:[],summary:null,engine:'ClamAV'};
    const job=this.job;
    this.pending='';
    this.store.state.activeScan=JSON.parse(JSON.stringify(this.job));this.store.save();
    const env=this.env();
    const child=spawn(file,args,{windowsHide:true,stdio:['ignore','pipe','pipe'],env});
    this.child=child;
    let output='',closed=false;
    const collector=new ClamOutput();
    const streams=[];
    const acceptLine=line=>{if(!line)return;collector.accept(line);output=(output+line+'\n').slice(-131072);job.lines.push(line.slice(0,700));job.lines=job.lines.slice(-65);this.snapshot();};
    const attach=stream=>{const state={decoder:new StringDecoder('utf8'),pending:''};streams.push(state);stream.on('data',chunk=>{state.pending+=state.decoder.write(chunk);const parts=state.pending.split(/\r\n|\n|\r/);state.pending=parts.pop()||'';for(const line of parts)acceptLine(line);if(state.pending.length>65536){collector.partial=true;acceptLine(state.pending.slice(0,700)+' [linha truncada]');state.pending='';}});};
    attach(child.stdout);attach(child.stderr);
    const finish=(code,error)=>{
      if(closed)return;closed=true;
      for(const stream of streams){acceptLine(stream.pending+stream.decoder.end());stream.pending='';}
      this.child=null;
      job.endedAt=new Date().toISOString();
      if(job.state==='cancelling')job.state='cancelled';
      else if(error){job.state='error';job.error=publicError(error);}
      else if(type==='update'){job.state=code===0?'completed':'error'; if(code!==0)job.error=publicError(output.slice(-1200));}
      else {
        job.summary=collector.result(code);
        job.state=job.summary.state;
        if(job.state==='error')job.error='Varredura incompleta. Consulte os registros para arquivos inacessíveis, limites ou falha do mecanismo.';
      }
      this.store.state.activeScan=null;
      const saved=JSON.parse(JSON.stringify(job));
      this.store.state.scans.unshift(saved);this.store.state.scans=this.store.state.scans.slice(0,30);
      try { this.store.event('antivirus',type==='update'?'Atualização de assinaturas':'Varredura '+({quick:'rápida',full:'completa',custom:'personalizada'}[type]||type),job.error||((job.summary?.infected||0)+' detecções; '+(job.summary?.scanned??'—')+' arquivos verificados.'),job.state==='completed'?'success':job.state==='threats'?'danger':'warning'); } catch(error){job.persistenceError='Não foi possível salvar o resultado: '+publicError(error);}
      this.snapshot();
    };
    child.on('error',error=>finish(null,error));child.on('close',code=>finish(code));
    this.snapshot();
    return {...job};
  }
  cancel() {
    if(this.child&&this.job){this.job.state='cancelling';this.child.kill('SIGTERM');this.snapshot();}
    return this.job;
  }
}
module.exports={Antivirus};

