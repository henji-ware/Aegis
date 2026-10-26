'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),{EventEmitter}=require('node:events');
const{Privacy}=require('../electron/privacy.cjs'),{Firewall}=require('../electron/firewall.cjs'),{Antivirus}=require('../electron/antivirus.cjs');
const{ClamOutput}=require('../electron/clam-output.cjs'),{protectScript}=require('../electron/dpapi.cjs');
const key='A'.repeat(43)+'=',id='d30ac9e7-23f7-4594-9e6b-3499a18f9292';
const profile='[Interface]\nPrivateKey = '+key+'\nAddress = 10.8.0.2/32\n[Peer]\nPublicKey = '+key+'\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.org:51820\n';
function store(){return{dir:path.resolve(__dirname,'..','.aegis-test','virtual'),state:{profiles:[{id,name:'Test',meta:{endpoint:'vpn.example.org:51820'},encrypted:Buffer.from(profile).toString('base64')}],activeVpn:null,rules:[],firewallBackup:null,history:[],scans:[]},save(){},event(type,title,detail,status){this.state.history.push({type,title,detail,status});}};}
function vpnFixture(platform,{fail=false,unknown=false}={}){
 const state=store(),files=new Map(),calls=[];let present=false;
 const io={mkdir:async(...args)=>calls.push(['mkdir',...args]),writeFile:async(name,data,options)=>{assert.equal(options.mode,0o600);files.set(name,data);},unlink:async name=>{files.delete(name);calls.push(['unlink',name]);},readFile:async name=>{if(name.startsWith('/var/run/')){if(present)return 'utun7\n';const e=new Error('missing');e.code='ENOENT';throw e;}return files.get(name);}};
 const ops={findTool:async name=>'/trusted/'+name,psQuote:s=>"'"+s.replace(/'/g,"''")+"'",ps:async(script,options)=>{calls.push(['protect',script,options]);return Buffer.alloc(160,1).toString('base64');},psJSON:async()=>{if(unknown)throw new Error('read denied');return{present,running:present};},elevatedPS:async command=>{calls.push(['elevatedPS',command]);if(fail)throw new Error('denied');present=command.includes('/installtunnelservice');},elevate:async(file,args)=>{calls.push(['elevate',file,args]);if(fail)throw new Error('denied');present=args.includes('up');}};
 const vpn=new Privacy({store:state,safeStorage:{isEncryptionAvailable:()=>true,getSelectedStorageBackend:()=> 'gnome_libsecret',decryptString:b=>b.toString(),encryptString:s=>Buffer.from(s)},resources:'/resources',emit:()=>{},platform,operations:ops,io,networkInterfaces:()=>present?(platform==='darwin'?{utun7:[]}:{['ag'+id.replace(/-/g,'').slice(0,10)]:[]}):{}});
 return{vpn,state,files,calls,setPresent:v=>{present=v;}};
}
for(const platform of ['win32','linux','darwin'])test('VPN lifecycle on '+platform+' uses only its owned configuration',async()=>{
 const fixture=vpnFixture(platform);const active=await fixture.vpn.connect(id);
 assert.equal(active.active.interfaceActive,true);
 assert.equal('file'in active.active,false);assert.equal(JSON.stringify(active).includes('encrypted'),false);assert.equal(JSON.stringify(active).includes(key),false);
 if(platform==='darwin')assert.equal(active.active.interfaceName,'utun7');
 if(platform==='win32'){const call=fixture.calls.find(c=>c[0]==='protect');assert.ok(call[1].includes('CryptProtectData'));assert.ok(call[1].includes('ag'+id.replace(/-/g,'').slice(0,10)));assert.ok(!call[1].includes(key));}
 await fixture.vpn.disconnect();assert.equal(fixture.state.state.activeVpn,null);assert.equal(fixture.files.size,0);
});
test('known failed activation does not leave a profile blocking the next attempt',async()=>{const f=vpnFixture('win32',{fail:true});await assert.rejects(f.vpn.connect(id));assert.equal(f.state.state.activeVpn,null);assert.equal(f.files.size,0);});
test('uncertain failed activation keeps its recovery configuration',async()=>{const f=vpnFixture('win32',{fail:true,unknown:true});await assert.rejects(f.vpn.connect(id));assert.equal(f.state.state.activeVpn.pending,true);assert.equal(f.files.size,1);const result=await f.vpn.vpnStatus();assert.equal(result.active.interfaceActive,null);});
test('VPN mutation cannot run twice concurrently',async()=>{const f=vpnFixture('linux');const first=f.vpn.connect(id);await assert.rejects(f.vpn.connect(id),/Aguarde/);await first;});
test('VPN never unlinks a path from a tampered state file',async()=>{const f=vpnFixture('linux');f.state.state.activeVpn={id,tunnel:'ag1234567890',file:path.resolve(f.state.dir,'..','outside.conf')};await assert.rejects(f.vpn.disconnect(),/não pertence/);assert.equal(f.calls.some(c=>c[0]==='unlink'),false);});
test('DPAPI label is fixed to a validated WireGuard tunnel name',()=>{assert.throws(()=>protectScript("name'; bad"));assert.ok(protectScript('ag1234567890').includes("Protect($bytes,'ag1234567890')"));});
test('firewall snapshot and rollback preserve the previous Windows policy',async()=>{
 const saved=[{Name:'Domain',Enabled:2,DefaultInboundAction:0},{Name:'Private',Enabled:0,DefaultInboundAction:2},{Name:'Public',Enabled:1,DefaultInboundAction:4}],calls=[],state=store();
 const firewall=new Firewall(state,{platform:'win32',operations:{psJSON:async()=>saved,elevatedPS:async s=>calls.push(s)},status:async()=>({supported:true,profiles:saved})});
 await firewall.harden();assert.equal(state.state.firewallBackup.pending,false);await firewall.restore();assert.equal(state.state.firewallBackup,null);
 assert.ok(calls[1].includes('Domain -Enabled NotConfigured -DefaultInboundAction NotConfigured'));assert.ok(calls[1].includes('Private -Enabled False -DefaultInboundAction Allow'));assert.ok(calls[1].includes('Public -Enabled True -DefaultInboundAction Block'));
});
test('partial macOS hardening retains the snapshot for recovery',async()=>{
 const state=store();let calls=0;const firewall=new Firewall(state,{platform:'darwin',operations:{elevate:async()=>{if(++calls===2)throw new Error('denied');}},status:async()=>({enabled:false,stealth:false,supported:true})});
 await assert.rejects(firewall.harden());assert.equal(state.state.firewallBackup.pending,true);assert.equal(state.state.firewallBackup.before.enabled,false);
});
test('duplicate managed ports are rejected before any native mutation',async()=>{const state=store();state.state.rules.push({port:443});const firewall=new Firewall(state,{platform:'win32',operations:{elevatedPS:async()=>assert.fail('native mutation must not run')}});await assert.rejects(firewall.blockPort(443),/Já existe/);});
test('UFW external rule is not adopted or overwritten',async()=>{const state=store(),calls=[];const firewall=new Firewall(state,{platform:'linux',operations:{findTool:async()=>'/usr/sbin/ufw',elevate:async(_f,args)=>{calls.push(args);return'ufw deny 443/tcp';}},status:async()=>({supported:true})});await assert.rejects(firewall.blockPort(443),/não será modificada/);assert.equal(state.state.rules.length,0);assert.deepEqual(calls,[['show','added']]);});
test('UFW delete requires an ownership comment',async()=>{const state=store();state.state.rules=[{id:'Aegis-d30ac9e7-23f7-4594-9e6b-3499a18f9292',port:443}];let deletes=0;const firewall=new Firewall(state,{platform:'linux',operations:{findTool:async()=>'/usr/sbin/ufw',elevate:async(_f,args)=>{if(args.includes('delete'))deletes++;return'ufw deny 443/tcp';}}});await assert.rejects(firewall.removeRule(state.state.rules[0].id),/propriedade/);assert.equal(deletes,0);});
test('early antivirus detections survive a log larger than the tail buffer',()=>{const output=new ClamOutput();output.accept('/safe/test: Test.Signature FOUND');for(let i=0;i<4000;i++)output.accept('Log '.repeat(30)+i);output.accept('Scanned files: 100');output.accept('Infected files: 1');const result=output.result(1);assert.equal(result.threats[0].name,'Test.Signature');assert.equal(result.infected,1);assert.equal(result.state,'threats');});
test('read errors and limits remain partial even if the engine exits zero',()=>{const output=new ClamOutput();output.accept('ERROR: unreadable');for(let i=0;i<3000;i++)output.accept('log'.repeat(100));output.accept('Scanned files: 100');output.accept('Infected files: 0');assert.equal(output.result(0).state,'error');assert.equal(output.result(0).partial,true);});
test('detected threat remains visible if another file causes an execution error',()=>{const output=new ClamOutput();output.accept('/test: Test.Signature FOUND');output.accept('Scanned files: 1');output.accept('Infected files: 1');const result=output.result(2);assert.equal(result.state,'threats');assert.equal(result.partial,true);});
test('antivirus reserves a task before asynchronous preparation',async()=>{const av=new Antivirus({store:store(),resources:'unused',emit:()=>{}});let release;av._startUpdate=()=>new Promise(resolve=>{release=resolve;});const first=av.startUpdate();await assert.rejects(av.startScan('quick'),/Aguarde/);release('done');assert.equal(await first,'done');});

