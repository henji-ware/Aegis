const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const{validateProfile,validatePort,validateRuleId,parseClamSummary,publicError}=require('../electron/validation.cjs');
const{firewallCheck}=require('../electron/audit.cjs');
const{Store}=require('../electron/store.cjs');
const KEY='A'.repeat(43)+'=';
const base='[Interface]\nPrivateKey = '+KEY+'\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = '+KEY+'\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example.org:51820\n';
test('WireGuard accepts standard profile and separates public metadata',()=>{const result=validateProfile(base);assert.equal(result.meta.endpoint,'vpn.example.org:51820');assert.equal(result.meta.fullTunnel,true);assert.equal(result.meta.ipv6,true);assert.equal(JSON.stringify(result.meta).includes(KEY),false);});
test('WireGuard rejects all executable hooks and shell fragments',()=>{for(const hook of ['PostUp','PreUp','PostDown','PreDown','SaveConfig'])assert.throws(()=>validateProfile(base+'\n'+hook+' = echo unsafe'));assert.throws(()=>validateProfile(base.replace('vpn.example.org:51820','$(whoami):22')));assert.throws(()=>validateProfile(base.replace('1.1.1.1','1.1.1.1; echo unsafe')));});
test('WireGuard rejects missing keys, invalid keys, duplicate interface sections and excessive peers',()=>{assert.throws(()=>validateProfile('[Interface]\nAddress = 10.0.0.1/32'));assert.throws(()=>validateProfile(base.replace(KEY,'not-a-key')));assert.throws(()=>validateProfile(base+'[Interface]\nPrivateKey = '+KEY));});
test('WireGuard validates IPv4, IPv6, CIDR and endpoint port boundaries',()=>{assert.throws(()=>validateProfile(base.replace('/32','/33')));assert.throws(()=>validateProfile(base.replace('51820','65536')));assert.throws(()=>validateProfile(base.replace('10.0.0.2','999.0.0.2')));assert.throws(()=>validateProfile('a'.repeat(70000)));});
test('only valid ports and owned rule identifiers are accepted',()=>{assert.equal(validatePort('443'),443);for(const value of [0,65536,22.2,'443; echo bad',''])assert.throws(()=>validatePort(value));assert.throws(()=>validateRuleId('Windows-system-rule'));});
test('scanner never interprets an execution error as a clean result',()=>{assert.equal(parseClamSummary('',2).state,'error');assert.equal(parseClamSummary('Scanned files: 0\nInfected files: 0\n',0).state,'completed');assert.equal(parseClamSummary('Scanned files: 10\nInfected files: 0\nTotal errors: 2\n',0).state,'error');assert.equal(parseClamSummary('Scanned files: 10\nInfected files: 0\nHeuristics.Limits.Exceeded',0).state,'error');});
test('scanner preserves detections for paths containing colons',()=>{const result=parseClamSummary('C:\\test\\file.txt: Test.Signature FOUND\nScanned files: 1\nInfected files: 1',1);assert.equal(result.state,'threats');assert.equal(result.threats[0].path,'C:\\test\\file.txt');assert.equal(result.infected,1);});
test('unknown firewall state is never reported as passing',()=>{assert.equal(firewallCheck({ok:false,error:'denied'}).status,'unknown');assert.equal(firewallCheck({ok:true,data:{profiles:[]}}).status,'warning');assert.equal(firewallCheck({ok:true,data:{profiles:[{Name:'Public',Enabled:false}]}}).status,'warning');});
test('local store persists real events and limits retained records',()=>{const parent=path.resolve(__dirname,'..','.aegis-test','store');fs.mkdirSync(parent,{recursive:true});const dir=fs.mkdtempSync(path.join(parent,'case-'));try{const store=new Store(dir);store.event('audit','Saved','Local evidence','success');const restored=new Store(dir);assert.equal(restored.state.history[0].title,'Saved');assert.equal(restored.state.history[0].status,'success');}finally{assert.ok(path.resolve(dir).startsWith(parent+path.sep));fs.rmSync(dir,{recursive:true,force:true});}});
test('errors omit strings shaped like private VPN keys',()=>assert.equal(publicError(new Error(KEY)).includes(KEY),false));


