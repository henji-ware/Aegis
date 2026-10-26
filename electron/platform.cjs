'use strict';
const os = require('node:os');
const fs = require('node:fs/promises');
const { run, psJSON, findTool } = require('./runner.cjs');
const{parseSs,parseLsof}=require('./network-parsers.cjs');
const { publicError } = require('./validation.cjs');
const list = value => value == null ? [] : Array.isArray(value) ? value : [value];
async function probe(fn) { try { return { ok:true, data:await fn() }; } catch(e) { return { ok:false, error:publicError(e) }; } }
async function firewallStatus() {
  if (process.platform === 'win32') return { backend:'Windows Firewall', profiles:list(await psJSON("Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress")), supported:true };
  if (process.platform === 'darwin') {
    const file='/usr/libexec/ApplicationFirewall/socketfilterfw';
    const global=await run(file,['--getglobalstate']), stealth=await run(file,['--getstealthmode']);
    return { backend:'macOS Application Firewall', enabled:/enabled|State = 1/i.test(global), stealth:/enabled|mode is on/i.test(stealth), evidence:global+'\n'+stealth, supported:true };
  }
  const ufw=await findTool('ufw');
  if (ufw) {
    try { return { backend:'UFW', evidence:await run(ufw,['status','verbose']), supported:true }; }
    catch { const config=await fs.readFile('/etc/ufw/ufw.conf','utf8'); const enabled=/^ENABLED=yes$/m.test(config); return {backend:'UFW',configuredEnabled:enabled,runtimeVerified:false,supported:true,evidence:enabled?'UFW configurado como ativado. Regras efetivas exigem privilégios para consulta.':'UFW configurado como desativado.'}; }
  }
  return { backend:'Não detectado', supported:false, evidence:'Instale o UFW para gerenciar o firewall nesta distribuição.' };
}
async function connections() {
  if (process.platform === 'win32') {
    const data=await psJSON("$procs=@{}; Get-Process | ForEach-Object {$procs[$_.Id]=$_.ProcessName}; @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {$_.State -in @('Established','Listen')} | Select-Object -First 350 | ForEach-Object { [pscustomobject]@{protocol='TCP';localAddress=$_.LocalAddress;localPort=$_.LocalPort;remoteAddress=$_.RemoteAddress;remotePort=$_.RemotePort;state=[string]$_.State;pid=$_.OwningProcess;process=$procs[[int]$_.OwningProcess]}}) | ConvertTo-Json -Compress");
    return list(data).map((c,i)=>({...c,id:c.pid+'-'+c.localPort+'-'+c.remoteAddress+'-'+c.remotePort+'-'+i}));
  }
  if (process.platform === 'darwin') {
    let output;
    try { output=await run('/usr/sbin/lsof',['-nP','-iTCP','-FpcnT']); } catch(e) { if(e.code === 1) return []; throw e; }
    return parseLsof(output);
  }
  const ss=await findTool('ss');
  if (!ss) throw new Error('Instale iproute2 para consultar as conexões locais.');
  const output=await run(ss,['-H','-t','-a','-n','-p']);
  return parseSs(output);
}
async function systemInfo() {
  const interfaces=Object.entries(os.networkInterfaces()).flatMap(([name,values])=>(values||[]).filter(v=>!v.internal).map(v=>({name,address:v.address,family:v.family})));
  return { platform:process.platform, release:os.release(), architecture:os.arch(), hostname:os.hostname(), os:process.platform==='win32'?'Windows':process.platform==='darwin'?'macOS':'Linux', memory:os.totalmem(), cpus:os.cpus().length, interfaces };
}
async function extraChecks() {
  if(process.platform==='win32') {
    const result=await psJSON("$out=[ordered]@{}; try {$out.admins=@(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | Select-Object Name,ObjectClass)} catch {$out.adminError=$_.Exception.Message}; try {$out.encryption=@(Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,ProtectionStatus,VolumeStatus)} catch {$out.encryptionError='BitLocker não pôde ser consultado nesta sessão.'}; try {$out.updates=(Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1 | ForEach-Object {[pscustomobject]@{id=$_.HotFixID;date=$_.InstalledOn.ToString('o')}})} catch {$out.updatesError='Histórico de atualizações indisponível.'}; $out | ConvertTo-Json -Depth 5 -Compress",{timeout:35000});
    return result || {};
  }
  if(process.platform==='darwin') {
    const data=await probe(()=>run('/usr/bin/fdesetup',['status']));
    return { encryptionText:data.ok?data.data:null, encryptionError:data.error };
  }
  return { encryptionText:null, encryptionError:'Criptografia não verificada automaticamente nesta distribuição.' };
}
module.exports = { firewallStatus, connections, systemInfo, extraChecks, probe, list };

