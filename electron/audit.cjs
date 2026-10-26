'use strict';
const {randomUUID}=require('node:crypto');
const {windowsGuardChecks}=require('./windows-guard.cjs');
const {systemInfo,firewallStatus,connections,extraChecks,probe,list}=require('./platform.cjs');
function firewallCheck(result) {
  if(!result.ok) return {id:'firewall',title:'Firewall do sistema',status:'unknown',evidence:result.error,recommendation:'Verifique as permissões de consulta do firewall.'};
  const fw=result.data;
  let enabled=null;
  if(fw.profiles) enabled=fw.profiles.length>0&&fw.profiles.every(p=>p.Enabled===true||p.Enabled===1);
  else if(typeof fw.enabled==='boolean') enabled=fw.enabled;
  else if(fw.backend==='UFW'&&fw.runtimeVerified!==false) enabled=/Status:\s*active/i.test(fw.evidence);
  return {id:'firewall',title:'Firewall do sistema',status:enabled===null?'unknown':enabled?'pass':'warning',evidence:fw.profiles?fw.profiles.map(p=>p.Name+': '+((p.Enabled===true||p.Enabled===1)?'ativado':'desativado')).join(' · '):fw.evidence,recommendation:enabled?'Revise as permissões dos serviços que recebem conexões.':'Ative o firewall e revise as regras de entrada.',action:'firewall'};
}
async function audit(antivirus) {
  const [system,firewall,network,extras,av,guard]=await Promise.all([systemInfo(),probe(firewallStatus),probe(connections),probe(extraChecks),probe(()=>antivirus.status()),windowsGuardChecks()]);
  const checks=[firewallCheck(firewall),...guard];
  const ready=av.ok&&av.data.installed&&av.data.signatures.ready;
  checks.push({id:'antivirus',title:'Mecanismo de varredura',status:ready?'pass':'warning',evidence:ready?av.data.version:av.ok?(av.data.installed?'ClamAV instalado. Base de assinaturas ainda não preparada.':'ClamAV não encontrado.'):av.error,recommendation:ready?'Mantenha as assinaturas atualizadas e execute varreduras periódicas.':'Prepare o mecanismo e atualize as assinaturas na área Antivírus.',action:'antivirus'});
  const last=av.ok?av.data.signatures.updatedAt:null,age=last?(Date.now()-new Date(last).getTime())/86400000:null;
  checks.push({id:'signatures',title:'Atualização local das assinaturas',status:age===null?'unknown':age<=2?'pass':'warning',evidence:last?'Última gravação da base local: '+last:'Sem base local disponível.',recommendation:'Atualize com FreshClam. O horário local não substitui a validação da versão das assinaturas.',action:'antivirus'});
  const listeners=network.ok?network.data.filter(c=>c.state==='Listen'&&!['127.0.0.1','::1'].includes(c.localAddress)):[];
  checks.push({id:'listeners',title:'Serviços em escuta na rede',status:network.ok?(listeners.length?'review':'pass'):'unknown',evidence:network.ok?listeners.length+' sockets TCP em endereços que não são loopback. Isso não prova acesso externo.':network.error,recommendation:'Confirme se cada serviço é necessário e se o firewall permite apenas o acesso esperado.',action:'network'});
  if(process.platform==='win32') {
    const data=extras.ok?extras.data:{};
    const admins=list(data.admins);
    checks.push({id:'admins',title:'Contas administrativas',status:data.adminError||!extras.ok?'unknown':admins.length>2?'review':'pass',evidence:data.adminError||extras.error||admins.map(a=>a.Name).join(' · ')||'Nenhuma conta retornada.',recommendation:'Mantenha privilégios administrativos apenas nas contas que precisam deles.'});
    const encrypted=list(data.encryption);
    checks.push({id:'encryption',title:'Criptografia dos volumes',status:data.encryptionError||!encrypted.length?'unknown':encrypted.every(v=>v.ProtectionStatus===1||v.ProtectionStatus==='On')?'pass':'review',evidence:data.encryptionError||encrypted.map(v=>v.MountPoint+': '+v.ProtectionStatus).join(' · '),recommendation:'Confira a criptografia do disco e guarde a chave de recuperação em um local seguro.'});
    checks.push({id:'updates',title:'Último hotfix registrado',status:data.updates?'review':'unknown',evidence:data.updates?data.updates.id+' · '+data.updates.date:data.updatesError||'Não foi possível consultar.',recommendation:'Confira o Windows Update. A data de um hotfix não determina se o sistema está totalmente atualizado.'});
  } else {
    const data=extras.ok?extras.data:{};
    checks.push({id:'encryption',title:'Criptografia do disco',status:data.encryptionText?/FileVault is On/i.test(data.encryptionText)?'pass':'review':'unknown',evidence:data.encryptionText||data.encryptionError||extras.error,recommendation:'Confira a criptografia nas configurações do sistema.'});
  }
  // Coverage is kept separate from findings; unknown checks never count as secure.
  const counts={pass:0,warning:0,review:0,unknown:0};
  for(const check of checks) counts[check.status]++;
  return {id:randomUUID(),at:new Date().toISOString(),system,checks,counts,firewall,network:network.ok?{ok:true,count:network.data.length}:network};
}
module.exports={audit,firewallCheck};

