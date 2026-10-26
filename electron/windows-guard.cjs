'use strict';
const {psJSON}=require('./runner.cjs');
// Read-only queries. Each source retains an independent unknown state on access failure.
const SCRIPT=String.raw`
$out=[ordered]@{sac=$null;guard=$null};
try {$out.sac=(Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Name VerifiedAndReputablePolicyState -ErrorAction Stop).VerifiedAndReputablePolicyState} catch {$out.sacError='Estado do Smart App Control indisponível nesta sessão.'};
try {$out.guard=Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -ErrorAction Stop | Select-Object VirtualizationBasedSecurityStatus,SecurityServicesRunning,UsermodeCodeIntegrityPolicyEnforcementStatus} catch {$out.guardError='Consulta Win32_DeviceGuard indisponível nesta sessão.'};
$out | ConvertTo-Json -Depth 4 -Compress
`;
const sacNames={0:'desativado',1:'ativado (imposição)',2:'avaliação'};
const ciNames={0:'desativado',1:'auditoria',2:'imposição'};
const vbsNames={0:'desativada',1:'configurada, sem execução',2:'em execução'};
const known=(value,map)=>typeof value==='number'&&Object.hasOwn(map,value);
function guardChecks(data={}){
 const guard=data.guard||{},sacKnown=known(data.sac,sacNames),ci=guard.UsermodeCodeIntegrityPolicyEnforcementStatus,ciKnown=known(ci,ciNames);
 const appEvidence=[sacKnown?'Smart App Control: '+sacNames[data.sac]+'.':data.sacError||'Smart App Control: não verificado.',ciKnown?'Integridade de código de aplicativos: '+ciNames[ci]+'.':data.guardError||'Política de aplicativos: não verificada.'].join(' ');
 const enforced=(sacKnown&&data.sac===1)||(ciKnown&&ci===2);
 const vbs=guard.VirtualizationBasedSecurityStatus,vbsKnown=known(vbs,vbsNames);
 const running=guard.SecurityServicesRunning,servicesKnown=Array.isArray(running)&&running.every(v=>Number.isInteger(v)&&v>=0);
 return [
  {id:'app-control',title:'Controle de aplicativos do Windows',status:enforced?'pass':sacKnown&&ciKnown?'review':'unknown',evidence:appEvidence,recommendation:enforced?'Aplicativos sem confiança ou assinatura podem ser bloqueados. Consulte os eventos CodeIntegrity para identificar o motivo de uma falha de execução.':'Revise o controle de aplicativos na Segurança do Windows e as políticas da organização.'},
  {id:'vbs',title:'Segurança baseada em virtualização',status:vbsKnown?(vbs===2?'pass':'review'):'unknown',evidence:vbsKnown?'VBS: '+vbsNames[vbs]+'.':data.guardError||'Estado da VBS não verificado.',recommendation:'Consulte Segurança do Windows > Segurança do dispositivo para conferir os recursos disponíveis neste hardware.'},
  {id:'memory-integrity',title:'Integridade da memória',status:servicesKnown?(running.includes(2)?'pass':'review'):'unknown',evidence:servicesKnown?(running.includes(2)?'HVCI em execução, informado por Win32_DeviceGuard.':'HVCI não consta entre os serviços em execução.'):data.guardError||'Serviços de segurança em execução não verificados.',recommendation:'Confira Isolamento do núcleo na Segurança do Windows. Compatibilidade de drivers deve ser validada antes de alterar esta proteção.'}
 ];
}
async function windowsGuardChecks({platform=process.platform,query=psJSON}={}){
 if(platform!=='win32')return [];
 try{return guardChecks(await query(SCRIPT,{timeout:15000})||{});}catch{return guardChecks({sacError:'Consulta de controle de aplicativos indisponível.',guardError:'Consulta Win32_DeviceGuard indisponível.'});}
}
module.exports={windowsGuardChecks,guardChecks};
