'use strict';
const path=require('node:path');
const fs=require('node:fs/promises');
const {randomUUID}=require('node:crypto');
const {firewallStatus}=require('./platform.cjs');
const {run,psQuote,psJSON,elevatedPS,elevate,findTool}=require('./runner.cjs');
const {validatePort,validateRuleId}=require('./validation.cjs');
class Firewall {
  constructor(store,{platform=process.platform,operations=require('./runner.cjs'),status=firewallStatus,io=fs}={}){this.store=store;this.platform=platform;this.ops=operations;this.nativeStatus=status;this.io=io;}
  async status(){return {native:await this.nativeStatus().catch(error=>({supported:false,error:error.message})),rules:this.store.state.rules,canRestore:Boolean(this.store.state.firewallBackup),platform:this.platform};}
  async harden(){
    if(this.store.state.firewallBackup)throw new Error('Há uma configuração anterior salva. Restaure-a antes de aplicar outro reforço.');
    let before;
    if(this.platform==='win32'){
      // Read the LOCAL policy, not effective/GPO settings, so rollback preserves inherited defaults.
      before=await this.ops.psJSON("Get-NetFirewallProfile -PolicyStore PersistentStore | Select-Object Name,Enabled,DefaultInboundAction | ConvertTo-Json -Compress");
      if(!Array.isArray(before)||before.length!==3)throw new Error('Não foi possível salvar os três perfis do firewall.');
      this.store.state.firewallBackup={platform:this.platform,before,at:new Date().toISOString(),pending:true};this.store.save();
      await this.ops.elevatedPS("Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block");
    }else if(this.platform==='darwin'){
      before=await this.nativeStatus();
      this.store.state.firewallBackup={platform:this.platform,before,at:new Date().toISOString(),pending:true};this.store.save();
      await this.ops.elevate('/usr/libexec/ApplicationFirewall/socketfilterfw',['--setglobalstate','on']);
      await this.ops.elevate('/usr/libexec/ApplicationFirewall/socketfilterfw',['--setstealthmode','on']);
    }else{
      const ufw=await this.ops.findTool('ufw');if(!ufw)throw new Error('Instale o UFW nesta distribuição para continuar.');
      const conf=await this.io.readFile('/etc/ufw/ufw.conf','utf8'),defaults=await this.io.readFile('/etc/default/ufw','utf8');
      before={enabled:/^ENABLED=yes$/m.test(conf),policy:defaults.match(/^DEFAULT_INPUT_POLICY="(ACCEPT|DROP|REJECT)"$/m)?.[1]};
      if(!before.policy)throw new Error('Não foi possível salvar a política anterior do UFW.');
      this.store.state.firewallBackup={platform:this.platform,before,at:new Date().toISOString(),pending:true};this.store.save();
      await this.ops.elevate(ufw,['default','deny','incoming']);
      await this.ops.elevate(ufw,['--force','enable']);
    }
    this.store.state.firewallBackup.pending=false;this.store.save();
    this.store.event('firewall','Reforço do firewall aplicado','Configuração anterior salva para restauração.','success');
    return this.status();
  }
  async restore(){
    const backup=this.store.state.firewallBackup;if(!backup||backup.platform!==this.platform)throw new Error('Não há configuração anterior para este sistema.');
    if(this.platform==='win32'){
      const value=(v,kind)=>kind==='bool'?(v===true||v===1?'True':v===false||v===0?'False':'NotConfigured'):({0:'NotConfigured',2:'Allow',4:'Block'}[v]||(['Allow','Block','NotConfigured'].includes(v)?v:'NotConfigured'));
      const scripts=backup.before.map(p=>{
        if(!['Domain','Private','Public'].includes(p.Name))throw new Error('Perfil salvo inválido.');
        return 'Set-NetFirewallProfile -Profile '+p.Name+' -Enabled '+value(p.Enabled,'bool')+' -DefaultInboundAction '+value(p.DefaultInboundAction);
      });
      await this.ops.elevatedPS(scripts.join('; '));
    }else if(this.platform==='darwin'){
      await this.ops.elevate('/usr/libexec/ApplicationFirewall/socketfilterfw',['--setglobalstate',backup.before.enabled?'on':'off']);
      await this.ops.elevate('/usr/libexec/ApplicationFirewall/socketfilterfw',['--setstealthmode',backup.before.stealth?'on':'off']);
    }else{
      const ufw=await this.ops.findTool('ufw');if(!ufw)throw new Error('UFW não encontrado.');
      const policy={ACCEPT:'allow',DROP:'deny',REJECT:'reject'}[backup.before.policy];if(!policy)throw new Error('Política salva inválida.');
      await this.ops.elevate(ufw,['default',policy,'incoming']);
      if(!backup.before.enabled)await this.ops.elevate(ufw,['--force','disable']);
    }
    this.store.state.firewallBackup=null;this.store.save();
    this.store.event('firewall','Configuração do firewall restaurada','Regras de outros aplicativos foram preservadas.','success');
    return this.status();
  }
  async blockPort(input){
    const port=validatePort(input);
    if(this.store.state.rules.some(rule=>rule.port===port))throw new Error('Já existe uma regra Aegis para esta porta.');
    let ufw;
    if(this.platform==='linux'){ufw=await this.ops.findTool('ufw');if(!ufw)throw new Error('UFW não encontrado.');const added=await this.ops.elevate(ufw,['show','added']);if(typeof added!=='string')throw new Error('Não foi possível verificar a propriedade das regras UFW.');if(added.split(/\r?\n/).some(line=>/\b(deny|reject)\b/.test(line.split('comment')[0])&&new RegExp('(?:port\\s+|\\s)'+port+'(?:/tcp|\\s|$)').test(line.split('comment')[0])))throw new Error('Já existe uma regra UFW para esta porta. Ela não será modificada pelo Aegis.');}
    if(this.platform==='darwin')throw new Error('No macOS, o firewall nativo controla aplicações. Use a integração LuLu para regras de saída.');
    const id='Aegis-'+randomUUID();
    // Persist intent before elevation so a partially applied rule can always be removed.
    const rule={id,port,direction:'inbound',protocol:'TCP',at:new Date().toISOString(),pending:true};
    this.store.state.rules.unshift(rule);this.store.save();
    if(this.platform==='win32')await this.ops.elevatedPS("New-NetFirewallRule -Name "+psQuote(id)+" -DisplayName "+psQuote('Aegis · Bloquear TCP '+port)+" -Group 'Aegis' -Direction Inbound -Protocol TCP -LocalPort "+port+" -Action Block -Enabled True | Out-Null");
    else{await this.ops.elevate(ufw,['deny','in','proto','tcp','to','any','port',String(port),'comment',id]);}
    rule.pending=false;this.store.save();this.store.event('firewall','Porta TCP '+port+' bloqueada','Regra de entrada criada pelo Aegis.','success');
    return this.status();
  }
  async removeRule(id){
    validateRuleId(id);const rule=this.store.state.rules.find(r=>r.id===id);if(!rule)throw new Error('Regra não encontrada.');
    if(this.platform==='win32')await this.ops.elevatedPS("Get-NetFirewallRule -Name "+psQuote(id)+" -ErrorAction SilentlyContinue | Where-Object {$_.Group -eq 'Aegis'} | Remove-NetFirewallRule");
    else if(this.platform==='linux'){const ufw=await this.ops.findTool('ufw');if(!ufw)throw new Error('UFW não encontrado.');const added=await this.ops.elevate(ufw,['show','added']);if(typeof added!=='string')throw new Error('Não foi possível verificar as regras UFW.');if(!added.includes(id))throw new Error('O UFW não confirmou a propriedade desta regra. Nenhuma regra externa foi removida.');await this.ops.elevate(ufw,['--force','delete','deny','in','proto','tcp','to','any','port',String(validatePort(rule.port)),'comment',id]);}
    this.store.state.rules=this.store.state.rules.filter(r=>r.id!==id);this.store.save();this.store.event('firewall','Regra removida','TCP '+rule.port,'success');return this.status();
  }
}
module.exports={Firewall};

