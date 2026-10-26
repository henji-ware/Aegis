'use strict';
const net = require('node:net');
function validateProfile(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 65536) throw new Error('O perfil deve ter no máximo 64 KB.');
  const allowed = {
    Interface: new Set(['PrivateKey','Address','DNS','ListenPort','MTU']),
    Peer: new Set(['PublicKey','PresharedKey','AllowedIPs','Endpoint','PersistentKeepalive'])
  };
  let section = '', peers = 0, interfaces = 0, peerHasKey = false, privateKey = false, publicKey = false;
  let keys = new Set();
  const result = [], meta = { endpoint: '', addresses: [], fullTunnel: false, dns: [], ipv6: false };
  for (const raw of text.replace(/^\uFEFF/, '').split(/\r?\n/)) {
    const line = raw.replace(/\s*#.*$/, '').trim();
    if (!line) continue;
    if (line === '[Interface]' || line === '[Peer]') {
      if (section === 'Peer' && !peerHasKey) throw new Error('Peer sem chave pública.');
      section = line.slice(1,-1); keys = new Set();
      if (section === 'Interface' && ++interfaces !== 1) throw new Error('Use apenas uma seção Interface.');
      if (section === 'Peer') { if (!interfaces || ++peers > 16) throw new Error('Número ou ordem de peers inválido.'); peerHasKey = false; }
      result.push(line); continue;
    }
    const match = line.match(/^([A-Za-z]+)\s*=\s*(.+)$/);
    if (!match || !allowed[section]?.has(match[1])) throw new Error('Diretiva não permitida no perfil: ' + (match?.[1] || line.slice(0,30)) + '. Scripts e comandos não são aceitos.');
    const [, key, value] = match;
    if (keys.has(key)) throw new Error('Diretiva duplicada: ' + key); keys.add(key);
    if (/[\0\r\n]/.test(value)) throw new Error('Conteúdo inválido no perfil.');
    if (['PrivateKey','PublicKey','PresharedKey'].includes(key) && !/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new Error('Chave WireGuard inválida.');
    if (key === 'PrivateKey') privateKey = true;
    if (key === 'PublicKey') { publicKey = true; peerHasKey = true; }
    if (['Address','AllowedIPs'].includes(key)) {
      const addresses = value.split(',').map(s => s.trim());
      for (const cidr of addresses) {
        const [ip, bits, extra] = cidr.split('/');
        const version = net.isIP(ip);
        if (!version || extra || !/^\d+$/.test(bits || '') || Number(bits) > (version === 4 ? 32 : 128)) throw new Error('Endereço ou rota CIDR inválido.');
      }
      if (key === 'Address') meta.addresses.push(...addresses);
      if (key === 'AllowedIPs') { meta.fullTunnel ||= addresses.includes('0.0.0.0/0'); meta.ipv6 ||= addresses.includes('::/0'); }
    }
    if (key === 'DNS') {
      meta.dns = value.split(',').map(s => s.trim());
      if (meta.dns.some(s => !net.isIP(s))) throw new Error('Use endereços IP como servidores DNS.');
    }
    if (key === 'Endpoint') {
      if (!/^(\[[0-9a-fA-F:]+\]|[a-zA-Z0-9][a-zA-Z0-9.-]*):[0-9]{1,5}$/.test(value)) throw new Error('Endpoint inválido.');
      const port = Number(value.slice(value.lastIndexOf(':') + 1));
      if (port < 1 || port > 65535) throw new Error('Porta do endpoint inválida.');
      meta.endpoint = value;
    }
    if (['ListenPort','MTU','PersistentKeepalive'].includes(key) && (!/^\d+$/.test(value) || Number(value) > 65535)) throw new Error('Valor numérico inválido.');
    result.push(key + ' = ' + value);
  }
  if (!privateKey || !publicKey || !peers || !peerHasKey || !meta.addresses.length) throw new Error('Perfil WireGuard incompleto.');
  return { text: result.join('\n') + '\n', meta };
}
function validatePort(value) {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Escolha uma porta entre 1 e 65535.');
  return port;
}
function validateRuleId(id) { if (typeof id !== 'string' || !/^Aegis-[a-f0-9-]{36}$/.test(id)) throw new Error('Regra inválida.'); return id; }
function parseClamSummary(output, code) {
  const get = label => { const m = output.match(new RegExp('^' + label + ':\\s*(\\d+)', 'mi')); return m ? Number(m[1]) : null; };
  const threats = output.split(/\r?\n/).map(s => s.match(/^(.+): (.+) FOUND$/)).filter(Boolean).map(m => ({ path:m[1], name:m[2] }));
  const scanned = get('Scanned files'), infected = get('Infected files');
  const errors = get('Total errors') || 0;
  const limited = /Heuristics\.Limits\.Exceeded|size limit reached|Scanning limit reached/i.test(output);
  const found=(infected||0)>0||threats.length>0;
  const state = found ? 'threats' : code === 0 && scanned !== null && errors === 0 && !limited ? 'completed' : 'error';
  return { state, scanned, infected:infected ?? threats.length, errors, limited, threats };
}
function publicError(error) {
  let raw=String(error?.message||error||'Falha inesperada.');
  if(raw.includes('#< CLIXML')||raw.includes('#<CLIXML')){
    const matches=[...raw.matchAll(/<S S="Error">([\s\S]*?)<\/S>/g)].map(m=>m[1]);
    raw=matches.length?matches.join(' '):'A consulta ao sistema não retornou um resultado legível.';
    raw=raw.replace(/_x([0-9A-Fa-f]{4})_/g,(_m,h)=>String.fromCharCode(parseInt(h,16))).replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&amp;/g,'&');
  }
  const message=raw.replace(/([A-Za-z0-9+/]{43}=)/g,'[chave omitida]');
  if (/access.*denied|acesso.*negado|UnauthorizedAccess|privilege/i.test(message)) return 'O sistema negou a consulta. Execute com a permissão necessária ou verifique a política do dispositivo.';
  return message.slice(0,1000);
}
module.exports = { validateProfile, validatePort, validateRuleId, parseClamSummary, publicError };

