import type {Connection} from './types';

export function socketAddress(address:string,port:number){return `${address.includes(':')&&!address.startsWith('[')?`[${address}]`:address}:${port}`;}
export function endpoint(row:Connection){return row.state==='Listen'?socketAddress(row.localAddress,row.localPort):socketAddress(row.remoteAddress,row.remotePort);}
export function applicationCount(rows:Connection[]){return new Set(rows.map(row=>row.process.trim()).filter(Boolean)).size;}
export function matchesConnection(row:Connection,query:string){const needle=query.trim().toLocaleLowerCase();return [row.process,`PID ${row.pid}`,row.localAddress,row.remoteAddress,String(row.localPort),String(row.remotePort),socketAddress(row.localAddress,row.localPort),socketAddress(row.remoteAddress,row.remotePort)].some(value=>value.toLocaleLowerCase().includes(needle));}
export function stateMessage(row:Connection){return row.state==='Listen'?'Em escuta':row.state==='Established'?'Estabelecida':'Não verificado';}
export function evidenceLevel(row:Connection):'review'|'no-signals'|'unknown'{const analysis=row.analysis;if(!analysis)return 'unknown';if(analysis.signals.length||analysis.level==='review')return 'review';return analysis.level==='no-signals'&&analysis.inspected&&!!analysis.path?.trim()?'no-signals':'unknown';}
