export async function call<T>(method:string,payload?:unknown):Promise<T>{
  if(!window.aegis)throw new Error('Abra o aplicativo desktop para acessar os recursos do sistema.');
  return window.aegis.call<T>(method,payload);
}
export const date=(value?:string|null)=>value?new Date(value).toLocaleString('pt-BR',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):'Ainda não verificado';
export const fullDate=(value?:string|null)=>value?new Date(value).toLocaleString('pt-BR'):'—';
export const jobLabel=(state?:string)=>({running:'Em andamento',cancelling:'Interrompendo',completed:'Concluída',cancelled:'Interrompida',threats:'Detecções encontradas',error:'Incompleta ou com erro',interrupted:'Interrompida'}[state||'']||'Aguardando');

