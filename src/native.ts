import {invoke,isTauri} from '@tauri-apps/api/core';
import {listen} from '@tauri-apps/api/event';
import type {AegisAPI} from './types';
export async function installNative(){
 if(!isTauri())return;
 const subscribers=new Set<Parameters<AegisAPI['onEvent']>[0]>();
 await listen<{type:string;data:unknown}>('aegis:event',event=>{for(const callback of subscribers)callback(event.payload);});
 window.aegis={
  call:async<T>(method:string,payload?:unknown):Promise<T>=>{try{return await invoke<T>('aegis_call',{method,payload:payload??null});}catch(value){const data=value as {code?:string;original?:string};const error=new Error(data.code==='cancelled'?'Operação cancelada.':(data.code==='operation-failed'?data.original:data.code)||String(value)) as Error&{original?:string};error.original=data.original;throw error;}},
  onEvent:callback=>{subscribers.add(callback);return()=>{subscribers.delete(callback);};}
 };
}
