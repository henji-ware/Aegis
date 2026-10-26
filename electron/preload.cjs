'use strict';
const {contextBridge,ipcRenderer}=require('electron');
const allowed=new Set(['bootstrap','audit','connections','av:status','av:update','av:scan','av:cancel','firewall:status','firewall:harden','firewall:restore','firewall:block','firewall:remove','vpn:status','vpn:import','vpn:connect','vpn:disconnect','vpn:remove','tor:status','tor:start','tor:stop','history','settings','export','external']);
contextBridge.exposeInMainWorld('aegis',{
  call:async(method,payload)=>{if(!allowed.has(method))throw new Error('Operação não permitida.');const result=await ipcRenderer.invoke('aegis:call',method,payload);if(!result.ok)throw new Error(result.error);return result.data;},
  onEvent:callback=>{const listener=(_event,value)=>callback(value);ipcRenderer.on('aegis:event',listener);return()=>ipcRenderer.removeListener('aegis:event',listener);}
});

