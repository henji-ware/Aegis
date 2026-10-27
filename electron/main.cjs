'use strict';
const {nativeTheme,app,BrowserWindow,ipcMain,protocol,net,session,dialog,shell,safeStorage,Menu}=require('electron');
const fs=require('node:fs/promises');
const path=require('node:path');
const {pathToFileURL}=require('node:url');
const {Store}=require('./store.cjs');
const {Antivirus}=require('./antivirus.cjs');
const {Privacy}=require('./privacy.cjs');
const {Firewall}=require('./firewall.cjs');
const {audit}=require('./audit.cjs');
const {systemInfo,connections,probe}=require('./platform.cjs');
const {publicError}=require('./validation.cjs');
const {translate,validateSettings}=require('./localization.cjs');
const {renderReport}=require('./report.cjs');
const tx=(source,values={})=>translate(source,store?.state.settings.language||'system',values,app.getLocale());
protocol.registerSchemesAsPrivileged([{scheme:'aegis',privileges:{standard:true,secure:true,supportFetchAPI:true}}]);
app.setName('Aegis');
if(process.env.AEGIS_DATA_DIR) app.setPath('userData',path.resolve(process.env.AEGIS_DATA_DIR));
let win,store,av,privacy,firewall,auditing=false,mutation=false;
const resources=app.isPackaged?process.resourcesPath:path.join(__dirname,'..','resources');
const dev=!app.isPackaged&&process.env.AEGIS_DEV==='1';
const emit=(type,data)=>{if(win&&!win.isDestroyed())win.webContents.send('aegis:event',{type,data});};
const external={
  clamav:'https://www.clamav.net/',clamavDocs:'https://docs.clamav.net/manual/Usage/Scanning.html',
  tor:'https://www.torproject.org/download/',torDocs:'https://support.torproject.org/about-tor/using-and-sharing/torifying/',
  wireguard:'https://www.wireguard.com/install/',portmaster:'https://safing.io/portmaster/',
  lulu:'https://objective-see.org/products/lulu.html',sourceClam:'https://github.com/Cisco-Talos/clamav',
  sourceTor:'https://gitlab.torproject.org/tpo/core/tor',sourceWireguard:'https://git.zx2c4.com/wireguard-windows/',
};
async function confirm(title,message,detail){
  title=tx(title);message=tx(message);detail=tx(detail);
  const result=await dialog.showMessageBox(win,{type:'question',title,message,detail,buttons:[tx('Cancelar'),tx('Continuar')],defaultId:0,cancelId:0,noLink:true});
  if(result.response!==1)throw new Error('Operação cancelada.');
}
async function mutate(fn){
  if(mutation)throw new Error('Aguarde a operação atual terminar.');
  mutation=true;try{return await fn();}finally{mutation=false;}
}
async function exportReport(){
  const result=await dialog.showSaveDialog(win,{title:tx("Exportar relatório local"),defaultPath:'Aegis-report-'+new Date().toISOString().slice(0,10)+'.html',filters:[{name:tx("Relatório HTML"),extensions:['html']}]});
  if(result.canceled)return null;
  const html=renderReport(store.state,{system:app.getLocale()});
  await fs.writeFile(result.filePath,html,'utf8');store.event('report','Relatório exportado','Arquivo HTML salvo no local escolhido.','success');return result.filePath;
}
async function createWindow(){
  win=new BrowserWindow({width:1440,height:960,minWidth:1080,minHeight:760,show:false,backgroundColor:'#07100d',title:'Aegis',autoHideMenuBar:true,icon:path.join(__dirname,'..','assets','icon.png'),webPreferences:{preload:path.join(__dirname,'preload.cjs'),nodeIntegration:false,contextIsolation:true,sandbox:true,webSecurity:true,webviewTag:false}});
  win.webContents.setWindowOpenHandler(()=>({action:'deny'}));
  win.webContents.on('will-navigate',(event,url)=>{if(!url.startsWith('aegis://app/')&&!(dev&&new URL(url).origin==='http://127.0.0.1:5173'))event.preventDefault();});
  win.once('ready-to-show',()=>win.show());
  if(dev)await win.loadURL('http://127.0.0.1:5173');else await win.loadURL('aegis://app/index.html');
}
if(app.requestSingleInstanceLock()){
app.on('second-instance',()=>{if(win){if(win.isMinimized())win.restore();win.show();win.focus();}});
app.whenReady().then(async()=>{
  Menu.setApplicationMenu(null);nativeTheme.themeSource='dark';
  const dist=path.resolve(__dirname,'..','dist');
  protocol.handle('aegis',async request=>{
    const url=new URL(request.url);
    if(url.host!=='app')return new Response('Forbidden',{status:403});
    let pathname;try{pathname=decodeURIComponent(url.pathname);}catch{return new Response('Invalid path',{status:400});}
    const target=path.resolve(dist,'.'+pathname);
    if(!target.startsWith(dist+path.sep)||pathname.includes('\0'))return new Response('Forbidden',{status:403});
    return net.fetch(pathToFileURL(target).toString());
  });
  session.defaultSession.setPermissionRequestHandler((_wc,_permission,callback)=>callback(false));
  session.defaultSession.setPermissionCheckHandler(()=>false);
  session.defaultSession.webRequest.onHeadersReceived((details,callback)=>{
    callback({responseHeaders:{...details.responseHeaders,'Content-Security-Policy':[dev?"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:5173 http://127.0.0.1:5173; object-src 'none'; base-uri 'none'":"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-src 'none'"]}});
  });
  store=new Store(app.getPath('userData'));av=new Antivirus({store,resources,emit,quickTargets:[app.getPath('downloads'),app.getPath('desktop')]});privacy=new Privacy({store,safeStorage,resources,emit});firewall=new Firewall(store);
  // Interrupted jobs are never restored as successful.
  if(store.state.activeScan){const interrupted={...store.state.activeScan,state:'interrupted',endedAt:new Date().toISOString(),error:'A tarefa foi interrompida antes de confirmar o resultado.'};store.state.scans.unshift(interrupted);store.state.activeScan=null;store.save();}
  for(const scan of store.state.scans)if(['running','cancelling'].includes(scan.state))scan.state='interrupted';
  const handlers={
    bootstrap:async()=>({system:await systemInfo(),settings:store.state.settings,history:store.state.history.slice(0,50),latestAudit:store.state.audits[0]||null,version:app.getVersion(),recoveryMessage:store.recoveryMessage||null}),
    audit:async()=>{if(auditing)throw new Error('Diagnóstico em andamento.');auditing=true;emit('audit',{state:'running'});try{const result=await audit(av);store.audit(result);store.event('audit','Diagnóstico concluído',result.counts.pass+' verificações atendidas; '+result.counts.unknown+' não verificadas.','success');emit('audit',{state:'completed',result});return result;}catch(error){emit('audit',{state:'error',error:publicError(error)});throw error;}finally{auditing=false;}},
    connections:()=>connections(),
    'av:status':()=>av.status(),
    'av:update':()=>av.startUpdate(),
    'av:scan':async payload=>{
      let selected;
      if(payload?.type==='custom'){const result=await dialog.showOpenDialog(win,{title:tx("Escolha o que deseja verificar"),properties:['openFile','openDirectory','dontAddToRecent']});if(result.canceled)return null;selected=result.filePaths[0];}
      return av.startScan(payload?.type,selected);
    },
    'av:cancel':()=>av.cancel(),
    'firewall:status':()=>firewall.status(),
    'firewall:harden':()=>mutate(async()=>{await confirm('Reforçar firewall','Ativar o firewall e restringir novas conexões de entrada?',process.platform==='win32'?'Ativa os perfis Domínio, Privado e Público e define o padrão de entrada como Bloquear. As regras existentes continuam válidas. A configuração local anterior será salva para restauração.':process.platform==='darwin'?'Ativa o firewall de aplicações e o modo discreto. A configuração anterior será salva.':'Define o padrão de entrada do UFW como Negar e ativa o firewall. Isso pode interromper acesso remoto e serviços. As regras existentes permanecem.');return firewall.harden();}),
    'firewall:restore':()=>mutate(async()=>{await confirm('Restaurar firewall','Restaurar a configuração anterior ao reforço?','As opções modificadas pelo reforço voltarão aos valores salvos. Regras de outros aplicativos serão preservadas.');return firewall.restore();}),
    'firewall:block':payload=>mutate(async()=>{const {validatePort}=require('./validation.cjs');const port=validatePort(payload?.port);await confirm('Bloquear porta',tx('Bloquear novas conexões TCP de entrada na porta {port}?',{port}),'A regra será identificada como Aegis e poderá ser removida pelo aplicativo.');return firewall.blockPort(port);}),
    'firewall:remove':payload=>mutate(async()=>{await confirm('Remover regra','Remover esta regra de bloqueio do Aegis?','Conexões antes bloqueadas por esta regra poderão ser permitidas por outras políticas.');return firewall.removeRule(payload?.id);}),
    'vpn:status':()=>privacy.vpnStatus(),
    'vpn:import':async()=>{const result=await dialog.showOpenDialog(win,{title:tx("Importar perfil WireGuard"),properties:['openFile','dontAddToRecent'],filters:[{name:'WireGuard',extensions:['conf']}]});if(result.canceled)return null;return privacy.importProfile(result.filePaths[0]);},
    'vpn:connect':payload=>mutate(async()=>{await confirm('Conectar VPN','Ativar este perfil WireGuard?','O perfil pode alterar rotas e servidores DNS. Use somente configurações de um servidor em que você confia. Uma interface ativa, por si só, não confirma ausência de vazamentos. O túnel permanece ativo ao fechar o Aegis; desconecte-o aqui antes de sair se necessário.');return privacy.connect(payload?.id);}),
    'vpn:disconnect':()=>mutate(async()=>{await confirm('Desconectar VPN','Desconectar o túnel gerenciado pelo Aegis?','As conexões voltarão a seguir as rotas do sistema.');return privacy.disconnect();}),
    'vpn:remove':async payload=>{await confirm('Remover perfil','Remover este perfil VPN do cofre local?','A configuração importada originalmente não será alterada.');return privacy.removeProfile(payload?.id);},
    'tor:status':()=>privacy.torStatus(),
    'tor:start':()=>privacy.startTor(),
    'tor:stop':()=>privacy.stopTor(),
    history:async()=>({events:store.state.history,audits:store.state.audits,scans:store.state.scans}),
    settings:async payload=>{validateSettings(payload);Object.assign(store.state.settings,payload);store.save();return store.state.settings;},
    export:exportReport,
    external:async payload=>{const url=external[payload?.id];if(!url)throw new Error('Destino inválido.');await shell.openExternal(url);return true;},
  };
  ipcMain.handle('aegis:call',async(event,method,payload)=>{
    try{
      const frameUrl=event.senderFrame?.url||'';
      if(event.sender!==win?.webContents||!((frameUrl.startsWith('aegis://app/'))||(dev&&new URL(frameUrl).origin==='http://127.0.0.1:5173')))throw new Error('Origem não autorizada.');
      if(typeof method!=='string'||!Object.hasOwn(handlers,method)||JSON.stringify(payload??null).length>10000)throw new Error('Operação não permitida.');
      return {ok:true,data:await handlers[method](payload)};
    }catch(error){return {ok:false,error:publicError(error)};}
  });
  await createWindow();
  app.on('activate',()=>{if(BrowserWindow.getAllWindows().length===0)createWindow();});
}).catch(error=>{dialog.showErrorBox('Aegis',publicError(error));app.quit();});
}else app.quit();
app.on('window-all-closed',()=>{if(process.platform!=='darwin')app.quit();});
app.on('before-quit',event=>{
  if(av?.child&&!app._confirmedQuit){
    event.preventDefault();
    dialog.showMessageBox(win,{type:'question',message:tx("Há uma tarefa do antivírus em andamento."),detail:tx("Sair interrompe a tarefa. O resultado não será considerado uma varredura concluída."),buttons:[tx("Continuar no Aegis"),tx("Interromper e sair")],defaultId:0,cancelId:0}).then(({response})=>{if(response===1){app._confirmedQuit=true;av.cancel();privacy?.stopTor();setTimeout(()=>app.quit(),700);}});return;
  }
  privacy?.stopTor();
});

