const fs=require('node:fs/promises'),path=require('node:path'),{spawn,execFileSync}=require('node:child_process');
const en=require('../locales/en.json');
(async()=>{
 if(process.platform!=='win32'||process.env.CI!=='true')throw Error('Run the native Windows smoke test only on an isolated CI runner.');
 const root=path.resolve(__dirname,'..'),payload=JSON.parse(await fs.readFile(path.join(root,'.build/installed-payload.json'),'utf8'));
 await fs.writeFile(path.join(root,'.build/uia-labels.json'),JSON.stringify({antivirus:en['Antivírus'],overview:en['Visão geral'],verify:en['Verificar sistema'],completed:en['Verificação concluída']}));
 const child=spawn(payload.executable,[],{cwd:path.dirname(payload.executable),windowsHide:true,stdio:'ignore',env:{...process.env,WEBVIEW2_USER_DATA_FOLDER:path.join(root,'.build/webview-test')}});
 try{
  execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-File',path.join(root,'scripts/test-native-uia.ps1'),'-AppProcessId',String(child.pid)],{windowsHide:true,stdio:'inherit',timeout:240000});
 }finally{
  if(Number.isSafeInteger(child.pid))try{execFileSync(path.join(process.env.SystemRoot||'C:\\Windows','System32/taskkill.exe'),['/PID',String(child.pid),'/T','/F'],{windowsHide:true,stdio:'ignore'});}catch{}
 }
})().catch(e=>{console.error(e);process.exitCode=1});
