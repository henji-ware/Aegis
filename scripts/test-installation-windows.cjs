const fs=require('node:fs/promises'),path=require('node:path'),{spawnSync,execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),build=path.join(root,'.build');
async function find(dir,predicate){for(const e of await fs.readdir(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(e.isFile()&&predicate(e.name))return file;if(e.isDirectory()){const found=await find(file,predicate);if(found)return found;}}return null;}
const exists=file=>fs.access(file).then(()=>true,()=>false);
function insideBuild(file){const resolved=path.resolve(file),relative=path.relative(build,resolved);if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw Error('Test installation path must be inside .build');return resolved;}
function run(file,args,timeout=180000){const result=spawnSync(file,args,{windowsHide:true,stdio:'inherit',timeout});if(result.error)throw result.error;if(![0,3010].includes(result.status))throw Error(path.basename(file)+' failed with '+result.status);}
async function removed(file){for(let i=0;i<120;i++){if(!await exists(file))return;await new Promise(resolve=>setTimeout(resolve,500));}throw Error('Uninstall did not remove '+file);}
(async()=>{
 if(process.platform!=='win32'||process.env.CI!=='true')throw Error('Installation tests are restricted to isolated Windows CI runners.');
 await fs.mkdir(build,{recursive:true});
 const bundle=path.join(root,'src-tauri/target/release/bundle'),msiexec=path.join(process.env.SystemRoot||'C:\\Windows','System32/msiexec.exe');
 const setup=await find(bundle,name=>name.endsWith('-setup.exe')),msi=await find(bundle,name=>name.endsWith('.msi'));
 if(!setup||!msi)throw Error('Both Windows installers are required.');
 for(const kind of ['nsis','msi']){
  const destination=insideBuild(path.join(build,kind+'-installed-'+Date.now())),executable=path.join(destination,'aegis-desktop.exe');
  if(await exists(destination))throw Error('Refusing to overwrite an existing test installation.');
  let installed=false;
  try{
   if(kind==='nsis')run(setup,['/S','/D='+destination]);
   else run(msiexec,['/i',msi,'/qn','/norestart','INSTALLDIR='+destination,'/L*v',path.join(build,'msi-install.log')]);
   installed=true;
   if(!await exists(executable))throw Error(kind+' did not install the application at the requested directory.');
   execFileSync(process.execPath,[path.join(root,'scripts/check-runtimes.cjs')],{windowsHide:true,stdio:'inherit',timeout:60000,env:{...process.env,AEGIS_CHECK_RESOURCES:path.join(destination,'engines')}});
   execFileSync(process.execPath,[path.join(root,'scripts/test-native-windows.cjs'),executable],{windowsHide:true,stdio:'inherit',timeout:300000});
  }finally{
   if(installed){
    if(kind==='msi')run(msiexec,['/x',msi,'/qn','/norestart','/L*v',path.join(build,'msi-uninstall.log')]);
    else{const uninstall=await find(destination,name=>/^uninstall.*\.exe$/i.test(name));if(!uninstall)throw Error('NSIS uninstaller missing.');run(uninstall,['/S']);}
    await removed(executable);
    await removed(path.join(destination,'engines'));
   }
  }
  console.log('PASS: '+kind.toUpperCase()+' installed, actual native UI/engines checked, then application and engine files uninstalled.');
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
