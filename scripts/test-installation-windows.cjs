const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync,execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),build=path.join(root,'.build');
async function find(dir,predicate){for(const e of await fs.readdir(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(e.isFile()&&predicate(e.name))return file;if(e.isDirectory()){const found=await find(file,predicate);if(found)return found;}}return null;}
const exists=file=>fs.access(file).then(()=>true,()=>false);
function insideBuild(file){const resolved=path.resolve(file),relative=path.relative(build,resolved);if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw Error('Test installation path must be inside .build');return resolved;}
function run(file,args,timeout=180000){const result=spawnSync(file,args,{windowsHide:true,stdio:'inherit',timeout});if(result.error)throw result.error;if(![0,3010].includes(result.status))throw Error(path.basename(file)+' failed with '+result.status);}
async function removed(file){for(let i=0;i<120;i++){if(!await exists(file))return;await new Promise(resolve=>setTimeout(resolve,500));}throw Error('Uninstall did not remove '+file);}
const samePath=(a,b)=>path.resolve(a).toLowerCase()===path.resolve(b).toLowerCase();
async function canonicalInsideBuild(file){const resolved=await fs.realpath(file),base=await fs.realpath(build),relative=path.relative(base,resolved);if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw Error('Registered installation escaped the canonical .build directory.');return resolved;}
async function hash(file){return crypto.createHash('sha256').update(await fs.readFile(file)).digest('hex');}
async function baseline(executable){const canonical=await canonicalInsideBuild(executable);return {executable:canonical,sha256:await hash(canonical),bytes:(await fs.stat(canonical)).size};}
async function nsisBaseline(setup){
 const sevenZip=path.join(process.env.ProgramFiles||'C:\\Program Files','7-Zip/7z.exe');
 if(!await exists(sevenZip))throw Error('The isolated Windows runner must provide its preinstalled 7-Zip for independent NSIS payload extraction.');
 const extracted=insideBuild(await fs.mkdtemp(path.join(build,'nsis-payload-')));
 run(sevenZip,['x',setup,'-o'+extracted,'-y','-bso0','-bsp0']);
 const matches=[];
 async function visit(dir){for(const item of await fs.readdir(dir,{withFileTypes:true})){const file=path.join(dir,item.name);if(item.isDirectory())await visit(file);else if(item.isFile()&&item.name.toLowerCase()==='aegis-desktop.exe')matches.push(file);}}
 await visit(extracted);
 if(matches.length!==1)throw Error('The independently extracted NSIS payload must contain exactly one Aegis executable.');
 return baseline(matches[0]);
}
function inspectMsi(msi){const powershell=path.join(process.env.SystemRoot||'C:\\Windows','System32/WindowsPowerShell/v1.0/powershell.exe');return JSON.parse(execFileSync(powershell,['-NoProfile','-NonInteractive','-File',path.join(root,'scripts/inspect-msi.ps1'),'-MsiPath',msi],{windowsHide:true,encoding:'utf8',timeout:60000}).trim().replace(/^\uFEFF/,''));}
(async()=>{
 if(process.platform!=='win32'||process.env.CI!=='true')throw Error('Installation tests are restricted to isolated Windows CI runners.');
 await fs.mkdir(build,{recursive:true});
 const bundle=path.join(root,'src-tauri/target/release/bundle'),msiexec=path.join(process.env.SystemRoot||'C:\\Windows','System32/msiexec.exe');
 const setup=await find(bundle,name=>name.endsWith('-setup.exe')),msi=await find(bundle,name=>name.endsWith('.msi'));
 if(!setup||!msi)throw Error('Both Windows installers are required.');
 const payload=JSON.parse(await fs.readFile(path.join(build,'installed-payload.json'),'utf8'));
 // Tauri patches the executable with a different bundle-type marker for NSIS
 // and MSI. Compare each real installation against its own extracted payload.
 const expectedByKind={nsis:await nsisBaseline(setup),msi:await baseline(payload.executable)};
 console.log('Independent installer payload baselines: '+JSON.stringify(expectedByKind));
 const initialMsi=inspectMsi(msi),expectedVersion=require('../package.json').version;
 if(initialMsi.productName!=='Aegis'||initialMsi.productVersion!==expectedVersion||initialMsi.productState===5)throw Error('MSI package identity/version is unexpected or already installed before this test.');
 const priorDestinations=[];
 for(const kind of ['nsis','msi']){
  const destination=insideBuild(path.join(build,kind+'-installed-'+Date.now()));
  let actualDestination=destination,executable=path.join(destination,'aegis-desktop.exe');
  const expected=expectedByKind[kind];
  let evidence={kind,requestedDestination:destination,expected};
  if(await exists(destination))throw Error('Refusing to overwrite an existing test installation.');
  const allowedDestinations=[destination,...priorDestinations];
  for(const candidate of allowedDestinations){if(await exists(path.join(candidate,'aegis-desktop.exe'))||await exists(path.join(candidate,'engines')))throw Error('A test destination contains stale application or engine files before installation.');}
  const beforeMsi=kind==='msi'?inspectMsi(msi):null;
  if(beforeMsi?.productState===5)throw Error('The MSI unexpectedly became installed before its installation test.');
  let installed=false;
  try{
   if(kind==='nsis')run(setup,['/S','/D='+destination]);
   else run(msiexec,['/i',msi,'/qn','/norestart','INSTALLDIR='+destination,'/L*v',path.join(build,'msi-install.log')]);
   installed=true;
   if(kind==='msi'){
    const registered=inspectMsi(msi);
    evidence={...evidence,before:beforeMsi,after:registered,allowedDestinations};
    await fs.writeFile(path.join(build,'msi-install-evidence.json'),JSON.stringify(evidence,null,2));
    if(registered.productCode!==initialMsi.productCode||registered.productState!==5||registered.registeredVersion!==expectedVersion||!registered.installLocation)throw Error('The exact MSI product is not registered with the expected version and installation location.');
    console.log('MSI registered installation location: '+registered.installLocation);
    actualDestination=await canonicalInsideBuild(registered.installLocation);
    const canonicalBase=await fs.realpath(build);
    if(!allowedDestinations.some(candidate=>samePath(actualDestination,path.join(canonicalBase,path.basename(candidate)))))throw Error('MSI registered a location that is not one of this job\'s empty test destinations.');
    executable=path.join(actualDestination,'aegis-desktop.exe');
   }
   if(!await exists(executable))throw Error(kind+' did not install the application in its verified installation directory.');
   actualDestination=await canonicalInsideBuild(actualDestination);
   const actual=await baseline(executable),expectedInstalledPath=path.join(actualDestination,'aegis-desktop.exe');
   evidence={...evidence,actualDestination,expectedInstalledPath,actual};
   await fs.writeFile(path.join(build,kind+'-install-evidence.json'),JSON.stringify(evidence,null,2));
   console.log(kind.toUpperCase()+' installation identity: '+JSON.stringify(evidence));
   if(!samePath(actual.executable,expectedInstalledPath))throw Error(kind+' installed executable has an unexpected canonical path: expected '+expectedInstalledPath+', actual '+actual.executable);
   if(actual.sha256!==expected.sha256||actual.bytes!==expected.bytes)throw Error(kind+' installed executable differs from its own extracted installer payload: expected SHA-256 '+expected.sha256+' ('+expected.bytes+' bytes), actual '+actual.sha256+' ('+actual.bytes+' bytes)');
   executable=actual.executable;
   execFileSync(process.execPath,[path.join(root,'scripts/check-runtimes.cjs')],{windowsHide:true,stdio:'inherit',timeout:60000,env:{...process.env,AEGIS_CHECK_RESOURCES:path.join(actualDestination,'engines')}});
   execFileSync(process.execPath,[path.join(root,'scripts/test-native-windows.cjs'),executable],{windowsHide:true,stdio:'inherit',timeout:300000});
  }finally{
   if(installed){
    if(kind==='msi')run(msiexec,['/x',msi,'/qn','/norestart','/L*v',path.join(build,'msi-uninstall.log')]);
    else{const uninstall=await find(destination,name=>/^uninstall.*\.exe$/i.test(name));if(!uninstall)throw Error('NSIS uninstaller missing.');run(uninstall,['/S']);}
    await removed(executable);
    await removed(path.join(actualDestination,'engines'));
    if(kind==='msi'&&inspectMsi(msi).productState===5)throw Error('The exact MSI product remained registered as installed after uninstall.');
   }
  }
  priorDestinations.push(destination);
  console.log('PASS: '+kind.toUpperCase()+' installed, actual native UI/engines checked, then application and engine files uninstalled.');
 }
})().catch(error=>{console.error(error.message);process.exitCode=1;});
