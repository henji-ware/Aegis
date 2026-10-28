const fs=require('node:fs/promises'),path=require('node:path'),{execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),build=path.join(root,'.build');
async function walk(dir,fn){for(const e of await fs.readdir(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(await fn(file,e))return file;if(e.isDirectory()){const found=await walk(file,fn);if(found)return found;}}return null;}
function safe(file){const absolute=path.resolve(file),relative=path.relative(build,absolute);if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw Error('Test path is outside .build');return absolute;}
async function temporary(prefix){const file=safe(path.join(build,prefix+'-'+Date.now()));await fs.mkdir(file,{recursive:true});return file;}
async function extractRpm(file,destination){
 // libarchive reads the RPM wrapper and compressed CPIO payload directly.
 // The caller separately requires rpm --checksig and all extracted payload checks.
 execFileSync('/usr/bin/bsdtar',['-x','-f',file,'-C',safe(destination),'--no-same-owner'],{stdio:'inherit',timeout:120000});
}
async function rpmInstallRoundTrip(file){
 if(process.env.CI!=='true'||process.platform!=='linux')throw Error('RPM transactions run only on isolated Linux CI runners.');
 const testRoot=await temporary('rpm-installed');
 const [realProject,realBuild,realRoot]=await Promise.all([fs.realpath(root),fs.realpath(build),fs.realpath(testRoot)]);
 const within=(parent,child)=>{const relative=path.relative(parent,child);return Boolean(relative)&&!relative.startsWith('..')&&!path.isAbsolute(relative);};
 if(!within(realProject,realBuild)||!within(realBuild,realRoot)||realRoot!==path.join(realBuild,path.basename(testRoot))||!path.basename(realRoot).startsWith('rpm-installed-')||(await fs.lstat(testRoot)).isSymbolicLink())throw Error('RPM transaction root is not an owned .build directory.');
 const rpm=(...args)=>execFileSync('/usr/bin/sudo',['-n','/usr/bin/rpm','--root',realRoot,'--define','_dbpath /var/lib/rpm',...args],{stdio:'inherit',timeout:120000});
 rpm('--initdb');let installed=false;
 try{
  rpm('--install','--nodeps','--noscripts','--notriggers',file);installed=true;
  await payload(realRoot);
 }finally{
  if(installed){
   rpm('--erase','--nodeps','--noscripts','--notriggers','aegis');
   const executable=path.join(realRoot,'usr/bin/aegis-desktop');
   if(await fs.lstat(executable).then(()=>true,error=>{if(error.code==='ENOENT')return false;throw error;}))throw Error('RPM erase left the application executable behind.');
  }
 }
 console.log('PASS: RPM installed, native payload checked and package erased in an isolated CI root. Dependency resolution and package scripts were not exercised.');
}
async function payload(extracted){
 const engines=await walk(extracted,async(f,e)=>e.isDirectory()&&e.name==='engines'&&await fs.stat(path.join(f,'clamav')).then(s=>s.isDirectory()).catch(()=>false));
 if(!engines)throw Error('Installed engine resources missing: '+extracted);
 if(process.platform!=='win32'){
  // Ownership during extraction must not hide owner-only package resources.
  const checkMode=async file=>{
   const stat=await fs.lstat(file);
   if(stat.isSymbolicLink())return;
   const expected=stat.isDirectory()||(stat.mode&0o111)?0o755:0o644;
   if((stat.mode&0o7777)!==expected)throw Error('Non-public packaged resource mode: '+file+' ('+(stat.mode&0o7777).toString(8)+')');
   if(stat.isDirectory())for(const entry of await fs.readdir(file))await checkMode(path.join(file,entry));
  };
  await checkMode(engines);
 }
 if(await walk(engines,async(f,e)=>e.isFile()&&/unrar/i.test(e.name)))throw Error('Restricted UnRAR module found');
 await fs.access(path.join(engines,'clamav/certs/clamav.crt'));
 const executable=await walk(extracted,async(f,e)=>e.isFile()&&e.name===(process.platform==='win32'?'aegis-desktop.exe':'aegis-desktop'));
 if(!executable)throw Error('Application executable missing');
 if(process.platform==='linux')await fs.access(executable,require('node:fs').constants.X_OK);
 execFileSync(process.execPath,[path.join(root,'scripts/check-runtimes.cjs')],{stdio:'inherit',windowsHide:true,timeout:60000,env:{...process.env,AEGIS_CHECK_RESOURCES:engines}});
 console.log('PASS: payload has app executable, working engines, ClamAV trust certificates and no UnRAR modules.');
 return {engines,executable};
}
(async()=>{
 if(process.env.CI!=='true')throw Error('Installer checks run only on isolated CI runners.');
 await fs.mkdir(build,{recursive:true});const bundle=path.join(root,'src-tauri/target/release/bundle');
 if(process.platform==='linux'){
  const deb=await walk(bundle,async(f,e)=>e.isFile()&&f.endsWith('.deb'));if(!deb)throw Error('DEB missing');
  const extracted=await temporary('deb-check');execFileSync('/usr/bin/dpkg-deb',['-x',deb,extracted],{stdio:'inherit'});console.log(execFileSync('/usr/bin/dpkg-deb',['-f',deb,'Package','Version','Architecture','Depends'],{encoding:'utf8'}));await payload(extracted);
  const rpm=await walk(bundle,async(f,e)=>e.isFile()&&f.endsWith('.rpm'));if(!rpm)throw Error('RPM missing');
  execFileSync('/usr/bin/rpm',['--checksig',rpm],{stdio:'inherit'});console.log(execFileSync('/usr/bin/rpm',['-qp','--qf','%{NAME} %{VERSION} %{ARCH}\n',rpm],{encoding:'utf8'}));
  const rpmDir=await temporary('rpm-check');await extractRpm(rpm,rpmDir);await payload(rpmDir);await rpmInstallRoundTrip(rpm);
  const image=await walk(bundle,async(f,e)=>e.isFile()&&f.endsWith('.AppImage'));if(!image)throw Error('AppImage missing');
  // The AppImage runtime intentionally creates extracted directories as 0700
  // (type2-runtime/src/runtime/runtime.c: mkdir_p). Inspect the actual embedded
  // filesystem with unsquashfs so extraction does not replace its stored modes.
  const offset=execFileSync(image,['--appimage-offset'],{encoding:'utf8',timeout:30000}).trim();
  if(!/^[0-9]+$/.test(offset)||!Number.isSafeInteger(Number(offset))||Number(offset)<=0)throw Error('Invalid AppImage filesystem offset');
  const imageDir=await temporary('appimage-check'),imageRoot=path.join(imageDir,'squashfs-root');
  execFileSync('/usr/bin/unsquashfs',['-no-progress','-strict-errors','-offset',offset,'-dest',imageRoot,image],{stdio:'inherit',timeout:120000});await payload(imageRoot);
  console.log('PASS: DEB, RPM integrity/metadata and extracted AppImage checked.');
 }else if(process.platform==='darwin'){
  const app=await walk(bundle,async(f,e)=>e.isDirectory()&&f.endsWith('.app'));if(!app)throw Error('App bundle missing');execFileSync('/usr/bin/codesign',['--verify','--deep','--strict',app],{stdio:'inherit'});await payload(app);
  const dmg=await walk(bundle,async(f,e)=>e.isFile()&&f.endsWith('.dmg'));if(!dmg)throw Error('DMG missing');
  const mount=await temporary('dmg-mount'),installed=await temporary('dmg-installed');let attached=false,copied;
  try{
   execFileSync('/usr/bin/hdiutil',['attach',dmg,'-readonly','-nobrowse','-noautoopen','-mountpoint',mount],{input:'Y\n',stdio:['pipe','inherit','inherit'],timeout:120000});attached=true;
   const source=await walk(mount,async(f,e)=>e.isDirectory()&&f.endsWith('.app'));if(!source)throw Error('DMG has no app bundle');
   copied=safe(path.join(installed,path.basename(source)));execFileSync('/usr/bin/ditto',[source,copied],{stdio:'inherit'});execFileSync('/usr/bin/codesign',['--verify','--deep','--strict',copied],{stdio:'inherit'});await payload(copied);
  }finally{
   if(attached)execFileSync('/usr/bin/hdiutil',['detach',mount],{stdio:'inherit',timeout:60000});
   if(copied){safe(copied);await fs.rm(copied,{recursive:true,force:true});if(await fs.stat(copied).then(()=>true,()=>false))throw Error('Copied app was not removed');}
  }
  console.log('PASS: DMG mounted read-only, app copied, signature/engines verified, volume detached and test app removed.');
 }else if(process.platform==='win32'){
  const msi=await walk(bundle,async(f,e)=>e.isFile()&&f.endsWith('.msi'));if(!msi)throw Error('MSI missing');const extracted=await temporary('msi-check');
  execFileSync(path.join(process.env.SystemRoot||'C:\\Windows','System32/msiexec.exe'),['/a',msi,'TARGETDIR='+extracted,'/qn','/L*v',path.join(extracted,'extract.log')],{windowsHide:true,timeout:120000});
  const setup=await walk(bundle,async(f,e)=>e.isFile()&&f.endsWith('-setup.exe'));if(!setup||(await fs.readFile(setup)).subarray(0,2).toString()!=='MZ')throw Error('NSIS missing or invalid');
  await fs.writeFile(path.join(build,'installed-payload.json'),JSON.stringify(await payload(extracted)));
 }else throw Error('Unsupported CI platform');
})().catch(error=>{console.error(error.message);process.exitCode=1;});
