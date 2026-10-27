const fs=require('node:fs/promises'),path=require('node:path'),{execFileSync,spawn}=require('node:child_process'),{pipeline}=require('node:stream/promises');
const root=path.resolve(__dirname,'..'),build=path.join(root,'.build');
async function walk(dir,fn){for(const e of await fs.readdir(dir,{withFileTypes:true})){const file=path.join(dir,e.name);if(await fn(file,e))return file;if(e.isDirectory()){const found=await walk(file,fn);if(found)return found;}}return null;}
function safe(file){const absolute=path.resolve(file),relative=path.relative(build,absolute);if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw Error('Test path is outside .build');return absolute;}
async function temporary(prefix){const file=safe(path.join(build,prefix+'-'+Date.now()));await fs.mkdir(file,{recursive:true});return file;}
async function extractRpm(file,destination){
 const converter=spawn('/usr/bin/rpm2cpio',[file],{stdio:['ignore','pipe','inherit']});
 const extractor=spawn('/usr/bin/cpio',['-id','--no-absolute-filenames','--quiet'],{cwd:destination,stdio:['pipe','inherit','inherit']});
 const completed=(child,label)=>new Promise((resolve,reject)=>{
  child.once('error',reject);
  child.once('close',(code,signal)=>code===0?resolve():reject(Error(label+' failed: '+(signal||code))));
 });
 const exits=[completed(converter,'rpm2cpio'),completed(extractor,'cpio')];let timedOut=false;
 const stop=()=>{converter.kill('SIGKILL');extractor.kill('SIGKILL');};
 const timer=setTimeout(()=>{timedOut=true;stop();},120000);
 try{
  await Promise.all([pipeline(converter.stdout,extractor.stdin),...exits]);
 }catch(error){
  stop();await Promise.allSettled(exits);
  throw timedOut?Error('RPM extraction timed out'):error;
 }finally{clearTimeout(timer);}
}
async function payload(extracted){
 const engines=await walk(extracted,async(f,e)=>e.isDirectory()&&e.name==='engines'&&await fs.stat(path.join(f,'clamav')).then(s=>s.isDirectory()).catch(()=>false));
 if(!engines)throw Error('Installed engine resources missing: '+extracted);
 if(await walk(engines,async(f,e)=>e.isFile()&&/unrar/i.test(e.name)))throw Error('Restricted UnRAR module found');
 await fs.access(path.join(engines,'clamav/certs/clamav.crt'));
 const executable=await walk(extracted,async(f,e)=>e.isFile()&&e.name===(process.platform==='win32'?'aegis-desktop.exe':'aegis-desktop'));
 if(!executable)throw Error('Application executable missing');
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
  const rpmDir=await temporary('rpm-check');await extractRpm(rpm,rpmDir);await payload(rpmDir);
  const image=await walk(bundle,async(f,e)=>e.isFile()&&f.endsWith('.AppImage'));if(!image)throw Error('AppImage missing');
  const imageDir=await temporary('appimage-check');execFileSync(image,['--appimage-extract'],{cwd:imageDir,stdio:'ignore',timeout:120000});await payload(path.join(imageDir,'squashfs-root'));
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
