'use strict';
const fs=require('node:fs/promises'),path=require('node:path');
const {packager}=require('@electron/packager');
const root=path.resolve(__dirname,'..');
(async()=>{
 const version=require('../package.json').version;
 const build=path.join(root,'.build','package-'+Date.now()),stage=path.join(build,'app'),runtime=path.join(build,'runtimes');
 await fs.mkdir(stage,{recursive:true});await fs.mkdir(runtime,{recursive:true});
 for(const name of ['electron','dist','assets','locales'])await fs.cp(path.join(root,name),path.join(stage,name),{recursive:true});
 await fs.writeFile(path.join(stage,'package.json'),JSON.stringify({name:'aegis-desktop',productName:'Aegis',version,main:'electron/main.cjs',author:'Aegis contributors',license:'MIT'}));
 await fs.cp(path.join(root,'LICENSE'),path.join(stage,'LICENSE'));
 const extra=[];
 for(const name of ['clamav','tor','wireguard']){
  const source=path.join(root,'resources',name),target=path.join(runtime,name);
  try{
   await fs.access(source);
   await fs.cp(source,target,{recursive:true,dereference:true,filter:entry=>{
    const base=path.basename(entry);
    // No restricted UnRAR module is distributed. Keep the scanning/updating tools only.
    if(/unrar/i.test(base))return false;
    if(name==='clamav'&&/\.(pdb|lib)$/i.test(base))return false;
    if(name==='clamav'&&/\.exe$/i.test(base)&&!['clamscan.exe','freshclam.exe','sigtool.exe'].includes(base.toLowerCase()))return false;
    return true;
   }});
   extra.push(target);
  }catch(error){if(name!=='wireguard'||process.platform==='win32')throw new Error('Prepare engines before packaging: '+name+' · '+error.message);}
 }
 extra.push(path.join(root,'docs','THIRD-PARTY-NOTICES.txt'),path.join(root,'docs','UI-LICENSES.txt'));
 const options={dir:stage,out:process.env.AEGIS_PACKAGE_OUTPUT?path.resolve(process.env.AEGIS_PACKAGE_OUTPUT):path.join(root,'release'),name:'Aegis',executableName:'Aegis',appBundleId:'org.aegis.desktop',appCopyright:'Aegis contributors',platform:process.platform,arch:process.arch,electronVersion:require('electron/package.json').version,icon:path.join(root,'assets','icon'),asar:true,prune:false,overwrite:false,tmpdir:path.join(build,'tmp'),extraResource:extra,download:{cacheRoot:path.join(root,'.build','electron-cache')}};
 const zipDir=process.env.AEGIS_ELECTRON_ZIP_DIR;if(zipDir)options.electronZipDir=path.resolve(zipDir);
 const paths=await packager(options);console.log('Package created:',paths.join('\n'));
})().catch(error=>{console.error(error);process.exitCode=1;});

