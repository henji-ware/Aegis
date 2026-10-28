const fs=require('node:fs/promises'),path=require('node:path');
// Only public package resources: upstream Tor owner-only modes fail after a
// root-owned install. Never apply this normalization to private user data.
async function publicModes(file){
 const stat=await fs.lstat(file);
 if(stat.isDirectory()){
  await fs.chmod(file,0o755);
  for(const entry of await fs.readdir(file))await publicModes(path.join(file,entry));
 }else if(stat.isFile())await fs.chmod(file,stat.mode&0o111?0o755:0o644);
 else throw Error('Unexpected staged resource type: '+file);
}
(async()=>{const root=path.resolve(__dirname,'..'),target=path.join(root,'.build','bundle-resources');await fs.mkdir(target,{recursive:true});for(const name of ['clamav','tor','wireguard']){const source=path.join(root,'resources',name);try{await fs.access(source);}catch{if(name==='wireguard'&&process.platform!=='win32')continue;throw Error('Missing runtime: '+name);}await fs.cp(source,path.join(target,name),{recursive:true,dereference:true,filter:file=>{const base=path.basename(file);if(/unrar/i.test(base))return false;if(name==='clamav'&&/\.(pdb|lib)$/i.test(base))return false;if(name==='clamav'&&/\.exe$/i.test(base)&&!['clamscan.exe','freshclam.exe','sigtool.exe'].includes(base.toLowerCase()))return false;return true;}});}if(process.platform!=='win32')await publicModes(target);console.log('Bundled engines staged; UnRAR and development libraries excluded.');})().catch(e=>{console.error(e);process.exitCode=1;});
