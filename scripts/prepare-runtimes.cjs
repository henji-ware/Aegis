'use strict';
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),{execFile}=require('node:child_process');
const root=path.resolve(__dirname,'..'),manifest=require('../runtimes.json'),platform=process.platform,arch=process.arch,key=platform+'-'+arch;
const cache=path.join(root,'.build','downloads'),resources=path.join(root,'resources');
const run=(file,args)=>new Promise((resolve,reject)=>execFile(file,args,{windowsHide:true,maxBuffer:8*1024*1024},(e,out,err)=>e?reject(new Error(err||e.message)):resolve(out)));
const quote=s=>"'"+String(s).replace(/'/g,"''")+"'";
const ps=code=>run(path.join(process.env.SystemRoot||'C:\\Windows','System32','WindowsPowerShell','v1.0','powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(code,'utf16le').toString('base64')]);
async function download(url,name,hash){
  const file=path.join(cache,name);let data;
  try{data=await fs.readFile(file);}catch{}
  if(!data||crypto.createHash('sha256').update(data).digest('hex')!==hash){
    console.log('Baixando '+name);const response=await fetch(url);if(!response.ok)throw new Error('Download falhou: '+response.status);
    data=Buffer.from(await response.arrayBuffer());if(crypto.createHash('sha256').update(data).digest('hex')!==hash)throw new Error('Checksum inválido: '+name);
    await fs.writeFile(file,data);
  }
  return file;
}
async function zip(file,dir){await fs.mkdir(dir,{recursive:true});await ps('Expand-Archive -LiteralPath '+quote(file)+' -DestinationPath '+quote(dir)+' -Force');}
async function findClamRoot(dir,depth=0){
 if(depth>9)return null;
 try{await fs.access(path.join(dir,'bin','clamscan'));return dir;}catch{}
 for(const item of await fs.readdir(dir,{withFileTypes:true}))if(item.isDirectory()){const found=await findClamRoot(path.join(dir,item.name),depth+1);if(found)return found;}
 return null;
}
function cabinetFromMsi(data){
 if(data.subarray(0,8).toString('hex')!=='d0cf11e0a1b11ae1')throw new Error('Contêiner MSI inválido.');
 const size=1<<data.readUInt16LE(30),sector=n=>data.subarray((n+1)*size,(n+2)*size),fat=[];
 // The pinned WireGuard MSI has its complete DIFAT in the header (less than 109 FAT sectors).
 const count=data.readUInt32LE(44);if(count>109)throw new Error('DIFAT estendido não suportado para este pacote.');
 for(let i=0;i<count;i++){const block=sector(data.readUInt32LE(76+i*4));for(let j=0;j<block.length;j+=4)fat.push(block.readUInt32LE(j));}
 function chain(first){const blocks=[],seen=new Set();let n=first;while(n<0xfffffffa){if(seen.has(n)||n>=fat.length)throw new Error('Cadeia MSI inválida.');seen.add(n);blocks.push(sector(n));n=fat[n];}return Buffer.concat(blocks);}
 const directory=chain(data.readUInt32LE(48));
 for(let offset=0;offset+128<=directory.length;offset+=128){
  if(directory[offset+66]!==2)continue;
  const length=Number(directory.readBigUInt64LE(offset+120));if(length<4096)continue;
  const content=chain(directory.readUInt32LE(offset+116)).subarray(0,length);
  if(content.subarray(0,4).toString()==='MSCF')return content;
 }
 throw new Error('Cabinet do WireGuard não encontrado.');
}
async function relocateMac(directory){
 const binaries=[],seen=new Set();
 async function walk(dir){for(const item of await fs.readdir(dir,{withFileTypes:true})){const full=path.join(dir,item.name);if(item.isDirectory())await walk(full);else if(item.isFile()&&(/\.dylib(?:\.|$)/.test(item.name)||path.basename(dir)==='bin')){const actual=await fs.realpath(full);if(!seen.has(actual)){seen.add(actual);binaries.push(actual);}}}}
 await walk(directory);
 for(const binary of binaries){let info;try{info=await run('/usr/bin/otool',['-L',binary]);}catch{continue;}
  for(const line of info.split('\n').slice(1)){const dependency=line.trim().split(' (')[0];if(!dependency.startsWith('/usr/local/')&&!dependency.startsWith('/opt/homebrew/'))continue;const destination=path.join(directory,'lib',path.basename(dependency));try{await fs.access(destination);}catch{throw new Error('Dependência macOS não incluída: '+dependency);}
   const relative=path.relative(path.dirname(binary),destination).split(path.sep).join('/');await run('/usr/bin/install_name_tool',['-change',dependency,'@loader_path/'+relative,binary]);
  }
  if(binary.includes(path.sep+'lib'+path.sep)&&/\.dylib/.test(binary))await run('/usr/bin/install_name_tool',['-id','@rpath/'+path.basename(binary),binary]);
  await run('/usr/bin/codesign',['--force','--sign','-',binary]);
 }
}
async function prepare(){
 await fs.mkdir(cache,{recursive:true});await fs.mkdir(resources,{recursive:true});
 const clam=manifest.clamav.assets[key],tor=manifest.tor.assets[key];
 if(!clam||!tor)throw new Error('Não há binários oficiais fixados para '+key+'. Atualize runtimes.json com uma distribuição oficial verificável.');
 const file=await download('https://github.com/Cisco-Talos/clamav/releases/download/clamav-'+manifest.clamav.version+'/'+clam.name,clam.name,clam.sha256);
 const extracted=path.join(cache,'clam-'+key);
 if(platform==='win32'){
  await zip(file,extracted);const directory=path.join(extracted,clam.name.replace('.zip','')),target=path.join(resources,'clamav');await fs.mkdir(target,{recursive:true});
  for(const item of await fs.readdir(directory)){if(!/unrar/i.test(item)&&(/\.(exe|dll)$/i.test(item)||/^COPYING/.test(item)||item==='certs'))await fs.cp(path.join(directory,item),path.join(target,item),{recursive:true});}
  const wg=manifest.wireguard;if(arch!=='x64')throw new Error('Prepare WireGuard para esta arquitetura antes de empacotar.');
  const msi=await download(wg.url,wg.name,wg.sha256),cab=path.join(cache,'wireguard.cab'),wgDir=path.join(resources,'wireguard');
  await fs.writeFile(cab,cabinetFromMsi(await fs.readFile(msi)));await fs.mkdir(wgDir,{recursive:true});
  await run(path.join(process.env.SystemRoot||'C:\\Windows','System32','expand.exe'),['-F:*',cab,wgDir]);
  const response=await fetch('https://git.zx2c4.com/wireguard-windows/plain/COPYING?h=v1.1.1');if(!response.ok)throw new Error('Licença WireGuard indisponível.');await fs.writeFile(path.join(wgDir,'COPYING'),await response.text());
 }else{
  if(platform==='linux'){await fs.mkdir(extracted,{recursive:true});await run('/usr/bin/dpkg-deb',['-x',file,extracted]);}
  else{await run('/usr/sbin/pkgutil',['--expand-full',file,extracted]);}
  const base=await findClamRoot(extracted);if(!base)throw new Error('Estrutura ClamAV desconhecida.');
  await fs.cp(base,path.join(resources,'clamav'),{recursive:true,filter:file=>!/unrar/i.test(path.basename(file))});
  if(platform==='darwin')await relocateMac(path.join(resources,'clamav'));
 }
 const torFile=await download(manifest.tor.base+tor.name,tor.name,tor.sha256),torDir=path.join(resources,'tor');
 await fs.mkdir(torDir,{recursive:true});await run(platform==='win32'?'tar':'/usr/bin/tar',['-xzf',torFile,'-C',torDir]);
 console.log('Mecanismos preparados para '+key+'. Nenhum serviço foi instalado e nenhuma configuração de rede foi alterada.');
}
module.exports={cabinetFromMsi};
if(require.main===module)prepare().catch(e=>{console.error(e.message);process.exitCode=1;});

