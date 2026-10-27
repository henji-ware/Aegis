const fs=require('node:fs/promises');
const{runtimeEnv}=require('../electron/runtime-env.cjs');
const path=require('node:path');
const{Antivirus}=require('../electron/antivirus.cjs'),{run,findTool}=require('../electron/runner.cjs');
(async()=>{const resources=process.env.AEGIS_CHECK_RESOURCES||path.resolve(__dirname,'..','resources'),av=new Antivirus({store:{dir:path.resolve(__dirname,'..','.build','check')},resources,emit:()=>{}}),{scanner,updater}=await av.binaries();
if(!scanner||!updater)throw new Error('ClamAV/FreshClam are unavailable.');
console.log(await run(scanner,['--version'],{env:av.env()}));
await fs.mkdir(av.store.dir,{recursive:true});const config=path.join(av.store.dir,'freshclam.conf');await fs.writeFile(config,'DatabaseDirectory "'+av.store.dir.replace(/\\/g,'/')+'"\nDatabaseMirror database.clamav.net\n');console.log(await run(updater,['--config-file='+config,'--version'],{env:av.env()}));
const exe=process.platform==='win32'?'tor.exe':'tor',tor=await findTool('tor',[path.join(resources,'tor','tor',exe),path.join(resources,'tor',exe)]);
if(!tor)throw new Error('Tor is unavailable.');console.log((await run(tor,['--version'],{env:runtimeEnv('tor',resources)})).split('\n')[0]);
})().catch(e=>{console.error(e.message);process.exitCode=1;});

