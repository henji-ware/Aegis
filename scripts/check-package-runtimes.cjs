const path=require('node:path');
const {run}=require('../electron/runner.cjs');
const fs=require('node:fs/promises');
const packageDir=path.resolve(__dirname,'..','release','Aegis-'+process.platform+'-'+process.arch);
const resources=process.platform==='darwin'?path.join(packageDir,'Aegis.app','Contents','Resources'):path.join(packageDir,'resources');
async function verifyLinks(dir){
 for(const entry of await fs.readdir(dir,{withFileTypes:true})){const file=path.join(dir,entry.name);if(entry.isDirectory())await verifyLinks(file);else if(entry.isSymbolicLink()){const actual=await fs.realpath(file);if(!actual.startsWith(resources+path.sep))throw Error('Dependência fora do pacote: '+file);}}
}
verifyLinks(resources).then(()=>run(process.execPath,[path.join(__dirname,'check-runtimes.cjs')],{env:{...process.env,AEGIS_CHECK_RESOURCES:resources}})).then(console.log).catch(e=>{console.error(e.message);process.exitCode=1});
