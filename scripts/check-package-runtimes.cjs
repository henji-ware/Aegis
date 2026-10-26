const path=require('node:path');
const {run}=require('../electron/runner.cjs');
const packageDir=path.resolve(__dirname,'..','release','Aegis-'+process.platform+'-'+process.arch);
const resources=process.platform==='darwin'?path.join(packageDir,'Aegis.app','Contents','Resources'):path.join(packageDir,'resources');
run(process.execPath,[path.join(__dirname,'check-runtimes.cjs')],{env:{...process.env,AEGIS_CHECK_RESOURCES:resources}}).then(console.log).catch(e=>{console.error(e.message);process.exitCode=1});
