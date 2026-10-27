const path=require('node:path'),{spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..'),env={...process.env};
if(process.platform==='linux'){const resources=path.join(root,'.build/bundle-resources');env.LD_LIBRARY_PATH=[path.join(resources,'tor/tor'),path.join(resources,'tor'),path.join(resources,'clamav/lib'),path.join(resources,'clamav/lib64'),env.LD_LIBRARY_PATH||''].filter(Boolean).join(path.delimiter);env.NO_STRIP='true';}
const child=spawnSync(process.execPath,[require.resolve('@tauri-apps/cli/tauri.js'),'build',...process.argv.slice(2)],{cwd:root,env,stdio:'inherit',windowsHide:true});if(child.error)console.error(child.error.message);process.exitCode=child.status??1;
