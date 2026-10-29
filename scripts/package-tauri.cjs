const path=require('node:path'),{spawn}=require('node:child_process');
const root=path.resolve(__dirname,'..'),env={...process.env};
if(process.platform==='linux'){const resources=path.join(root,'.build/bundle-resources');env.LD_LIBRARY_PATH=[path.join(resources,'tor/tor'),path.join(resources,'tor'),path.join(resources,'clamav/lib'),path.join(resources,'clamav/lib64'),env.LD_LIBRARY_PATH||''].filter(Boolean).join(path.delimiter);env.NO_STRIP='true';}
async function build(){return new Promise(resolve=>{
 let tail='';const child=spawn(process.execPath,[require.resolve('@tauri-apps/cli/tauri.js'),'build',...process.argv.slice(2)],{cwd:root,env,stdio:['inherit','pipe','pipe'],windowsHide:true});
 for(const [input,output]of [[child.stdout,process.stdout],[child.stderr,process.stderr]])input.on('data',bytes=>{output.write(bytes);tail=(tail+bytes.toString()).slice(-8000);});
 child.on('error',error=>{console.error(error.message);resolve({code:1,tail:error.message});});
 child.on('close',code=>resolve({code:code??1,tail}));
});}
(async()=>{for(let attempt=1;attempt<=3;attempt++){
 const result=await build();if(result.code===0)return;
 const downloadTimeout=process.platform==='win32'&&/failed to bundle project:[^\n]*timeout: global/i.test(result.tail);
 if(!downloadTimeout||attempt===3){process.exitCode=result.code;return;}
 console.log(`The Windows bundler download timed out. Retrying the verified Tauri build (${attempt+1}/3).`);
}})().catch(error=>{console.error(error.message);process.exitCode=1;});
