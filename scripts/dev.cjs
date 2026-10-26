const {spawn}=require('node:child_process');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const vite=spawn(process.execPath,[path.join(root,'node_modules/vite/bin/vite.js')],{cwd:root,stdio:'inherit'});
let electron;
async function launch(){
  for(let i=0;i<50;i++){
    try{const response=await fetch('http://127.0.0.1:5173');if(response.ok)break;}catch{}
    await new Promise(resolve=>setTimeout(resolve,300));
  }
  electron=spawn(require('electron'),[root],{cwd:root,stdio:'inherit',env:{...process.env,AEGIS_DEV:'1'}});
  electron.on('close',()=>{vite.kill();process.exit(0);});
}
launch();
process.on('SIGINT',()=>{vite.kill();electron?.kill();});

