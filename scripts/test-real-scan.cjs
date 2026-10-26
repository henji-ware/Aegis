const path=require('node:path');
const{spawn}=require('node:child_process');
const{parseClamSummary}=require('../electron/validation.cjs');
const root=path.resolve(__dirname,'..');
const args=['--database='+path.join(root,'.aegis-test','engine','signatures'),'--stdout','--infected','-'];
const child=spawn(path.join(root,'resources','clamav','clamscan.exe'),args,{windowsHide:true,stdio:['pipe','pipe','pipe']});
let output='';child.stdout.on('data',chunk=>output+=chunk);child.stderr.on('data',chunk=>output+=chunk);
child.on('close',code=>{const result=parseClamSummary(output,code);console.log(JSON.stringify({code,result,output}));if(code!==1||result.infected!==1)process.exitCode=1;});
child.stdin.end(Buffer.from('58354f2150254041505b345c505a58353428505e2937434329377d2445494341522d5354414e444152442d414e544956495255532d544553542d46494c452124482b482a','hex'));

