const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
if(process.env.CI!=='true')throw Error('Signing preparation is restricted to isolated CI.');
const root=path.resolve(__dirname,'..'),configFile=path.join(root,'src-tauri/tauri.conf.json');
const trusted=process.env.GITHUB_REF==='refs/heads/main'&&process.env.GITHUB_EVENT_NAME!=='pull_request';
if(trusted){if(!process.env.TAURI_SIGNING_PRIVATE_KEY)throw Error('Configure the repository Actions secret TAURI_SIGNING_PRIVATE_KEY before building a public release.');
 const delimiter='AEGIS_'+crypto.randomBytes(16).toString('hex');fs.appendFileSync(process.env.GITHUB_ENV,'TAURI_SIGNING_PRIVATE_KEY<<'+delimiter+'\n'+process.env.TAURI_SIGNING_PRIVATE_KEY.trim()+'\n'+delimiter+'\nTAURI_SIGNING_PRIVATE_KEY_PASSWORD=\n');
 console.log('Using the configured release signing secret; key contents are never printed.');}
else{
 const folder=path.join(root,'.build/update-signing');fs.mkdirSync(folder,{recursive:true});const key=path.join(folder,'ephemeral.key');
 const result=spawnSync(process.execPath,[require.resolve('@tauri-apps/cli/tauri.js'),'signer','generate','--ci','-p','','-w',key],{encoding:'utf8',windowsHide:true});if(result.status!==0)throw Error('Ephemeral test key generation failed.');
 const secret=fs.readFileSync(key,'utf8').trim(),config=JSON.parse(fs.readFileSync(configFile,'utf8'));
 config.plugins.updater.pubkey=fs.readFileSync(key+'.pub','utf8').trim();fs.writeFileSync(configFile,JSON.stringify(config,null,2)+'\n');
 const delimiter='AEGIS_'+crypto.randomBytes(16).toString('hex');console.log('::add-mask::'+secret);fs.appendFileSync(process.env.GITHUB_ENV,'TAURI_SIGNING_PRIVATE_KEY<<'+delimiter+'\n'+secret+'\n'+delimiter+'\nTAURI_SIGNING_PRIVATE_KEY_PASSWORD=\n');
 console.log('Pull request validation uses an ephemeral key. These test artifacts cannot be published by the release job.');
}
