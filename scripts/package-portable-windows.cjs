const fs=require('node:fs/promises'),path=require('node:path'),{execFileSync}=require('node:child_process');
(async()=>{
 if(process.platform!=='win32'||process.env.CI!=='true')throw Error('Portable packaging is restricted to isolated Windows CI.');
 const root=path.resolve(__dirname,'..'),build=path.join(root,'.build'),payload=JSON.parse(await fs.readFile(path.join(build,'installed-payload.json'),'utf8'));
 const executable=await fs.realpath(payload.executable),source=path.dirname(executable),base=await fs.realpath(build);
 const relative=path.relative(base,source);if(!relative||relative.startsWith('..')||path.isAbsolute(relative))throw Error('Portable source escaped the verified MSI extraction.');
 const version=require('../package.json').version,name=`Aegis_${version}_windows_x64_portable`,folder=path.join(build,'portable',name),zip=path.join(build,'portable',name+'.zip');
 await fs.mkdir(path.dirname(folder),{recursive:true});await fs.mkdir(folder,{recursive:false});
 await fs.copyFile(executable,path.join(folder,'aegis-desktop.exe'));await fs.cp(path.join(source,'engines'),path.join(folder,'engines'),{recursive:true});
 for(const file of ['THIRD-PARTY-NOTICES.txt','UI-LICENSES.txt','RUST-LICENSES.txt'])await fs.copyFile(path.join(root,'docs',file),path.join(folder,file));
 await fs.writeFile(path.join(folder,'aegis-portable.json'),'{"format":1}\n');
 await fs.writeFile(path.join(folder,'README.txt'),`Aegis ${version} - Windows x64, no installer\r\n\r\nExtract the entire ZIP and open aegis-desktop.exe. Keep the engines folder beside it.\r\nThe Windows WebView2 system runtime is required. Settings and scan history use your Windows user profile, as in the installed application.\r\nThis package does not register an uninstaller or Start menu entry. WireGuard/firewall actions still require explicit OS authorization.\r\nUpdate this folder using a new portable ZIP; in-place installer updates are disabled in this mode.\r\nThe application currently has no trusted Authenticode publisher signature. Do not disable device security policies.\r\n`);
 execFileSync(process.execPath,[path.join(root,'scripts/check-runtimes.cjs')],{stdio:'inherit',windowsHide:true,env:{...process.env,AEGIS_CHECK_RESOURCES:path.join(folder,'engines')}});
 execFileSync(process.execPath,[path.join(root,'scripts/test-native-windows.cjs'),path.join(folder,'aegis-desktop.exe')],{stdio:'inherit',windowsHide:true,timeout:300000});
 const command='Compress-Archive -LiteralPath $env:AEGIS_PORTABLE_SOURCE -DestinationPath $env:AEGIS_PORTABLE_ZIP -Force';
 execFileSync(path.join(process.env.SystemRoot,'System32/WindowsPowerShell/v1.0/powershell.exe'),['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(command,'utf16le').toString('base64')],{stdio:'inherit',windowsHide:true,timeout:180000,env:{...process.env,AEGIS_PORTABLE_SOURCE:folder,AEGIS_PORTABLE_ZIP:zip}});
 console.log('PASS: no-install Windows package has working engines and a fresh native UI diagnostic. ZIP: '+zip);
})().catch(error=>{console.error(error.message);process.exitCode=1});
