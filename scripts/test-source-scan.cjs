const path=require('node:path'),fs=require('node:fs'),assert=require('node:assert/strict');
const{_electron}=require(process.env.AEGIS_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const root=path.resolve(__dirname,'..'),release=process.env.AEGIS_PACKAGE_DIR||path.join(root,'release','Aegis-win32-x64'),data=path.join(root,'.aegis-test','source-scan-020'),fixture=path.join(root,'.aegis-test','benign-folder');
 fs.mkdirSync(path.join(data,'signatures'),{recursive:true});fs.mkdirSync(fixture,{recursive:true});fs.writeFileSync(path.join(fixture,'readme.txt'),'Aegis: harmless local test file. No threat or executable content.');
 for(const name of fs.readdirSync(path.join(root,'.aegis-test','engine','signatures')))if(/\.(cvd|cld|sign)$/.test(name))fs.copyFileSync(path.join(root,'.aegis-test','engine','signatures',name),path.join(data,'signatures',name));
 const env={...process.env,AEGIS_DATA_DIR:data};delete env.ELECTRON_RUN_AS_NODE;const localeStore=new (require('../electron/store.cjs').Store)(env.AEGIS_DATA_DIR);localeStore.state.settings.language='pt-BR';localeStore.save();
 const app=await _electron.launch({executablePath:require('electron'),args:[...(process.env.AEGIS_TEST_NO_SANDBOX==='1'?['--no-sandbox','--disable-gpu']:[]),root],env,timeout:45000});
 try{
  const page=await app.firstWindow(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.waitForSelector('h1');await page.waitForFunction(async()=>{try{return (await window.aegis.call('av:status')).signatures.ready;}catch{return false;}},{timeout:30000});
  const status=await page.evaluate(()=>window.aegis.call('av:status'));assert.equal(status.installed,true);assert.equal(status.signatures.ready,true);
  // Development test substitutes the file picker only, to restrict the scan to this benign test folder.
  await app.evaluate(({dialog},fixture)=>{dialog.showOpenDialog=async()=>({canceled:false,filePaths:[fixture]});},fixture);
  await page.getByRole('button',{name:'Antivírus',exact:true}).click();
  await page.getByRole('button',{name:/Personalizada/}).click();
  const scanId=await page.evaluate(async()=>{const status=await window.aegis.call('av:status');return status.job?.id;});assert.ok(scanId);
  await page.getByRole('button',{name:'Conexões',exact:true}).click();
  await page.getByRole('button',{name:'Visão geral',exact:true}).click();
  for(let attempt=0;attempt<90;attempt++){const current=await page.evaluate(()=>window.aegis.call('av:status')); if(current.job?.id===scanId&&!['running','cancelling'].includes(current.job.state))break; await new Promise(resolve=>setTimeout(resolve,1000));}
  const result=await page.evaluate(()=>window.aegis.call('av:status'));assert.equal(result.job.state,'completed');assert.equal(result.job.summary.scanned,1);assert.equal(result.job.summary.infected,0);
  console.log('SOURCE_REAL_SCAN',JSON.stringify(result.job.summary));
  await page.getByRole('button',{name:'Antivírus',exact:true}).click();
  await page.screenshot({path:path.join(root,'.aegis-test','antivirus-verified.png'),fullPage:true});
  await page.getByRole('button',{name:'Visão geral',exact:true}).click();
  await page.screenshot({path:path.join(root,'.aegis-test','packaged-overview.png'),fullPage:true});
  const illegal=await page.evaluate(async()=>{try{await window.aegis.call('not-allowed');return false;}catch{return true;}});assert.equal(illegal,true);
  const quarantineLeaks=await page.evaluate(async()=>JSON.stringify(await window.aegis.call('vpn:status')));assert.ok(!quarantineLeaks.includes('encrypted'));
  assert.equal(errors.length,0);console.log('UI_ERRORS',JSON.stringify(errors));
  if(process.env.AEGIS_PREVIEW_PATH)await page.screenshot({path:process.env.AEGIS_PREVIEW_PATH,fullPage:false,scale:'css'});
 }finally{await app.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});


