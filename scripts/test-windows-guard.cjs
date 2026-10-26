const path=require('node:path'),assert=require('node:assert/strict');
const {_electron}=require(process.env.AEGIS_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const root=path.resolve(__dirname,'..'),env={...process.env,AEGIS_DATA_DIR:path.join(root,'.aegis-test','guard-021')};delete env.ELECTRON_RUN_AS_NODE;
 const app=await _electron.launch({executablePath:require('electron'),args:[...(process.env.AEGIS_TEST_NO_SANDBOX==='1'?['--no-sandbox','--disable-gpu']:[]),root],env,timeout:45000});
 try{
  const page=await app.firstWindow(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.waitForSelector('h1');
  const result=await page.evaluate(()=>window.aegis.call('audit'));
  for(const id of ['app-control','vbs','memory-integrity'])assert.ok(result.checks.some(c=>c.id===id));
  assert.equal(Object.values(result.counts).reduce((a,b)=>a+b,0),result.checks.length);
  await page.getByRole('button',{name:'Diagnóstico',exact:true}).click();
  await page.getByText('Controle de aplicativos do Windows',{exact:true}).waitFor();
  await page.getByText('Integridade da memória',{exact:true}).waitFor();
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({guard:result.checks.filter(c=>['app-control','vbs','memory-integrity'].includes(c.id)),uiErrors:errors}));
 }finally{await app.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
