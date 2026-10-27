const path=require('node:path'),fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {_electron}=require(process.env.AEGIS_PLAYWRIGHT_MODULE||'playwright');
const {Store}=require('../electron/store.cjs');
const {languages,translate}=require('../electron/localization.cjs');
(async()=>{
 const root=path.resolve(__dirname,'..'),data=path.join(root,'.aegis-test','ui-030'),shots=path.join(root,'.aegis-test','screens-030');fs.mkdirSync(shots,{recursive:true});const store=new Store(data);store.state.settings.language='en';store.state.settings.reducedMotion=false;store.save();
 const env={...process.env,AEGIS_DATA_DIR:data};delete env.ELECTRON_RUN_AS_NODE;
 async function launch(){return _electron.launch({executablePath:require('electron'),args:[...(process.env.AEGIS_TEST_NO_SANDBOX==='1'?['--no-sandbox','--disable-gpu']:[]),root],env,timeout:45000});}
 let app=await launch();const errors=[];
 try{
  let page=await app.firstWindow();page.on('pageerror',e=>errors.push(e.message));await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();await page.waitForFunction(()=>!!window.aegis);await page.locator('.device-sub').filter({hasText:'Windows'}).waitFor();
  // The native confirmation is always cancelled; no firewall operation is applied.
  await app.evaluate(({dialog})=>{dialog.showMessageBox=async(_window,options)=>{globalThis.aegisTestConfirmation=options;return {response:0};};});
  const labels=['Visão geral','Diagnóstico','Antivírus','Conexões','Firewall','Privacidade','Atividade'];
  for(const locale of languages){
   await page.locator('.topbar select').selectOption(locale);await page.waitForFunction(code=>document.documentElement.lang===code,locale);
   assert.equal(await page.locator('html').getAttribute('dir'),locale==='ar'?'rtl':'ltr');
   for(let i=0;i<labels.length;i++){await page.locator('nav[aria-label] > button').nth(i).click();assert.equal(await page.locator('h1').innerText(),translate(labels[i],locale));}
   await page.locator('.sidebar-bottom > button').click();assert.equal(await page.locator('h1').innerText(),translate('Preferências',locale));
   assert.equal(await page.locator('.language-panel select').inputValue(),locale);
   await page.locator('nav[aria-label] > button').first().click();
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),'horizontal overflow: '+locale);
   await page.evaluate(async()=>{try{await window.aegis.call('firewall:harden');throw Error('Unexpected permission');}catch(error){if(error.message==='Unexpected permission')throw error;}});
   const confirmation=await app.evaluate(()=>globalThis.aegisTestConfirmation);assert.equal(confirmation.title,translate('Reforçar firewall',locale));assert.equal(confirmation.buttons[0],translate('Cancelar',locale));assert.equal(confirmation.buttons[1],translate('Continuar',locale));assert.equal(confirmation.message,translate('Ativar o firewall e restringir novas conexões de entrada?',locale));
   if(['en','ar','pt-BR'].includes(locale))await page.screenshot({path:path.join(shots,locale+'.png'),fullPage:true,mask:[page.locator('.posture-panel>h2')],maskColor:'#13251a'});
  }
  await page.locator('.topbar select').selectOption('en');await page.getByRole('heading',{name:'Overview',exact:true}).waitFor();
  const hero=page.locator('[data-parallax="hero"]'),box=await hero.boundingBox();await page.mouse.move(box.x+box.width*.8,box.y+box.height*.3);await page.waitForTimeout(180);assert.notEqual(await hero.evaluate(el=>el.style.getPropertyValue('--px')),'0');
  const canvas=page.locator('.hero-stage .orb canvas');await canvas.waitFor();const before=await canvas.screenshot();await page.waitForTimeout(300);const after=await canvas.screenshot();assert.notEqual(crypto.createHash('sha256').update(before).digest('hex'),crypto.createHash('sha256').update(after).digest('hex'),'3D should animate');
  await page.locator('.sidebar-bottom > button').click();await page.getByRole('switch',{name:'Reduce motion',exact:true}).click();await page.waitForFunction(()=>document.documentElement.dataset.motion==='reduced');await page.locator('nav[aria-label] > button').first().click();assert.equal(await page.locator('.hero-stage .orb').evaluate(el=>getComputedStyle(el).transform),'none');
  const staticA=await canvas.screenshot();await page.waitForTimeout(250);const staticB=await canvas.screenshot();assert.ok(staticA.equals(staticB),'Reduced motion must stop continuous 3D rendering');
  await canvas.evaluate(el=>el.dispatchEvent(new Event('webglcontextlost',{cancelable:true})));await page.getByText('3D is unavailable. Use the connection list.',{exact:true}).waitFor();await page.locator('nav[aria-label] > button').nth(3).click();assert.equal(await page.locator('h1').innerText(),'Connections');
  await page.locator('.topbar select').selectOption('de');await page.waitForFunction(()=>document.documentElement.lang==='de');await app.close();app=await launch();page=await app.firstWindow();page.on('pageerror',e=>errors.push(e.message));await page.getByRole('heading',{name:'Übersicht',exact:true}).waitFor();assert.equal(await page.locator('.topbar select').inputValue(),'de');
  assert.deepEqual(errors,[]);console.log('PASS: 10 locales × 8 screens, RTL, native confirmation cancellation, persistence, no overflow, animated 3D, reduced-motion freeze, WebGL fallback, no JS errors');
 }finally{await app.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
