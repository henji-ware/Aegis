const{_electron}=require(process.env.AEGIS_PLAYWRIGHT_MODULE||'playwright'),path=require('node:path'),assert=require('node:assert/strict');
(async()=>{
 const root=path.resolve(__dirname,'..'),env={...process.env,AEGIS_DATA_DIR:path.join(root,'.aegis-test','effects')};delete env.ELECTRON_RUN_AS_NODE;
 const app=await _electron.launch({executablePath:require('electron'),args:[...(process.env.AEGIS_TEST_NO_SANDBOX==='1'?['--no-sandbox','--disable-gpu']:[]),root],env,timeout:45000});
 try{
  const page=await app.firstWindow(),errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.waitForSelector('h1');assert.equal(await page.locator('h1').textContent(),'Visão geral'); await page.waitForFunction(()=>document.querySelector('.device-sub')?.textContent?.includes('Windows')); await page.getByRole('button',{name:'Preferências',exact:true}).click(); const initialMotion=page.getByRole('switch',{name:'Reduzir movimento'}); if(await initialMotion.getAttribute('aria-checked')==='true')await initialMotion.click(); await page.waitForFunction(()=>document.documentElement.dataset.motion==='full'); await page.getByRole('button',{name:'Visão geral',exact:true}).click();
  for(const phrase of ['Segurança em perspectiva','Observe. Entenda','Seu caminho. Suas regras','Um olhar mais profundo'])assert.ok(!(await page.locator('body').innerText()).includes(phrase));
  const hero=page.locator('[data-parallax="hero"]'),rect=await hero.boundingBox();
  await page.mouse.move(rect.x+rect.width*.85,rect.y+rect.height*.3);await page.waitForTimeout(200);
  assert.notEqual(await hero.evaluate(el=>el.style.getPropertyValue('--px')),'0');
  const card=page.locator('[data-parallax="card"]').first(),box=await card.boundingBox();
  await page.mouse.move(box.x+box.width*.8,box.y+box.height*.2);await page.waitForTimeout(250);
  assert.notEqual(await card.evaluate(el=>getComputedStyle(el).transform),'none');
  await page.getByRole('button',{name:'Preferências',exact:true}).click();const motion=page.getByRole('switch',{name:'Reduzir movimento'});
  if(await motion.getAttribute('aria-checked')!=='true')await motion.click();
  await page.waitForFunction(()=>document.documentElement.dataset.motion==='reduced');
  await page.getByRole('button',{name:'Visão geral',exact:true}).click();assert.equal(await page.locator('.hero-stage .orb').evaluate(el=>getComputedStyle(el).transform),'none');
  await page.keyboard.press('Control+k');await page.getByRole('textbox',{name:'Buscar área do aplicativo'}).fill('Antivírus');await page.keyboard.press('Enter');assert.equal(await page.locator('h1').textContent(),'Antivírus');
  await page.getByRole('button',{name:'Visão geral',exact:true}).click();
  await page.screenshot({path:path.join(root,'.aegis-test','ui-v020.png'),fullPage:true,scale:'css',mask:[page.locator('.posture-panel>h2')],maskColor:'#10161f'});
  assert.deepEqual(errors,[]);console.log('UI: plain labels, parallax, cards, reduced motion, keyboard navigation, no JS errors: PASS');
 }finally{await app.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});


