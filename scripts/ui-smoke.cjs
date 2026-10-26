const path=require('node:path');
const fs=require('node:fs');
const {_electron}=require(process.env.AEGIS_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
const root=path.resolve(__dirname,'..'),dataDir=path.join(root,'.aegis-test','ui');
const env={...process.env,AEGIS_DATA_DIR:dataDir};delete env.ELECTRON_RUN_AS_NODE;
const electron=await _electron.launch({executablePath:require('electron'),args:[...(process.env.AEGIS_TEST_NO_SANDBOX === '1' ? ['--no-sandbox','--disable-gpu'] : []),root],env,timeout:45000});
const page=await electron.firstWindow();const errors=[];page.on('pageerror',error=>errors.push(error.message));
await page.waitForSelector('h1',{timeout:30000});
await page.waitForFunction(()=>document.querySelector('.device-sub')?.textContent?.includes('Windows'),{timeout:30000});
await page.screenshot({path:path.join(root,'.aegis-test','overview.png'),fullPage:true});
console.log('TITLE',await page.title());
for(const label of ['Diagnóstico','Antivírus','Conexões','Firewall','Privacidade','Atividade','Preferências']){
 await page.getByRole('button',{name:label,exact:true}).first().click();
 await page.waitForTimeout(350);
 console.log('PAGE',label,await page.locator('h1').textContent());
 await page.screenshot({path:path.join(root,'.aegis-test',label.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase()+'.png'),fullPage:true});
}
await page.getByRole('button',{name:'Visão geral',exact:true}).click();
await page.getByRole('button',{name:'Verificar sistema',exact:true}).click();
await page.waitForFunction(()=>document.querySelector('.hero-caption h2')?.textContent?.includes('Verificação concluída'),{timeout:60000});
console.log('AUDIT',await page.locator('.hero-caption').innerText());
await page.screenshot({path:path.join(root,'.aegis-test','overview-audit.png'),fullPage:true});
console.log('ERRORS',JSON.stringify(errors));
const info=await page.evaluate(async()=>({av:await window.aegis.call('av:status'),vpn:await window.aegis.call('vpn:status'),tor:await window.aegis.call('tor:status')}));
console.log('ENGINES',JSON.stringify({av:info.av.installed,vpn:info.vpn.installed,tor:info.tor.installed}));
await electron.close();
if(errors.length)throw new Error(errors.join('\n'));
})().catch(error=>{console.error(error);process.exitCode=1;});





