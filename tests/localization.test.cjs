const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {languages,resolveLocale,translate,validateSettings}=require('../electron/localization.cjs');
const {Store,parseState}=require('../electron/store.cjs'),{renderReport}=require('../electron/report.cjs');
const en=require('../locales/en.json');
const tokens=value=>[...value.matchAll(/\{\w+\}/g)].map(m=>m[0]).sort();
test('all ten locales have complete catalogs with matching interpolation tokens',()=>{
 assert.equal(languages.length,10);assert.ok(Object.keys(en).length>=340);
 for(const locale of languages.filter(l=>l!=='pt-BR')){const data=require('../locales/'+locale+'.json');assert.deepEqual(Object.keys(data).sort(),Object.keys(en).sort());for(const [source,value]of Object.entries(data)){assert.ok(typeof value==='string'&&value.trim(),locale+': '+source);assert.deepEqual(tokens(value),tokens(source),locale+': '+source);}}
});
test('locale resolution supports system selection, language variants and English fallback',()=>{assert.equal(resolveLocale('system','pt-PT'),'pt-BR');assert.equal(resolveLocale('system','zh-TW'),'zh-CN');assert.equal(resolveLocale('system','es-MX'),'es');assert.equal(resolveLocale('system','unsupported'),'en');assert.equal(resolveLocale('ar'),'ar');});
test('translations interpolate values without rewriting literal paths or original system output',()=>{assert.equal(translate('Remover perfil {name}','en',{name:'<untrusted>.conf'}),'Remove profile <untrusted>.conf');assert.equal(translate('C:\\original\\trace.txt','ja'),'C:\\original\\trace.txt');assert.equal(translate('Visão geral','pt-BR'),'Visão geral');});
test('settings reject malformed locales and preserve the boolean-only toggles',()=>{for(const payload of [null,[],{language:'../../secrets'},{language:true},{liveNetwork:'yes'},{reducedMotion:1},{unknown:true}])assert.throws(()=>validateSettings(payload));assert.deepEqual(validateSettings({language:'ar',reducedMotion:true}),{language:'ar',reducedMotion:true});});
test('language preference persists and legacy state migrates without losing data',()=>{
 const parent=path.resolve(__dirname,'..','.aegis-test','locales');fs.mkdirSync(parent,{recursive:true});const dir=fs.mkdtempSync(path.join(parent,'case-'));
 try{const store=new Store(dir);store.state.settings.language='de';store.event('test','keep');const restored=new Store(dir);assert.equal(restored.state.settings.language,'de');assert.equal(restored.state.history[0].title,'keep');const legacy=structuredClone(restored.state);delete legacy.settings.language;assert.equal(parseState(JSON.stringify(legacy)).settings.language,'system');legacy.settings.language='invalid';assert.throws(()=>parseState(JSON.stringify(legacy)));}finally{assert.ok(dir.startsWith(parent+path.sep));fs.rmSync(dir,{recursive:true,force:true});}
});
test('localized reports retain original evidence and escape untrusted values',()=>{
 const state={settings:{language:'ar'},audits:[{system:{os:'Windows'},checks:[{title:'Integridade da memória',status:'unknown',evidence:'<script>unsafe</script>',recommendation:'original system guidance'}]}],scans:[],history:[{at:'now',title:'<img src=x>',detail:'" & <'}]};
 const html=renderReport(state,{now:new Date('2026-10-27T00:00:00Z')});assert.match(html,/<html lang="ar" dir="rtl">/);assert.ok(html.includes(translate('Integridade da memória','ar')));assert.ok(html.includes('&lt;script&gt;'));assert.ok(!html.includes('<script>'));assert.ok(html.includes('original system guidance'));assert.ok(html.includes('default-src'));
});
