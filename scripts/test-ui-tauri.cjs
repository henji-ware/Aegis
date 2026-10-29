const path = require('node:path'), fs = require('node:fs'), assert = require('node:assert/strict'), crypto = require('node:crypto'), { spawn } = require('node:child_process');
const { chromium } = require(process.env.AEGIS_PLAYWRIGHT_MODULE || 'playwright');
(async () => {
    const root = path.resolve(__dirname, '..'), shots = path.join(root, '.aegis-test', 'screens-040');
    fs.mkdirSync(shots, { recursive: true });
    const server = spawn(process.execPath, [path.join(root, 'node_modules/vite/bin/vite.js'), 'preview', '--host', '127.0.0.1', '--port', '5180'], { cwd: root, windowsHide: true, stdio: 'ignore' });
    let browser;
    try {
        for (let i = 0; i < 100; i++) {
            try {
                if ((await fetch('http://127.0.0.1:5180')).ok)
                    break;
            }
            catch { }
            await new Promise(r => setTimeout(r, 100));
        }
        browser = await chromium.launch({ headless: true, args: process.env.AEGIS_TEST_NO_SANDBOX === '1' ? ['--no-sandbox', '--disable-gpu'] : [] });
        const page = await browser.newPage({ viewport: { width: 1440, height: 960 }, deviceScaleFactor: 1 });
        const errors = [];
        page.on('pageerror', e => errors.push(e.message));
        await page.addInitScript(() => {
            const subscribers = new Set(); const isolated=[];let didInstall=false,pendingScan=null;
const emit=data=>{for(const callback of subscribers)callback({type:'antivirus',data});};
            let failUpdates = false,analysisMode="normal";
            const settings = { onboardingDone:localStorage.getItem('setup')!=='1',autoDefinitions:false,background:false,schedule:{enabled:false,hour:20,minute:0,frequency:'daily',type:'quick',catchUp:true}, reducedMotion: false, liveNetwork: false, language: localStorage.getItem('language') || 'en' };
            const audit = { id: 'audit-1', at: new Date().toISOString(), system: { os: 'Windows' }, counts: { pass: 1, warning: 0, review: 1, unknown: 1 }, checks: [{ id: 'app-control', title: 'Controle de aplicativos do Windows', status: 'pass', evidence: 'Smart App Control: ativado (imposição).', recommendation: 'Aplicativos sem confiança ou assinatura podem ser bloqueados.' }, { id: 'listeners', title: 'Serviços em escuta na rede', status: 'review', evidence: '5 sockets TCP em endereços que não são loopback.', recommendation: 'Confirme se cada serviço é necessário.', action: 'network' }, { id: 'vbs', title: 'Segurança baseada em virtualização', status: 'unknown', evidence: 'Consulta não permitida.', recommendation: 'Confira o sistema.' }] };
            const system = { platform: 'win32', release: '11', architecture: 'x86_64', hostname: 'Aegis local', os: 'Windows', memory: 17179869184, cpus: 8, interfaces: [] };
            const rows = Array.from({ length: 16 }, (_, i) => ({ id: 'process-' + i, protocol: 'TCP', localAddress: i % 4 === 0 ? '0.0.0.0' : '127.0.0.1', localPort: 8000 + i, remoteAddress: '203.0.113.' + (i + 1), remotePort: 443, state: i % 4 === 0 ? 'Listen' : 'Established', pid: 200 + i, process: i === 0 ? 'Browser' : 'Application ' + i }));
            const history = [{ id: 'a', at: new Date().toISOString(), type: 'audit', title: 'Diagnóstico concluído', detail: { pass: 1, unknown: 1 }, status: 'success' }, { id: 'b', at: new Date().toISOString(), type: 'antivirus', title: 'Varredura rápida', detail: '0 detecções; 40 arquivos verificados.', status: 'success' }, { id: 'c', at: new Date().toISOString(), type: 'firewall', title: 'Porta TCP 445 bloqueada', detail: 'Regra de entrada criada pelo Aegis.', status: 'success' }];
            const av = { engine: 'ClamAV', installed: true, updaterAvailable: true, version: 'ClamAV 1.5.4', runnable: true, signatures: { ready: true, updatedAt: new Date().toISOString(), count: 9000000, files: [] }, job: { id: 's', type: 'quick', state: 'completed', startedAt: new Date().toISOString(), lines: [], summary: { scanned: 40, infected: 0, errors: 0, limited: false, threats: [] } }, scans: [], realtime: false };
            const vpn = { installed: true, secureStorage: true, profiles: [{ id: 'p', name: 'Local VPN', meta: { endpoint: 'vpn.example:51820', addresses: [], fullTunnel: true, ipv6: false, dns: ['1.1.1.1'] } }], active: null, verification: 'A interface ativa não confirma handshake recente, rotas, DNS ou ausência de vazamentos.' };
            window.__aegisTest = { partialScan:()=>{av.job={id:'partial-fixture',type:'quick',state:'partial',startedAt:new Date().toISOString(),lines:['Original engine evidence'],progress:{phase:'scan',processed:25,total:28,percent:89,current:'C:/fixture/locked.txt'},summary:{scanned:25,infected:0,errors:3,limited:false,partial:true,threats:[],issues:[{path:'C:/fixture/locked.txt',kind:'permission',detail:'Permission denied'},{path:'C:/fixture/gone.txt',kind:'missing',detail:'No such file'}]}};emit(av.job);},
analysisMode:value=>{analysisMode=value;},liveConnections:()=>{for(const callback of subscribers)callback({type:'connections',data:rows.slice(0,2)});},largeScan:()=>{av.job={id:'size-fixture',type:'custom',state:'partial',startedAt:new Date().toISOString(),lines:[],progress:{phase:'empty',processed:0,total:0,percent:null},summary:{scanned:0,infected:0,errors:0,sizeLimited:1,limited:true,partial:true,threats:[],issues:[{path:'C:/fixture/large-video.mkv',kind:'size',bytes:3*1024**3,limit:2147483647,detail:'File was not scanned: supported engine size exceeded.'}]}};emit(av.job);},seedQuarantine:()=>{isolated.splice(0,isolated.length,...Array.from({length:36},(_,i)=>({id:'q-'+i,name:'sample-'+i+'.txt',original:'C:/fixture/sample-'+i+'.txt',detection:'Local.Test.Signature',state:'isolated',at:new Date().toISOString()})));},detectedScan:()=>{av.job={id:'detected-fixture',type:'custom',state:'threats',startedAt:new Date().toISOString(),lines:[],progress:{phase:'scan',processed:1,total:1,percent:100},summary:{scanned:1,infected:1,errors:0,limited:false,partial:false,threats:[{path:'C:/fixture/test.txt',name:'Local.Test.Signature'}]}};emit(av.job);},getSettings:()=>settings,didInstall:()=>didInstall,
finishUpdate: () => { av.job = { ...av.job, state: 'completed' }; for (const callback of subscribers)
                    callback({ type: 'antivirus', data: av.job }); }, failUpdates: () => { failUpdates = true; }, setUnconfirmedVpn: () => { vpn.active = { id: 'p', name: 'Local VPN', tunnel: 'aegis-test', interfaceActive: null, present: null, pending: true }; } };
            window.aegis = { call: async (method, payload) => { switch (method) {
                    case 'bootstrap': return { system, settings, history, latestAudit: audit, version: '1.0.0' };
                    case 'settings':
                        Object.assign(settings, payload);
                        localStorage.setItem('language', settings.language);
                        return { ...settings };
                    case 'history': return { events: history, audits: [audit], scans: [] };
                    case 'startup:status':return{enabled:false};
case 'startup:set':return{enabled:payload.enabled};
case 'automation:status':return{settings,state:{},folder:null,monitor:{checkedAt:new Date().toISOString()},events:[]};
case 'automation:folder':return{settings,state:{},folder:'C:/fixture'};
case 'quarantine:list':return structuredClone(isolated);
case 'quarantine:add':isolated.push({id:'isolated-fixture',name:'test.txt',original:'C:/fixture/test.txt',detection:'Local.Test.Signature',state:'isolated',at:new Date().toISOString()});return structuredClone(isolated);
case 'quarantine:restore':isolated.find(item=>item.id===payload.id).state='restored';return structuredClone(isolated);
case 'update:check':return{available:true,version:'1.0.1'};
case 'update:install':didInstall=true;return true;
case 'vpn:diagnose':return{checks:{tunnel:'pass',route:'pass',dns:'unknown'},evidence:{source:'fixture'},killSwitch:{supported:false,configured:false}};
case 'vpn:public-ip':return{ip:'203.0.113.99'};
case 'av:status': return av;
                    case 'av:scan':av.job={id:'inventory-fixture',type:'full',state:'preparing',startedAt:new Date().toISOString(),lines:[],progress:{phase:'inventory',discovered:50,processed:0,total:null,percent:null}};emit(av.job);return new Promise(resolve=>pendingScan=resolve);
                    case 'av:cancel':av.job={...av.job,state:'cancelled'};emit(av.job);pendingScan?.(av.job);pendingScan=null;return true;
                    case 'connections': return rows;
                    case 'connections:analyse': await new Promise(resolve=>setTimeout(resolve,180));if(analysisMode==='error')throw Error('Connection inspection fixture failed');if(analysisMode==='empty')return[];if(analysisMode==='unknown')return rows.filter(row=>row.state==='Established').slice(0,3).map(row=>({...row,analysis:{level:'unknown',signals:[],path:null,signature:null,inspected:false,token:null,at:new Date().toISOString()}}));return rows.map(r => ({ ...r, analysis: { level: r.state === 'Listen' ? 'review' : 'no-signals', signals: r.state === 'Listen' ? ['listener'] : [], path: 'C:\\Program Files\\Application\\app.exe', signature: null, inspected: true, token: 'test', at: new Date().toISOString() } }));
                    case 'firewall:status': return { platform: 'win32', native: { backend: 'Windows Firewall', supported: true, profiles: [{ Name: 'Private', Enabled: true, DefaultInboundAction: 4 }] }, rules: [], canRestore: false };
                    case 'vpn:status': return vpn;
                    case 'tor:status': return { installed: true, state: 'stopped', progress: 0, port: null, lines: [] };
                    case 'audit': return audit;
                    case 'av:update':
                        if (failUpdates)
                            throw Error('Mensagem técnica original do sistema');
                        av.job = { id: 'update-test', type: 'update', state: 'running', startedAt: new Date().toISOString(), lines: [] };
                        return { ...av.job };
                    default: throw Error('Operation not mocked: ' + method);
                } }, onEvent: callback => { subscribers.add(callback); return () => subscribers.delete(callback); } };
        });
        await page.goto('http://127.0.0.1:5180');
        await page.getByRole('heading', { name: 'Overview', exact: true }).waitFor();
        assert.equal(await page.locator('.sidebar>.brand').innerText(), '');
        assert.ok(!(await page.locator('.sidebar').innerText()).includes('Aegis'));
        const locales = ['pt-BR', 'en', 'es', 'fr', 'de', 'ru', 'zh-CN', 'ja', 'ar', 'hi'];
        const sources = ['Visão geral', 'Diagnóstico', 'Antivírus', 'Conexões', 'Firewall', 'Privacidade', 'Atividade'];
        const tr = (source, locale) => locale === 'pt-BR' ? source : require('../locales/' + locale + '.json')[source] || source;
        const selectLanguage = async (locale) => { await page.locator('.sidebar-bottom>button').click(); const select = page.locator('.language-panel select'); assert.equal(await page.locator('.language-panel select').count(), 1, 'language control is only in preferences'); await select.selectOption(locale); await page.waitForFunction(value => document.documentElement.lang === value, locale); await page.locator('nav[aria-label]>button').first().click(); assert.equal(await page.locator('.topbar select').count(), 0); };
        for (const locale of locales) {
            await selectLanguage(locale);
            await page.waitForFunction(l => document.documentElement.lang === l, locale);
            assert.equal(await page.locator('html').getAttribute('dir'), locale === 'ar' ? 'rtl' : 'ltr');
            await page.locator('nav[aria-label]>button').first().click();
            assert.equal(await page.locator('.hero-caption>p').innerText(), tr('{count} verificação ainda precisa de confirmação.', locale).replace('{count}', '1'));
            const graphColumns=await page.locator('.hero-stage .graph-head>span').evaluateAll(nodes=>nodes.map(node=>node.getBoundingClientRect().x));assert.ok(graphColumns[0]<graphColumns[1],'application heading must stay over the process nodes, including RTL locales');
            for (let i = 0; i < sources.length; i++) {
                await page.locator('nav[aria-label]>button').nth(i).click();
                assert.equal(await page.locator('h1').innerText(), tr(sources[i], locale));
                if (i === 1) {
                    await page.locator('.check-row').first().click();
                    assert.equal(await page.locator('.detail-modal>p').first().innerText(), tr('Atendido', locale));
                    assert.ok(!(await page.locator('.detail-modal').innerText()).includes('ativado (imposição)'));
                    await page.locator('.detail-modal .icon-button').click();
                }
                if (i === 2) {
                    assert.equal(await page.locator('.scan-job .overline').innerText(), tr(locale === 'pt-BR' ? 'VARREDURA' : 'ASSINATURAS', locale));
                    await page.getByRole('button', { name: tr('Atualizar assinaturas', locale), exact: true }).click();
                    await page.getByRole('button', { name: tr('Atualizando assinaturas', locale), exact: true }).waitFor();
                    await page.evaluate(() => window.__aegisTest.finishUpdate());
                    await page.getByRole('button', { name: tr('Atualizar assinaturas', locale), exact: true }).waitFor();
                }
                if (i === 3) {
                    await page.getByRole('button', { name: tr('Analisar conexões', locale), exact: true }).click();
                    await page.getByRole('button', { name: tr('Analisar conexões', locale), exact: true }).waitFor();
                    await page.locator('.network-table tbody tr').first().locator('td').last().getByRole('button').click();
                    assert.ok((await page.locator('.detail-modal').innerText()).includes(tr('Serviço em escuta fora do loopback. Revise a necessidade e as regras do firewall.', locale)));
                    await page.locator('.detail-modal .icon-button').click();
                }
                if (i === 6) {
                    assert.equal(await page.locator('.event-row strong').first().innerText(), tr('Diagnóstico concluído', locale));
                    assert.ok(!(await page.locator('.event-list').innerText()).includes('0 detecções;'));
                }
            }
            await page.locator('.sidebar-bottom>button').click();
            assert.equal(await page.locator('h1').innerText(), tr('Preferências', locale));
            await page.locator('nav[aria-label]>button').first().click();
            assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 2), 'overflow ' + locale);
            if (['en', 'pt-BR', 'ar'].includes(locale)) {
                await page.locator('canvas[data-visual="connections"]').waitFor();
                await page.waitForTimeout(300);
                await page.screenshot({ path: path.join(shots, locale + '.png'), fullPage: true });
            }
        }
        await selectLanguage('en');
        await page.evaluate(() => window.__aegisTest.setUnconfirmedVpn());
        await page.locator('nav[aria-label]>button').nth(5).click();
        await page.getByRole('button', { name: 'Refresh status', exact: true }).click();
        await page.locator('nav[aria-label]>button').first().click();
        assert.equal(await page.locator('.module-card').nth(2).locator('strong').innerText(), tr('Ativação não confirmada', 'en'));
        assert.equal(await page.locator('.module-card').nth(2).locator('.badge').innerText(), tr('Revisar', 'en'));
        const canvas = page.locator('.hero-stage .connection-graph canvas');
        const before = await canvas.screenshot();
        await page.waitForTimeout(350);
        assert.ok(before.equals(await canvas.screenshot()), 'observed graph stays stable without input');
        const hero = page.locator('[data-parallax="hero"]'), rect = await hero.boundingBox();
        await page.mouse.move(rect.x + rect.width * .8, rect.y + rect.height * .25);
        await page.waitForTimeout(200);
        assert.notEqual(await hero.evaluate(e => e.style.getPropertyValue('--px')), '0');
assert.ok(!before.equals(await canvas.screenshot()),'graph responds to pointer parallax');
        await page.locator('.sidebar-bottom>button').click();
        await page.getByRole('switch', { name: 'Reduce motion', exact: true }).click();
        await page.locator('nav[aria-label]>button').first().click();
        await page.waitForTimeout(350);
        const fixed = await canvas.screenshot();
        await page.waitForTimeout(300);
        assert.ok(fixed.equals(await canvas.screenshot()), 'reduced motion must freeze');
        await canvas.evaluate(el => el.dispatchEvent(new Event('webglcontextlost', { cancelable: true })));
        await page.locator('.hero-stage .graph-fallback').waitFor();assert.ok(await page.locator('.hero-stage .graph-fallback button').count()>0,'fallback preserves real application selection');
        await page.locator('nav[aria-label]>button').nth(3).click();
        await page.getByRole('button',{name:'Analyze connections',exact:true}).click();await page.getByRole('button',{name:'Analyzing connections…',exact:true}).waitFor();
        const review=page.locator('.network-review');await review.locator('.analysis-counts').waitFor();await page.getByRole('button',{name:'Analyze connections',exact:true}).waitFor();
        assert.equal(await page.locator('.network-table tbody tr').count(),16);assert.equal(await review.locator('.analysis-counts strong').first().innerText(),'16');
        await page.evaluate(()=>window.__aegisTest.liveConnections());assert.equal(await page.locator('.network-table tbody tr').count(),16,'live polling must not erase analysis');
        await review.locator('.analysis-counts button').nth(1).click();assert.equal(await page.locator('.network-table tbody tr').count(),4);assert.equal(await page.locator('.analysis-reason').first().innerText(),tr('Serviço em escuta fora do loopback. Revise a necessidade e as regras do firewall.','en'));
        await review.locator('.analysis-counts button').first().click();await page.screenshot({path:path.join(shots,'connection-results-en.png'),fullPage:true});
        await review.getByRole('button',{name:'Live connections',exact:true}).click();assert.equal(await page.locator('.network-table tbody tr').count(),2);await review.getByRole('button',{name:'View analysis results',exact:true}).click();assert.equal(await page.locator('.network-table tbody tr').count(),16);
        await page.evaluate(()=>window.__aegisTest.analysisMode('error'));await page.getByRole('button',{name:'Analyze connections',exact:true}).click();await review.locator('.analysis-error').waitFor();assert.equal(await page.locator('.network-table tbody tr').count(),16,'failed reanalysis retains the previous completed snapshot');
        await page.evaluate(()=>window.__aegisTest.analysisMode('unknown'));await page.getByRole('button',{name:'Analyze connections',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.network-table tbody tr').length===3);assert.equal(await review.locator('.analysis-counts strong').nth(3).innerText(),'3');assert.ok((await page.locator('.network-table').innerText()).includes('Not verified'));
        await page.evaluate(()=>window.__aegisTest.analysisMode('empty'));await page.getByRole('button',{name:'Analyze connections',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.network-table tbody tr').length===0);assert.equal(await review.locator('.analysis-counts strong').first().innerText(),'0');
        await page.evaluate(()=>window.__aegisTest.analysisMode('normal'));await page.getByRole('button',{name:'Analyze connections',exact:true}).click();await page.waitForFunction(()=>document.querySelectorAll('.network-table tbody tr').length===16);
        await page.locator('nav[aria-label]>button').nth(2).click();await page.evaluate(()=>window.__aegisTest.largeScan());await page.getByText('File exceeds the engine size limit',{exact:true}).waitFor();assert.ok((await page.locator('.scan-issues').innerText()).includes('2 GiB'));assert.equal(await page.locator('.scan-statistics>div').nth(2).locator('strong').innerText(),'0');assert.equal(await page.locator('.scan-statistics>div').nth(3).locator('strong').innerText(),'1');assert.equal(await page.getByRole('button',{name:'Isolate file',exact:true}).count(),0);await page.screenshot({path:path.join(shots,'size-limit-en.png'),fullPage:true});await page.evaluate(()=>window.__aegisTest.finishUpdate());
        await page.locator('nav[aria-label]>button').nth(2).click();
        await page.locator('.scan-option').nth(1).click();await page.getByRole('button',{name:'Stop',exact:true}).waitFor();assert.equal(await page.getByRole('button',{name:'Stop',exact:true}).isEnabled(),true,'inventory cancellation bypasses the pending start call');await page.getByRole('button',{name:'Stop',exact:true}).click();await page.locator('.scan-job h3').filter({hasText:'Stopped'}).waitFor();
        await page.evaluate(()=>window.__aegisTest.partialScan());await page.locator('.scan-job progress[value="89"]').waitFor();
assert.equal(await page.locator('.scan-explanation').count(),1,'partial warning is not duplicated');assert.ok((await page.locator('.scan-issues').innerText()).includes('C:/fixture/locked.txt'));
assert.ok((await page.locator('.scan-issues').innerText()).includes('Read permission denied'));
await page.screenshot({path:path.join(shots,'scan-errors-en.png'),fullPage:true});
await page.evaluate(()=>window.__aegisTest.detectedScan());await page.getByRole('button',{name:'Isolate file',exact:true}).click();await page.getByRole('button',{name:'Restore file',exact:true}).click();await page.locator('.quarantine-row small').filter({hasText:'Restored'}).waitFor();
await page.evaluate(()=>window.__aegisTest.seedQuarantine());await page.locator('.feature-panel').filter({has:page.getByRole('heading',{name:'Quarantine',exact:true})}).getByRole('button',{name:'Refresh',exact:true}).click();await page.locator('.quarantine-row').filter({hasText:'sample-35.txt'}).getByRole('button',{name:'Restore file',exact:true}).click();await page.locator('.quarantine-row').filter({hasText:'sample-35.txt'}).locator('small').filter({hasText:'Restored'}).waitFor();
await page.locator('.sidebar-bottom>button').click();await page.getByRole('checkbox',{name:'Schedule a scan',exact:true}).check();await page.locator('input[type="time"]').fill('23:42');
await page.getByRole('checkbox',{name:/Start with the system/}).check();
await page.locator('.feature-fields select').first().selectOption('weekly');await page.locator('.feature-fields select').nth(1).selectOption('5');
await page.getByRole('button',{name:'Save schedule',exact:true}).click();assert.equal((await page.evaluate(()=>window.__aegisTest.getSettings())).schedule.hour,23);assert.equal((await page.evaluate(()=>window.__aegisTest.getSettings())).schedule.weekday,5);
await page.getByRole('button',{name:'Check for updates',exact:true}).click();await page.getByRole('button',{name:'Install and restart',exact:true}).click();assert.equal(await page.evaluate(()=>window.__aegisTest.didInstall()),true);
await page.locator('nav[aria-label]>button').nth(5).click();await page.getByRole('button',{name:'Check connection',exact:true}).click();assert.ok((await page.locator('.vpn-checks').innerText()).includes('Routes'));await page.getByRole('button',{name:'Check public IP with permission',exact:true}).click();await page.getByText('203.0.113.99',{exact:true}).waitFor();
for(const viewport of [{width:1440,height:960},{width:1080,height:800}]){await page.setViewportSize(viewport);for(let screen=0;screen<7;screen++){await page.locator('nav[aria-label]>button').nth(screen).click();assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2),'screen overflow '+screen);assert.equal(await page.locator('.integration-card,.open-source-panel').count(),0);}assert.equal(await page.locator('.sidebar .local-card,.sidebar .version-line').count(),0);}
await page.setViewportSize({width:1440,height:960});await page.locator('nav[aria-label]>button').nth(2).click();
await page.evaluate(() => window.__aegisTest.failUpdates());
        await page.getByRole('button', { name: 'Update definitions', exact: true }).click();
        await page.getByText('The operation could not be completed.', { exact: true }).waitFor();
        assert.ok(!(await page.locator('.toast').innerText()).includes('Mensagem técnica'));
        await selectLanguage('de');
        await page.reload();
        await page.getByRole('heading', { name: 'Übersicht', exact: true }).waitFor();
        assert.deepEqual(errors, []);
        console.log('PASS: visible connection reports, preserved snapshots after live updates, review/unknown/empty/error states, explicit oversized-file exclusions, inventory progress and file-level issues, nonduplicated warnings, quarantine/restore, schedule persistence, signed-update UI, explicit public-IP request, clean sidebar, real graph, 1080/1440 layouts, settings-only language switching, 10 locales × 8 screens, singular diagnostic messages, localized running definition updates and native completion events, unconfirmed VPN overview state, diagnostic/legacy history/connection details, errors, RTL, no overflow, connection graph, parallax, reduced motion, WebGL fallback and persisted settings. UI uses mocked native transport; no OS settings changed.');
    }
    finally {
        if (browser)
            await browser.close();
        server.kill();
    }
})().catch(e => { console.error(e); process.exitCode = 1; });
