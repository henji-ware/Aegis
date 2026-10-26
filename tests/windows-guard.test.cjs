const test=require('node:test'),assert=require('node:assert/strict');
const {guardChecks,windowsGuardChecks}=require('../electron/windows-guard.cjs');
test('Windows guard separates enforcement, VBS and running memory integrity',()=>{
 const checks=guardChecks({sac:1,guard:{UsermodeCodeIntegrityPolicyEnforcementStatus:2,VirtualizationBasedSecurityStatus:2,SecurityServicesRunning:[1,2]}});
 assert.deepEqual(checks.map(c=>c.status),['pass','pass','pass']);
 const configured=guardChecks({sac:2,guard:{UsermodeCodeIntegrityPolicyEnforcementStatus:1,VirtualizationBasedSecurityStatus:1,SecurityServicesRunning:[1]}});
 assert.deepEqual(configured.map(c=>c.status),['review','review','review']);
 assert.match(configured[1].evidence,/sem execução/);
});
test('missing, denied and unexpected Windows guard values remain unknown',()=>{
 for(const data of [{},{sac:null,guard:{}},{sac:99,guard:{UsermodeCodeIntegrityPolicyEnforcementStatus:99,VirtualizationBasedSecurityStatus:99,SecurityServicesRunning:null}},{sac:'1',guard:{SecurityServicesRunning:['2']}}])assert.ok(guardChecks(data).every(c=>c.status==='unknown'));
 const partial=guardChecks({sac:1,guardError:'access denied'});assert.equal(partial[0].status,'pass');assert.equal(partial[2].status,'unknown');assert.match(partial[0].evidence,/access denied/);
 const off=guardChecks({sac:0,guard:{UsermodeCodeIntegrityPolicyEnforcementStatus:0,VirtualizationBasedSecurityStatus:0,SecurityServicesRunning:[0]}});assert.ok(off.every(c=>c.status==='review'));
});
test('Windows guard tolerates query failure and does not query other platforms',async()=>{
 assert.ok((await windowsGuardChecks({platform:'win32',query:async()=>{throw Error('denied')}})).every(c=>c.status==='unknown'));
 assert.deepEqual(await windowsGuardChecks({platform:'linux',query:async()=>{assert.fail('must not query')}}),[]);
});
