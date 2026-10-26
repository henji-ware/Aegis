const test=require('node:test'),assert=require('node:assert/strict'),path=require('node:path'),fs=require('node:fs/promises');
const {runtimeEnv}=require('../electron/runtime-env.cjs');
const {findClamRoots}=require('../scripts/prepare-runtimes.cjs');
test('native runtime paths include the bundled Tor libraries without losing environment',()=>{
 const resources=path.join(__dirname,'..','resources'),base={PATH:'keep',LD_LIBRARY_PATH:'/existing'};
 const env=runtimeEnv('tor',resources,'linux',base);
 assert.ok(env.LD_LIBRARY_PATH.includes(path.join(resources,'tor','tor')));assert.ok(env.LD_LIBRARY_PATH.endsWith(':/existing'));assert.equal(env.PATH,'keep');assert.deepEqual(base,{PATH:'keep',LD_LIBRARY_PATH:'/existing'});
 const mac=runtimeEnv('clamav',resources,'darwin',{DYLD_LIBRARY_PATH:'/existing'});assert.ok(mac.DYLD_LIBRARY_PATH.includes(path.join(resources,'clamav','lib64')));assert.ok(mac.DYLD_LIBRARY_PATH.endsWith(':/existing'));
 assert.deepEqual(runtimeEnv('tor',resources,'win32',{PATH:'keep'}),{PATH:'keep'});
});
test('ClamAV collector merges library and program payload roots from macOS product packages',async()=>{
 const base=path.resolve(__dirname,'..','.aegis-test','split-payload');await fs.mkdir(base,{recursive:true});const dir=await fs.mkdtemp(path.join(base,'case-'));
 try{
  const roots=['libraries.pkg','programs.pkg','documentation.pkg'].map(n=>path.join(dir,n,'Payload','usr','local','clamav'));
  await Promise.all(roots.map(r=>fs.mkdir(r,{recursive:true})));await fs.mkdir(path.join(roots[1],'bin'));await fs.writeFile(path.join(roots[1],'bin','clamscan'),'fixture');
  assert.deepEqual((await findClamRoots(dir)).sort(),roots.sort());
 }finally{assert.ok(dir.startsWith(base+path.sep));await fs.rm(dir,{recursive:true,force:true});}
});
