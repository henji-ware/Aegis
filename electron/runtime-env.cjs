'use strict';
const path=require('node:path');
function runtimeEnv(kind,resources,platform=process.platform,base=process.env){
 const env={...base},root=path.join(resources,kind);
 if(platform==='linux')env.LD_LIBRARY_PATH=[root,path.join(root,'tor'),path.join(root,'lib'),path.join(root,'lib64'),path.join(root,'usr','local','lib'),env.LD_LIBRARY_PATH].filter(Boolean).join(':');
 if(platform==='darwin')env.DYLD_LIBRARY_PATH=[root,path.join(root,'tor'),path.join(root,'lib'),path.join(root,'lib64'),env.DYLD_LIBRARY_PATH].filter(Boolean).join(':');
 return env;
}
module.exports={runtimeEnv};
