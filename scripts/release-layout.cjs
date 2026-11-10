const fs=require('node:fs/promises'),path=require('node:path'),{execFileSync}=require('node:child_process');
module.exports=async function compactRelease(out,version){
 const names=await fs.readdir(out),manifest=JSON.parse(await fs.readFile(path.join(out,'latest.json'),'utf8'));
 const packages=names.filter(name=>/\.(exe|msi|deb|rpm|AppImage|dmg)$|\.app\.tar\.gz$|_portable\.zip$/.test(name));
 for(const platform of Object.values(manifest.platforms)){const name=decodeURIComponent(new URL(platform.url).pathname.split('/').pop());if(!packages.includes(name)||!platform.signature?.trim())throw Error('Incomplete signed updater: '+name);if((await fs.readFile(path.join(out,name+'.sig'),'utf8')).trim()!==platform.signature.trim())throw Error('Updater signature mismatch: '+name);}
 const support=await fs.mkdtemp(path.join(path.dirname(out),'release-support-'));
 // Keep all compliance sources, notices and verification records available in one archive.
 for(const name of names.filter(name=>!packages.includes(name)&&name!=='latest.json'))await fs.copyFile(path.join(out,name),path.join(support,name));
 const archive=`Aegis_${version}_sources-and-notices.tar.gz`;
 execFileSync('tar',['-czf',path.resolve(out,archive),'-C',support,'.'],{stdio:'pipe',timeout:180000});
 for(const name of names.filter(name=>!packages.includes(name)&&name!=='latest.json'))await fs.unlink(path.join(out,name));
 return {packages:packages.length,assets:packages.length+2,archive};
};
