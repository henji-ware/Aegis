const fs=require('node:fs'),path=require('node:path');
const root=path.resolve(__dirname,'..');let output='AEGIS — LICENÇAS DAS DEPENDÊNCIAS DA INTERFACE\n\n';
for(const name of ['react','react-dom','scheduler','three','lucide-react']){
 const dir=path.join(root,'node_modules',name),pkg=JSON.parse(fs.readFileSync(path.join(dir,'package.json'),'utf8'));
 const file=['LICENSE','LICENSE.txt','LICENSE.md'].find(f=>fs.existsSync(path.join(dir,f)));
 if(!file)throw new Error('Licença não encontrada: '+name);
 output+='\n'+'='.repeat(72)+'\n'+name+' '+pkg.version+' · '+pkg.license+'\n'+'='.repeat(72)+'\n'+fs.readFileSync(path.join(dir,file),'utf8')+'\n';
}
fs.writeFileSync(path.join(root,'docs','UI-LICENSES.txt'),output);

