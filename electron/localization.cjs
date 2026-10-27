'use strict';
const languages=['pt-BR','en','es','fr','de','ru','zh-CN','ja','ar','hi'];
const catalogs=Object.fromEntries(languages.filter(l=>l!=='pt-BR').map(l=>[l,require('../locales/'+l+'.json')]));
function resolveLocale(choice,system='en'){
 const raw=choice==='system'?system:choice;
 if(typeof raw!=='string')return 'en';if(/^pt(?:-|$)/i.test(raw))return 'pt-BR';if(/^zh(?:-|$)/i.test(raw))return 'zh-CN';const base=raw.split('-')[0].toLowerCase();return languages.includes(base)?base:'en';
}
function translate(source,choice='system',values={},system='en'){
 const locale=resolveLocale(choice,system),template=locale==='pt-BR'?source:catalogs[locale]?.[source]||catalogs.en[source]||source;
 return template.replace(/\{(\w+)\}/g,(token,key)=>Object.hasOwn(values,key)?String(values[key]):token);
}
function validateSettings(payload){
 if(!payload||typeof payload!=='object'||Array.isArray(payload))throw Error('Configuração inválida.');
 for(const [key,value]of Object.entries(payload)){if(key==='language'){if(value!=='system'&&!languages.includes(value))throw Error('Idioma inválido.');}else if(!['reducedMotion','liveNetwork'].includes(key)||typeof value!=='boolean')throw Error('Configuração inválida.');}
 return payload;
}
module.exports={languages,resolveLocale,translate,validateSettings};
