import {useSyncExternalStore} from 'react';
import en from '../locales/en.json';
import es from '../locales/es.json';
import fr from '../locales/fr.json';
import de from '../locales/de.json';
import ru from '../locales/ru.json';
import zh from '../locales/zh-CN.json';
import ja from '../locales/ja.json';
import ar from '../locales/ar.json';
import hi from '../locales/hi.json';
export const languages=[{code:'pt-BR',native:'Português'},{code:'en',native:'English'},{code:'es',native:'Español'},{code:'fr',native:'Français'},{code:'de',native:'Deutsch'},{code:'ru',native:'Русский'},{code:'zh-CN',native:'简体中文'},{code:'ja',native:'日本語'},{code:'ar',native:'العربية'},{code:'hi',native:'हिन्दी'}];
const catalogs:Record<string,Record<string,string>>={en,es,fr,de,ru,'zh-CN':zh,ja,ar,hi};
const listeners=new Set<()=>void>();let language='system';
export function resolveLocale(choice:string,system=navigator.language):string{
 const raw=choice==='system'?system:choice;
 if(/^pt(?:-|$)/i.test(raw))return 'pt-BR';if(/^zh(?:-|$)/i.test(raw))return 'zh-CN';
 const base=raw.split('-')[0].toLowerCase();return languages.some(l=>l.code===base)?base:'en';
}
export function getLocale(){return resolveLocale(language);}
export function setLanguage(value:string){
 if(value!=='system'&&!languages.some(l=>l.code===value))return;
 language=value;const locale=getLocale();document.documentElement.lang=locale;document.documentElement.dir=locale==='ar'?'rtl':'ltr';listeners.forEach(listener=>listener());
}
export function t(source:string,values:Record<string,string|number>={}){
 const locale=getLocale(),template=locale==='pt-BR'?source:catalogs[locale]?.[source]||catalogs.en[source]||source;
 return template.replace(/\{(\w+)\}/g,(token,key)=>Object.hasOwn(values,key)?String(values[key]):token);
}
export function useI18n(){useSyncExternalStore(listener=>{listeners.add(listener);return()=>listeners.delete(listener);},()=>language);return {language,locale:getLocale(),t};}
setLanguage('system');
