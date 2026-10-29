import {useEffect,useMemo,useRef,useState,type KeyboardEvent} from 'react';
import * as THREE from 'three';
import {Search,Monitor,ArrowUpRight,X} from 'lucide-react';
import {t,useI18n} from './i18n';
import type {Connection} from './types';

type Props={connections:Connection[];reducedMotion:boolean;onSelect?:(process:string)=>void;onInspect?:(connection:Connection)=>void};
export function graphData(connections:Connection[]){
 const groups=new Map<string,{name:string;count:number;review:boolean;rows:Connection[]}>();
 for(const row of connections){const name=row.process||`PID ${row.pid}`;let group=groups.get(name);if(!group){group={name,count:0,review:false,rows:[]};groups.set(name,group);}group.count++;group.review ||=row.analysis?.level==='review';group.rows.push(row);}
 return [...groups.values()].sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));
}
function endpoint(row:Connection){const address=row.state==='Listen'?row.localAddress:row.remoteAddress;return `${address.includes(':')?`[${address}]`:address}:${row.state==='Listen'?row.localPort:row.remotePort}`;}
export function Orb({connections,reducedMotion,onSelect,onInspect}:Props){
 useI18n();const host=useRef<HTMLDivElement>(null),active=useRef<HTMLButtonElement>(null),targets=useRef<HTMLDivElement>(null);
 const [selected,setSelected]=useState(''),[search,setSearch]=useState(''),[fallback,setFallback]=useState(false);
 const groups=useMemo(()=>graphData(connections),[connections]);
 const visible=useMemo(()=>{const q=search.toLocaleLowerCase();return groups.filter(p=>p.name.toLocaleLowerCase().includes(q)||p.rows.some(row=>`${row.pid} ${endpoint(row)}`.toLocaleLowerCase().includes(q)));},[groups,search]);
 const current=visible.find(p=>p.name===selected)||visible[0];
 const signature=JSON.stringify(current?.rows.map(row=>[row.id,endpoint(row),row.analysis?.level]));
 function select(name:string){setSelected(name);onSelect?.(name);if(targets.current)targets.current.scrollTop=0;}
 function navigate(event:KeyboardEvent<HTMLButtonElement>,index:number){let next:number|undefined;if(event.key==='ArrowDown')next=Math.min(index+1,visible.length-1);if(event.key==='ArrowUp')next=Math.max(index-1,0);if(event.key==='Home')next=0;if(event.key==='End')next=visible.length-1;if(next!==undefined){event.preventDefault();select(visible[next].name);const button=host.current?.querySelectorAll<HTMLButtonElement>('.graph-app')[next];button?.focus();button?.scrollIntoView({block:'nearest'});}}
 useEffect(()=>{
  const element=host.current;if(!element||!current)return;
  let renderer:THREE.WebGLRenderer;
  try{renderer=new THREE.WebGLRenderer({alpha:true,antialias:true,powerPreference:'low-power'});}catch{setFallback(true);return;}
  setFallback(false);renderer.setPixelRatio(Math.min(devicePixelRatio,1.5));renderer.setClearColor(0,0);renderer.domElement.dataset.visual='connections';renderer.domElement.setAttribute('aria-hidden','true');element.prepend(renderer.domElement);
  const scene=new THREE.Scene(),camera=new THREE.OrthographicCamera(-1,1,1,-1,.1,1000),field=new THREE.Group();scene.add(field);camera.position.z=400;
  const geometries:THREE.BufferGeometry[]=[],materials:THREE.Material[]=[];
  let frame=0,disposed=false,inView=true,documentVisible=!document.hidden,targetX=0,x=0;
  function clear(){field.clear();geometries.splice(0).forEach(g=>g.dispose());materials.splice(0).forEach(m=>m.dispose());}
  function draw(){
   const box=element!.getBoundingClientRect(),source=active.current?.getBoundingClientRect(),column=targets.current?.getBoundingClientRect();clear();field.rotation.y=reducedMotion?0:x*.035;
   if(source&&column){const start=new THREE.Vector3(source.right-box.left+4-box.width/2,box.height/2-(Math.max(column.top+12,Math.min(column.bottom-12,source.top+source.height/2))-box.top),0);
    for(const button of targets.current!.querySelectorAll<HTMLButtonElement>('.graph-target')){const rect=button.getBoundingClientRect();if(rect.bottom<column.top||rect.top>column.bottom)continue;const end=new THREE.Vector3(rect.left-box.left-box.width/2-4,box.height/2-(rect.top+rect.height/2-box.top),0),curve=new THREE.CubicBezierCurve3(start,new THREE.Vector3(start.x+35,start.y,15),new THREE.Vector3(end.x-35,end.y,15),end),geometry=new THREE.BufferGeometry().setFromPoints(curve.getPoints(24)),material=new THREE.LineBasicMaterial({color:current!.review?0x9d875a:0x5e9d76,transparent:true,opacity:.48});geometries.push(geometry);materials.push(material);field.add(new THREE.Line(geometry,material));
     for(const point of [start,end]){const nodeGeometry=new THREE.SphereGeometry(2.4,8,6),nodeMaterial=new THREE.MeshBasicMaterial({color:current!.review?0xc1a66e:0xa0d3b0});geometries.push(nodeGeometry);materials.push(nodeMaterial);const node=new THREE.Mesh(nodeGeometry,nodeMaterial);node.position.copy(point);field.add(node);}
    }
   }renderer.render(scene,camera);
  }
  function render(){frame=0;if(disposed||!documentVisible||!inView)return;x+=((reducedMotion?0:targetX)-x)*.2;draw();if(!reducedMotion&&Math.abs(targetX-x)>.001)frame=requestAnimationFrame(render);}
  const start=()=>{if(!frame&&!disposed&&documentVisible&&inView)frame=requestAnimationFrame(render);};
  const stop=()=>{cancelAnimationFrame(frame);frame=0;};
  function resize(){const box=element!.getBoundingClientRect();if(!box.width||!box.height)return;renderer.setSize(box.width,box.height);camera.left=-box.width/2;camera.right=box.width/2;camera.top=box.height/2;camera.bottom=-box.height/2;camera.updateProjectionMatrix();draw();}
  const move=(event:PointerEvent)=>{targetX=(event.clientX-element!.getBoundingClientRect().left)/Math.max(element!.clientWidth,1)*2-1;start();},leave=()=>{targetX=0;start();};
  const observer=new ResizeObserver(resize);observer.observe(element);const intersection=new IntersectionObserver(entries=>{inView=entries[0].isIntersecting;if(inView)start();else stop();});intersection.observe(element);
  const visibility=()=>{documentVisible=!document.hidden;if(documentVisible)start();else stop();},lost=(event:Event)=>{event.preventDefault();setFallback(true);stop();};
  element.addEventListener('pointermove',move);element.addEventListener('pointerleave',leave);element.addEventListener('scroll',start,true);document.addEventListener('visibilitychange',visibility);renderer.domElement.addEventListener('webglcontextlost',lost);resize();
  return()=>{disposed=true;stop();observer.disconnect();intersection.disconnect();element.removeEventListener('pointermove',move);element.removeEventListener('pointerleave',leave);element.removeEventListener('scroll',start,true);document.removeEventListener('visibilitychange',visibility);renderer.domElement.removeEventListener('webglcontextlost',lost);clear();renderer.dispose();renderer.domElement.remove();};
 },[signature,current?.name,current?.review,reducedMotion]);
 return <div ref={host} className={'connection-graph graph-explorer'+(fallback?' graph-fallback':'')} aria-label={t('Relações reais entre aplicativos e conexões')}>
  <div className="graph-search"><Search size={14}/><input aria-label={t('Buscar conexões')} placeholder={t('Buscar aplicativo, IP, porta ou PID…')} value={search} onChange={event=>setSearch(event.target.value)}/>{search&&<button aria-label={t('Limpar busca')} onClick={()=>setSearch('')}><X size={14}/></button>}</div>
  <div className="graph-head"><span>{t('Aplicativos')} <small>{visible.length}</small></span><span>{t('Destinos / portas')} <small>{current?.count||0}</small></span></div>
  <div className="graph-lists"><div className="graph-apps" aria-label={t('Aplicativos')}>{visible.map((group,index)=><button ref={group===current?active:undefined} className={'graph-app'+(group===current?' selected':'')} aria-pressed={group===current} key={group.name} onClick={()=>select(group.name)} onKeyDown={event=>navigate(event,index)} title={group.name}><Monitor size={16}/><span><strong>{group.name}</strong><small>{group.review?t('Para revisar'):`PID ${[...new Set(group.rows.map(row=>row.pid))].join(', ')}`}</small></span><b>{group.count}</b></button>)}</div>
   <div ref={targets} className="graph-targets" aria-label={t('Destinos / portas')}>{current?.rows.map(row=><button className="graph-target" key={row.id} onClick={()=>onInspect?.(row)} title={endpoint(row)}><span><strong>{endpoint(row)}</strong><small>{row.protocol} · {row.state==='Listen'?t('Em escuta'):t('Estabelecida')} · PID {row.pid}</small></span><ArrowUpRight size={15}/></button>)}</div>
  </div>
  {!visible.length&&<p className="graph-no-results">{t(connections.length?'Nenhuma conexão corresponde à busca.':'Nenhuma conexão retornada nesta consulta.')}</p>}
  <div className="graph-caption" aria-live="polite">{current?`${current.name} · ${current.count} ${t('Conexões')}`:t('Selecione um aplicativo para ver suas conexões')}</div>
 </div>;
}
