import {useEffect,useMemo,useRef,useState} from 'react';
import * as THREE from 'three';
import {t,useI18n} from './i18n';
import type {Connection} from './types';
type Props={connections:Connection[];reducedMotion:boolean;onSelect?:(process:string)=>void};
export function graphData(connections:Connection[]){
 const groups=new Map<string,{name:string;count:number;review:boolean;targets:Map<string,number>}>();
 for(const row of connections){const name=row.process||`PID ${row.pid}`;let group=groups.get(name);if(!group){group={name,count:0,review:false,targets:new Map()};groups.set(name,group);}group.count++;group.review ||=row.analysis?.level==='review';const target=row.state==='Listen'?`${row.localAddress}:${row.localPort} (${t('Em escuta')})`:`${row.remoteAddress}:${row.remotePort}`;group.targets.set(target,(group.targets.get(target)||0)+1);}
 const processes=[...groups.values()].sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name)).slice(0,12);
 const targets=[...new Set(processes.flatMap(p=>[...p.targets.keys()]))].slice(0,20);
 return {processes,targets,omitted:groups.size-processes.length};
}
export function Orb({connections,reducedMotion,onSelect}:Props){
 const host=useRef<HTMLDivElement>(null),callback=useRef(onSelect);callback.current=onSelect;
 const [fallback,setFallback]=useState(false),[hover,setHover]=useState('');useI18n();
 const graph=useMemo(()=>graphData(connections),[connections,t('Em escuta')]);
 const signature=JSON.stringify(graph.processes.map(p=>({name:p.name,count:p.count,review:p.review,targets:[...p.targets]})));
 useEffect(()=>{
  const element=host.current;if(!element||!graph.processes.length)return;
  let renderer:THREE.WebGLRenderer;
  try{renderer=new THREE.WebGLRenderer({alpha:true,antialias:true,powerPreference:'low-power'});}catch{setFallback(true);return;}
  setFallback(false);renderer.setPixelRatio(Math.min(devicePixelRatio,1.5));renderer.setClearColor(0,0);renderer.outputColorSpace=THREE.SRGBColorSpace;renderer.domElement.dataset.visual='connections';element.appendChild(renderer.domElement);
  const scene=new THREE.Scene(),camera=new THREE.PerspectiveCamera(36,1,.1,50),field=new THREE.Group();scene.add(field);camera.position.set(0,.1,12);
  const pickable:THREE.Mesh[]=[];const geometries:THREE.BufferGeometry[]=[],materials:THREE.Material[]=[];
  const addNode=(position:THREE.Vector3,size:number,color:number,process?:string)=>{const geometry=new THREE.IcosahedronGeometry(size,1),material=new THREE.MeshBasicMaterial({color,wireframe:true});geometries.push(geometry);materials.push(material);const node=new THREE.Mesh(geometry,material);node.position.copy(position);if(process){node.userData.process=process;pickable.push(node);}field.add(node);return node;};
  const left=graph.processes.map((p,i)=>new THREE.Vector3(-2.15,(graph.processes.length-1)*.22-i*.44,Math.sin(i*.9)*.4));
  const right=graph.targets.map((_,i)=>new THREE.Vector3(2.2,(graph.targets.length-1)*.15-i*.3,Math.cos(i*.8)*.5));
  const points:number[]=[];const targetMap=new Map(graph.targets.map((name,i)=>[name,i]));
  graph.processes.forEach((p,i)=>{addNode(left[i],.075+Math.min(p.count,20)*.003,p.review?0xb69b65:0x9bc8ad,p.name);for(const target of p.targets.keys()){const index=targetMap.get(target);if(index!==undefined){const center=new THREE.Vector3(0,(left[i].y+right[index].y)/2,.6);const curve=new THREE.QuadraticBezierCurve3(left[i],center,right[index]);const lineGeometry=new THREE.BufferGeometry().setFromPoints(curve.getPoints(24));const material=new THREE.LineBasicMaterial({color:p.review?0x6d5d37:0x2f6249,transparent:true,opacity:.52});geometries.push(lineGeometry);materials.push(material);field.add(new THREE.Line(lineGeometry,material));}}});
  right.forEach(p=>addNode(p,.05,0x548a6b));
  const dividerGeometry=new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,-2.5,-.8),new THREE.Vector3(0,2.5,-.8)]);const dividerMaterial=new THREE.LineDashedMaterial({color:0x233029,dashSize:.04,gapSize:.09});geometries.push(dividerGeometry);materials.push(dividerMaterial);const divider=new THREE.Line(dividerGeometry,dividerMaterial);divider.computeLineDistances();field.add(divider);
  const raycaster=new THREE.Raycaster(),pointer=new THREE.Vector2();let frame=0,disposed=false,inView=true,visible=!document.hidden,last=0,targetX=0,targetY=0,x=0,y=0,selected:THREE.Mesh|undefined;
  function draw(){field.rotation.y=x*.12;field.rotation.x=y*.05;camera.lookAt(0,0,0);renderer.render(scene,camera);}
  function render(now:number){frame=0;if(disposed||!visible||!inView)return;if(now-last>=33||reducedMotion){last=now;x+=((reducedMotion?0:targetX)-x)*.12;y+=((reducedMotion?0:targetY)-y)*.12;draw();}if(!reducedMotion)frame=requestAnimationFrame(render);}
  const start=()=>{if(!frame&&!disposed&&inView&&visible)frame=requestAnimationFrame(render);};const stop=()=>{cancelAnimationFrame(frame);frame=0;};
  function resize(){const rect=element!.getBoundingClientRect();if(!rect.width||!rect.height)return;renderer.setSize(rect.width,rect.height);camera.aspect=rect.width/rect.height;camera.position.z=camera.aspect<1.5?16:12;camera.updateProjectionMatrix();draw();start();}
  function move(event:PointerEvent){const rect=renderer.domElement.getBoundingClientRect();pointer.set((event.clientX-rect.left)/rect.width*2-1,-(event.clientY-rect.top)/rect.height*2+1);targetX=pointer.x;targetY=pointer.y;raycaster.setFromCamera(pointer,camera);selected=raycaster.intersectObjects(pickable)[0]?.object as THREE.Mesh|undefined;setHover(selected?.userData.process||'');renderer.domElement.style.cursor=selected?'pointer':'default';start();}
  function leave(){targetX=targetY=0;selected=undefined;setHover('');start();}function click(){if(selected)callback.current?.(selected.userData.process);}
  const observer=new ResizeObserver(resize);observer.observe(element);const intersection=new IntersectionObserver(entries=>{inView=entries[0].isIntersecting;if(inView)start();else stop();});intersection.observe(element);
  const visibility=()=>{visible=!document.hidden;if(visible)start();else stop();};document.addEventListener('visibilitychange',visibility);renderer.domElement.addEventListener('pointermove',move);renderer.domElement.addEventListener('pointerleave',leave);renderer.domElement.addEventListener('click',click);
  const lost=(event:Event)=>{event.preventDefault();setFallback(true);stop();};renderer.domElement.addEventListener('webglcontextlost',lost);resize();
  return()=>{disposed=true;stop();observer.disconnect();intersection.disconnect();document.removeEventListener('visibilitychange',visibility);renderer.domElement.removeEventListener('pointermove',move);renderer.domElement.removeEventListener('pointerleave',leave);renderer.domElement.removeEventListener('click',click);renderer.domElement.removeEventListener('webglcontextlost',lost);geometries.forEach(g=>g.dispose());materials.forEach(m=>m.dispose());renderer.dispose();renderer.domElement.remove();};
 },[signature,reducedMotion]);
 return <div className="connection-graph"><div className="graph-head"><span>{t('Aplicativos')}</span><span>{t('Destinos / portas')}</span></div><div ref={host} className="orb-canvas" role="img" aria-label={t('Relações reais entre aplicativos e conexões')}>{!graph.processes.length&&<p className="graph-empty">{t('Nenhuma conexão retornada nesta consulta.')}</p>}{fallback&&<div className="graph-fallback">{graph.processes.map(p=><button key={p.name} onClick={()=>onSelect?.(p.name)}>{p.name}<span>{p.count}</span></button>)}</div>}</div><div className="graph-caption" aria-live="polite">{hover||t('Selecione um aplicativo para ver suas conexões')}</div><div className="graph-processes" aria-label={t('Aplicativos')}>{graph.processes.slice(0,6).map(p=><button key={p.name} onClick={()=>onSelect?.(p.name)}><i className={p.review?'review':''}/>{p.name}<span>{p.count}</span></button>)}</div></div>;
}
