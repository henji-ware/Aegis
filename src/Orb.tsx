import {useEffect,useMemo,useRef,useState} from 'react';
import * as THREE from 'three';
import {t,useI18n} from './i18n';
import type {Connection} from './types';

type Props={connections:Connection[];reducedMotion:boolean;onSelect?:(process:string)=>void};

export function Orb({connections,reducedMotion,onSelect}:Props){
 const host=useRef<HTMLDivElement>(null),selectRef=useRef(onSelect);
 const [fallback,setFallback]=useState(false);
 const {locale}=useI18n();
 selectRef.current=onSelect;
 const processes=useMemo(()=>Array.from(new Set(connections.map(c=>c.process).filter(Boolean))).sort().slice(0,24),[connections]);
 const signature=processes.join('\u0000');

 useEffect(()=>{
  const element=host.current;
  if(!element)return;
  let renderer:THREE.WebGLRenderer;
  try{renderer=new THREE.WebGLRenderer({alpha:true,antialias:true,powerPreference:'low-power'});}
  catch{setFallback(true);return;}
  setFallback(false);
  renderer.setPixelRatio(Math.min(devicePixelRatio,1.5));
  renderer.setClearColor(0,0);
  renderer.outputColorSpace=THREE.SRGBColorSpace;
  renderer.domElement.dataset.visual='constellation';
  element.appendChild(renderer.domElement);

  const scene=new THREE.Scene(),camera=new THREE.PerspectiveCamera(37,1,.1,40);
  camera.position.set(0,.1,10);
  const field=new THREE.Group();
  scene.add(field);
  let seed=7319;
  const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
  // Orbital arcs are an abstract backdrop, not measured paths or packet traffic.
  const orbit=(angle:number,layer:number)=>{
   const radius=2.3+layer*.24;
   const point=new THREE.Vector3(Math.cos(angle)*radius*1.22,Math.sin(angle)*radius*.5,Math.sin(angle)*radius*.42);
   point.applyAxisAngle(new THREE.Vector3(1,0,0),-.42+layer*.46);
   point.applyAxisAngle(new THREE.Vector3(0,0,1),-.28+layer*.28);
   return point;
  };
  const starCanvas=document.createElement('canvas');
  starCanvas.width=64;starCanvas.height=64;
  const context=starCanvas.getContext('2d');
  if(context){
   const glow=context.createRadialGradient(32,32,0,32,32,32);
   glow.addColorStop(0,'rgba(220,241,224,1)');
   glow.addColorStop(.12,'rgba(170,212,180,.9)');
   glow.addColorStop(.3,'rgba(80,138,97,.3)');
   glow.addColorStop(1,'rgba(24,66,37,0)');
   context.fillStyle=glow;context.fillRect(0,0,64,64);
  }
  const texture=new THREE.CanvasTexture(starCanvas),positions:THREE.Vector3[]=[];
  const lines:number[]=[];
  for(let layer=0;layer<3;layer++){
   for(let i=0;i<54;i++){
    const angle=i/54*Math.PI*2;
    const position=orbit(angle,layer);
    position.add(new THREE.Vector3((random()-.5)*.09,(random()-.5)*.09,(random()-.5)*.12));
    positions.push(position);
    // Partial arcs leave space around the central void.
    if(i%18<13)lines.push(...position.toArray(),...orbit((i+1)/54*Math.PI*2,layer).toArray());
    if(layer<2&&i%18===6)lines.push(...position.toArray(),...orbit(angle+.08,layer+1).toArray());
   }
  }
  const starGeometry=new THREE.BufferGeometry().setFromPoints(positions);
  const starMaterial=new THREE.PointsMaterial({size:.085,map:texture,color:0x6c9878,transparent:true,opacity:.65,depthWrite:false});
  field.add(new THREE.Points(starGeometry,starMaterial));
  const lineGeometry=new THREE.BufferGeometry();
  lineGeometry.setAttribute('position',new THREE.Float32BufferAttribute(lines,3));
  const lineMaterial=new THREE.LineBasicMaterial({color:0x3b6548,transparent:true,opacity:.24,depthWrite:false});
  field.add(new THREE.LineSegments(lineGeometry,lineMaterial));

  const nodes:THREE.Mesh[]=[];
  const nodeGeometry=new THREE.SphereGeometry(.047,10,8);
  const names=signature?signature.split('\u0000'):[];
  names.forEach((name,index)=>{
   const anchor=orbit(index/Math.max(names.length,1)*Math.PI*2+.35,index%3);
   const node=new THREE.Mesh(nodeGeometry,new THREE.MeshBasicMaterial({color:0xa8c9b0}));
   node.position.copy(anchor);node.userData.process=name;nodes.push(node);field.add(node);
   const halo=new THREE.Sprite(new THREE.SpriteMaterial({map:texture,color:0x699f78,transparent:true,opacity:.65,depthWrite:false}));
   halo.position.copy(anchor);halo.scale.set(.35,.35,1);field.add(halo);
  });
  const tracerGeometry=new THREE.BufferGeometry();
  const tracerPositions=new Float32Array(18);
  tracerGeometry.setAttribute('position',new THREE.BufferAttribute(tracerPositions,3));
  field.add(new THREE.Points(tracerGeometry,new THREE.PointsMaterial({size:.14,map:texture,color:0x91bd9c,transparent:true,opacity:.6,depthWrite:false})));
  const distant:number[]=[];
  for(let i=0;i<80;i++)distant.push((random()-.5)*13,(random()-.5)*7,-2-random()*5);
  const dustGeometry=new THREE.BufferGeometry();
  dustGeometry.setAttribute('position',new THREE.Float32BufferAttribute(distant,3));
  scene.add(new THREE.Points(dustGeometry,new THREE.PointsMaterial({size:.025,color:0x66726a,transparent:true,opacity:.35,depthWrite:false})));

  const raycaster=new THREE.Raycaster(),pointer=new THREE.Vector2();
  let frame=0,disposed=false,inView=true,visible=!document.hidden,last=0,elapsed=0;
  let targetX=0,targetY=0,currentX=0,currentY=0;
  function draw(){
   field.rotation.set(.16+currentY*.12,-.12+currentX*.15+(reducedMotion?0:Math.sin(elapsed*.09)*.12),-.03);
   field.position.y=reducedMotion?0:Math.sin(elapsed*.22)*.035;
   for(let i=0;i<6;i++){
    const position=orbit(i/6*Math.PI*2+elapsed*.065,i%3);
    tracerPositions.set(position.toArray(),i*3);
   }
   tracerGeometry.attributes.position.needsUpdate=true;
   camera.position.x=currentX*.1;camera.position.y=.1+currentY*.08;
   camera.lookAt(0,0,0);
   renderer.render(scene,camera);
  }
  function render(now:number){
   frame=0;
   if(disposed||!inView||!visible)return;
   if(now-last>=33||reducedMotion){
    const delta=Math.min((now-last)/1000,.06);last=now;
    if(!reducedMotion){elapsed+=delta;currentX+=(targetX-currentX)*.07;currentY+=(targetY-currentY)*.07;}
    draw();
   }
   if(!reducedMotion)frame=requestAnimationFrame(render);
  }
  const start=()=>{if(!frame&&!disposed&&inView&&visible)frame=requestAnimationFrame(render);};
  const stop=()=>{cancelAnimationFrame(frame);frame=0;};
  function resize(){
   if(disposed)return;
   const rect=element!.getBoundingClientRect();
   if(!rect.width||!rect.height)return;
   renderer.setSize(rect.width,rect.height);
   camera.aspect=rect.width/rect.height;
   camera.position.z=rect.width/rect.height<1.5?12:10;
   camera.updateProjectionMatrix();draw();start();
  }
  function move(event:PointerEvent){
   const rect=renderer.domElement.getBoundingClientRect();
   pointer.set((event.clientX-rect.left)/rect.width*2-1,-(event.clientY-rect.top)/rect.height*2+1);
   if(!reducedMotion){targetX=pointer.x;targetY=pointer.y;}
   raycaster.setFromCamera(pointer,camera);
   renderer.domElement.style.cursor=raycaster.intersectObjects(nodes).length?'pointer':'default';
  }
  function leave(){targetX=0;targetY=0;}
  function select(){raycaster.setFromCamera(pointer,camera);const hit=raycaster.intersectObjects(nodes)[0];if(hit)selectRef.current?.(hit.object.userData.process);}
  function visibility(){visible=!document.hidden;visible?start():stop();}
  function lost(event:Event){event.preventDefault();stop();setFallback(true);}
  const observer=new ResizeObserver(resize);
  observer.observe(element);
  const intersection=new IntersectionObserver(entries=>{inView=entries[0]?.isIntersecting??true;inView?start():stop();});
  intersection.observe(element);
  renderer.domElement.addEventListener('pointermove',move);
  renderer.domElement.addEventListener('pointerleave',leave);
  renderer.domElement.addEventListener('click',select);
  renderer.domElement.addEventListener('webglcontextlost',lost);
  document.addEventListener('visibilitychange',visibility);
  resize();start();
  return()=>{
   disposed=true;stop();observer.disconnect();intersection.disconnect();
   document.removeEventListener('visibilitychange',visibility);
   renderer.domElement.removeEventListener('pointermove',move);
   renderer.domElement.removeEventListener('pointerleave',leave);
   renderer.domElement.removeEventListener('click',select);
   renderer.domElement.removeEventListener('webglcontextlost',lost);
   const geometries=new Set<THREE.BufferGeometry>(),materials=new Set<THREE.Material>();
   scene.traverse(object=>{
    if(object instanceof THREE.Mesh||object instanceof THREE.Points||object instanceof THREE.Line){
     geometries.add(object.geometry);
     for(const material of Array.isArray(object.material)?object.material:[object.material])materials.add(material);
    }else if(object instanceof THREE.Sprite)materials.add(object.material);
   });
   geometries.forEach(geometry=>geometry.dispose());materials.forEach(material=>material.dispose());
   texture.dispose();renderer.dispose();renderer.domElement.remove();
  };
 },[signature,reducedMotion]);
 return <div ref={host} className={'orb'+(fallback?' fallback':'')} role="img" aria-label={t('Topologia 3D de {count} aplicativos. Os dados completos estão na tabela de conexões.',{count:processes.length})} data-locale={locale}>{fallback&&<div className="orb-fallback"><div/><span>{t('3D indisponível. Use a visualização em lista.')}</span></div>}</div>;
}
