import {useEffect,useMemo,useRef,useState} from 'react';
import * as THREE from 'three';
import {t,useI18n} from './i18n';
import type {Connection} from './types';

export function Orb({connections,reducedMotion,onSelect}:{connections:Connection[];reducedMotion:boolean;onSelect?:(process:string)=>void}){
 const host=useRef<HTMLDivElement>(null),selectRef=useRef(onSelect),[fallback,setFallback]=useState(false);
 const {locale}=useI18n();selectRef.current=onSelect;
 const processes=useMemo(()=>Array.from(new Set(connections.map(c=>c.process).filter(Boolean))).sort().slice(0,24),[connections]);
 const signature=processes.join('\u0000');
 useEffect(()=>{
  const element=host.current;if(!element)return;
  let renderer:THREE.WebGLRenderer;
  try{renderer=new THREE.WebGLRenderer({alpha:true,antialias:true,powerPreference:'low-power'});}catch{setFallback(true);return;}
  setFallback(false);renderer.setPixelRatio(Math.min(devicePixelRatio,1.6));renderer.setClearColor(0,0);renderer.outputColorSpace=THREE.SRGBColorSpace;
  element.appendChild(renderer.domElement);renderer.domElement.dataset.visual='constellation';
  const scene=new THREE.Scene(),camera=new THREE.PerspectiveCamera(34,1,.1,40);camera.position.set(0,.1,10.4);
  const rig=new THREE.Group();scene.add(rig);
  // Seeded decorative stars give the scene depth; they do not represent remote hosts or traffic.
  let seed=7319;const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed/4294967296;};
  const positions:THREE.Vector3[]=[];
  for(let i=0;i<190;i++){const a=random()*Math.PI*2,z=random()*2-1,r=Math.cbrt(random()),s=Math.sqrt(1-z*z);positions.push(new THREE.Vector3(Math.cos(a)*s*r*3.45,z*r*2.35,Math.sin(a)*s*r*2.2));}
  const starCanvas=document.createElement('canvas');starCanvas.width=64;starCanvas.height=64;const ctx=starCanvas.getContext('2d');
  if(ctx){const gradient=ctx.createRadialGradient(32,32,0,32,32,32);gradient.addColorStop(0,'rgba(230,255,239,1)');gradient.addColorStop(.16,'rgba(192,246,210,1)');gradient.addColorStop(.32,'rgba(135,224,169,.36)');gradient.addColorStop(1,'rgba(100,200,150,0)');ctx.fillStyle=gradient;ctx.fillRect(0,0,64,64);}
  const texture=new THREE.CanvasTexture(starCanvas);
  const starGeometry=new THREE.BufferGeometry().setFromPoints(positions);
  const colors=positions.flatMap(()=>{const shade=.5+random()*.5;return [.57*shade,.91*shade,.69*shade];});starGeometry.setAttribute('color',new THREE.Float32BufferAttribute(colors,3));
  const stars=new THREE.Points(starGeometry,new THREE.PointsMaterial({size:.105,map:texture,vertexColors:true,transparent:true,opacity:.86,depthWrite:false,blending:THREE.AdditiveBlending}));rig.add(stars);
  const links:number[]=[];
  positions.forEach((p,i)=>{const neighbors=positions.map((q,j)=>({j,d:p.distanceToSquared(q)})).filter(n=>n.j>i&&n.d<.85).sort((a,b)=>a.d-b.d).slice(0,3);for(const {j} of neighbors)links.push(...p.toArray(),...positions[j].toArray());});
  const linkGeometry=new THREE.BufferGeometry();linkGeometry.setAttribute('position',new THREE.Float32BufferAttribute(links,3));
  const linkMaterial=new THREE.LineBasicMaterial({color:0x6baf88,transparent:true,opacity:.16,depthWrite:false});rig.add(new THREE.LineSegments(linkGeometry,linkMaterial));
  // Only the brighter, selectable nodes map to local process names. Lines are illustrative.
  const names=signature?signature.split('\u0000'):[],nodes:THREE.Mesh[]=[],highlightPositions:THREE.Vector3[]=[];
  names.forEach((name,i)=>{const anchor=positions[(i*7+17)%positions.length].clone().multiplyScalar(.88);highlightPositions.push(anchor);const node=new THREE.Mesh(new THREE.SphereGeometry(.035,10,8),new THREE.MeshBasicMaterial({color:0xc2f2d3}));node.position.copy(anchor);node.userData.process=name;rig.add(node);nodes.push(node);const halo=new THREE.Sprite(new THREE.SpriteMaterial({map:texture,color:0x9de6b8,transparent:true,opacity:.65,blending:THREE.AdditiveBlending,depthWrite:false}));halo.position.copy(anchor);halo.scale.set(.34,.34,1);rig.add(halo);});
  if(highlightPositions.length>1){const pairs:number[]=[];highlightPositions.forEach((p,i)=>{const nearest=highlightPositions.map((q,j)=>({j,d:p.distanceToSquared(q)})).filter(n=>n.j!==i).sort((a,b)=>a.d-b.d).slice(0,2);for(const {j} of nearest)if(j>i)pairs.push(...p.toArray(),...highlightPositions[j].toArray());});const geo=new THREE.BufferGeometry();geo.setAttribute('position',new THREE.Float32BufferAttribute(pairs,3));rig.add(new THREE.LineSegments(geo,new THREE.LineBasicMaterial({color:0xa1d6b3,transparent:true,opacity:.21,depthWrite:false})));}
  const distant:number[]=[];for(let i=0;i<90;i++)distant.push((random()-.5)*14,(random()-.5)*9,-3-random()*5);
  const distantGeometry=new THREE.BufferGeometry();distantGeometry.setAttribute('position',new THREE.Float32BufferAttribute(distant,3));scene.add(new THREE.Points(distantGeometry,new THREE.PointsMaterial({size:.035,map:texture,color:0x779b86,transparent:true,opacity:.38,depthWrite:false})));
  const raycaster=new THREE.Raycaster(),mouse=new THREE.Vector2();let frame=0,disposed=false,inView=true,visible=!document.hidden,last=0,elapsed=0,px=0,py=0,currentX=0,currentY=0;
  function draw(){rig.rotation.set(.12+currentY*.09,.2+currentX*.16+(reducedMotion?0:Math.sin(elapsed*.1)*.13),-.08+(reducedMotion?0:elapsed*.009));rig.position.y=reducedMotion?0:Math.sin(elapsed*.3)*.055;camera.position.x=currentX*.18;camera.position.y=.1+currentY*.12;camera.lookAt(0,0,0);renderer.render(scene,camera);}
  function render(now:number){frame=0;if(disposed||!inView||!visible)return;if(now-last>=33||reducedMotion){const delta=Math.min((now-last)/1000,.06);last=now;if(!reducedMotion){elapsed+=delta;currentX+=(px-currentX)*.08;currentY+=(py-currentY)*.08;linkMaterial.opacity=.15+Math.sin(elapsed*.45)*.025;}draw();}if(!reducedMotion)frame=requestAnimationFrame(render);}
  const start=()=>{if(!frame&&!disposed&&inView&&visible)frame=requestAnimationFrame(render);},stop=()=>{cancelAnimationFrame(frame);frame=0;};
  function resize(){if(disposed)return;const rect=element!.getBoundingClientRect();if(!rect.width||!rect.height)return;renderer.setSize(rect.width,rect.height);camera.aspect=rect.width/rect.height;camera.updateProjectionMatrix();draw();start();}
  function move(event:PointerEvent){const rect=renderer.domElement.getBoundingClientRect();mouse.set((event.clientX-rect.left)/rect.width*2-1,-(event.clientY-rect.top)/rect.height*2+1);if(!reducedMotion){px=mouse.x;py=mouse.y;}raycaster.setFromCamera(mouse,camera);renderer.domElement.style.cursor=raycaster.intersectObjects(nodes).length?'pointer':'default';}
  function leave(){px=0;py=0;}
  function select(){raycaster.setFromCamera(mouse,camera);const hit=raycaster.intersectObjects(nodes)[0];if(hit)selectRef.current?.(hit.object.userData.process);}
  function visibility(){visible=!document.hidden;visible?start():stop();}
  function lost(event:Event){event.preventDefault();stop();setFallback(true);}
  const observer=new ResizeObserver(resize);observer.observe(element);const intersection=new IntersectionObserver(entries=>{inView=entries[0]?.isIntersecting??true;inView?start():stop();});intersection.observe(element);
  renderer.domElement.addEventListener('pointermove',move);renderer.domElement.addEventListener('pointerleave',leave);renderer.domElement.addEventListener('click',select);renderer.domElement.addEventListener('webglcontextlost',lost);document.addEventListener('visibilitychange',visibility);resize();start();
  return()=>{disposed=true;stop();observer.disconnect();intersection.disconnect();document.removeEventListener('visibilitychange',visibility);renderer.domElement.removeEventListener('pointermove',move);renderer.domElement.removeEventListener('pointerleave',leave);renderer.domElement.removeEventListener('click',select);renderer.domElement.removeEventListener('webglcontextlost',lost);scene.traverse(object=>{if(object instanceof THREE.Mesh||object instanceof THREE.Points||object instanceof THREE.Line){object.geometry.dispose();for(const material of Array.isArray(object.material)?object.material:[object.material])material.dispose();}else if(object instanceof THREE.Sprite)object.material.dispose();});texture.dispose();renderer.dispose();renderer.domElement.remove();};
 },[signature,reducedMotion]);
 return <div ref={host} className={'orb'+(fallback?' fallback':'')} role="img" aria-label={t('Topologia 3D de {count} aplicativos. Os dados completos estão na tabela de conexões.',{count:processes.length})} data-locale={locale}>{fallback&&<div className="orb-fallback"><div/><span>{t('3D indisponível. Use a visualização em lista.')}</span></div>}</div>;
}
