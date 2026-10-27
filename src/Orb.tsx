import {useEffect,useMemo,useRef,useState} from 'react';
import * as THREE from 'three';
import {t,useI18n} from './i18n';
import type {Connection} from './types';
export function Orb({connections,reducedMotion,onSelect}:{connections:Connection[];reducedMotion:boolean;onSelect?:(process:string)=>void}){
 const host=useRef<HTMLDivElement>(null),selectRef=useRef(onSelect),[fallback,setFallback]=useState(false);
 const {locale}=useI18n();selectRef.current=onSelect;
 const processes=useMemo(()=>Array.from(new Set(connections.map(c=>c.process||'System'))).sort().slice(0,24),[connections]);
 const signature=processes.join('\u0000');
 useEffect(()=>{
  const element=host.current;if(!element)return;
  let renderer:THREE.WebGLRenderer;
  try{renderer=new THREE.WebGLRenderer({alpha:true,antialias:true,powerPreference:'low-power'});}catch{setFallback(true);return;}
  setFallback(false);renderer.setPixelRatio(Math.min(devicePixelRatio,1.6));renderer.setClearColor(0,0);
  renderer.outputColorSpace=THREE.SRGBColorSpace;renderer.toneMapping=THREE.ACESFilmicToneMapping;renderer.toneMappingExposure=1.18;
  element.appendChild(renderer.domElement);
  const scene=new THREE.Scene(),camera=new THREE.PerspectiveCamera(33,1,.1,45);camera.position.set(0,.35,10.2);
  const rig=new THREE.Group(),core=new THREE.Group(),orbital=new THREE.Group();scene.add(rig);rig.add(core,orbital);
  scene.add(new THREE.AmbientLight(0xd8ffe8,1.35));
  const key=new THREE.DirectionalLight(0xc9ffe6,4.3);key.position.set(3,5,5);scene.add(key);
  const edgeLight=new THREE.DirectionalLight(0x36bd87,5);edgeLight.position.set(-4,1,-2);scene.add(edgeLight);
  const bottomLight=new THREE.PointLight(0x8affbd,7,12);bottomLight.position.set(0,-3,2);scene.add(bottomLight);
  const shape=new THREE.Shape();shape.moveTo(0,1.48);shape.lineTo(1.12,.97);shape.lineTo(1.03,-.27);shape.bezierCurveTo(.92,-.88,.35,-1.2,0,-1.48);shape.bezierCurveTo(-.35,-1.2,-.92,-.88,-1.03,-.27);shape.lineTo(-1.12,.97);shape.closePath();
  const geometry=new THREE.ExtrudeGeometry(shape,{depth:.2,bevelEnabled:true,bevelThickness:.055,bevelSize:.06,bevelSegments:4,curveSegments:18});geometry.center();
  const shield=new THREE.Mesh(geometry,new THREE.MeshPhysicalMaterial({color:0x154d3a,metalness:.84,roughness:.24,clearcoat:1,clearcoatRoughness:.12}));core.add(shield);
  const contour=new THREE.LineSegments(new THREE.EdgesGeometry(geometry,26),new THREE.LineBasicMaterial({color:0x9be7ba,transparent:true,opacity:.68}));core.add(contour);
  const inner=new THREE.LineSegments(new THREE.EdgesGeometry(geometry,26),new THREE.LineBasicMaterial({color:0x6ed8a0,transparent:true,opacity:.25}));inner.scale.set(.87,.87,.8);inner.position.z=.15;core.add(inner);
  const back=new THREE.Mesh(geometry.clone(),new THREE.MeshPhysicalMaterial({color:0x15372d,metalness:.7,roughness:.4,transparent:true,opacity:.35,depthWrite:false}));back.position.z=-.22;back.scale.set(1.08,1.08,1);core.add(back);
  const crystal=new THREE.Group();crystal.position.z=.33;core.add(crystal);
  const gemGeometry=new THREE.IcosahedronGeometry(.47,0);
  crystal.add(new THREE.Mesh(gemGeometry,new THREE.MeshPhysicalMaterial({color:0xc4f9dc,metalness:.36,roughness:.13,clearcoat:1,emissive:0x1d593b,emissiveIntensity:.38,flatShading:true})));
  crystal.add(new THREE.LineSegments(new THREE.EdgesGeometry(gemGeometry),new THREE.LineBasicMaterial({color:0xe2ffed,transparent:true,opacity:.6})));
  const glowCanvas=document.createElement('canvas');glowCanvas.width=128;glowCanvas.height=128;const ctx=glowCanvas.getContext('2d');
  let glowTexture:THREE.CanvasTexture|undefined;
  if(ctx){const gradient=ctx.createRadialGradient(64,64,0,64,64,64);gradient.addColorStop(0,'rgba(80,220,147,0.18)');gradient.addColorStop(.38,'rgba(35,155,101,0.07)');gradient.addColorStop(1,'rgba(0,0,0,0)');ctx.fillStyle=gradient;ctx.fillRect(0,0,128,128);glowTexture=new THREE.CanvasTexture(glowCanvas);const halo=new THREE.Sprite(new THREE.SpriteMaterial({map:glowTexture,blending:THREE.AdditiveBlending,depthWrite:false}));halo.scale.set(5.6,5.6,1);halo.position.z=-.65;rig.add(halo);}
  const rings:THREE.Group[]=[],tracers:{mesh:THREE.Mesh;radius:number;offset:number;speed:number}[]=[];
  [{radius:2.22,x:1.15,y:.25,opacity:.42},{radius:2.72,x:.85,y:-.64,opacity:.17},{radius:2.48,x:.2,y:1.1,opacity:.24}].forEach((r,index)=>{
   const group=new THREE.Group();group.rotation.set(r.x,r.y,index*.3);orbital.add(group);rings.push(group);
   group.add(new THREE.Mesh(new THREE.TorusGeometry(r.radius,.006,5,160),new THREE.MeshBasicMaterial({color:0x79c99d,transparent:true,opacity:r.opacity})));
   const arc=new THREE.Mesh(new THREE.TorusGeometry(r.radius,.012,5,70,Math.PI*.28),new THREE.MeshBasicMaterial({color:0xb7f9d0,transparent:true,opacity:.74}));arc.rotation.z=index*1.8;group.add(arc);
   for(let i=0;i<2;i++){const point=new THREE.Mesh(new THREE.SphereGeometry(.024,8,6),new THREE.MeshBasicMaterial({color:0xc4f7d7}));group.add(point);tracers.push({mesh:point,radius:r.radius,offset:i*Math.PI+index,speed:.08+index*.025});}
  });
  const particles=[];for(let i=0;i<420;i++){const y=1-2*(i+.5)/420,r=Math.sqrt(1-y*y),a=i*2.399963;particles.push(r*Math.cos(a)*3.18,y*3.18,r*Math.sin(a)*3.18);}
  const dustGeometry=new THREE.BufferGeometry();dustGeometry.setAttribute('position',new THREE.Float32BufferAttribute(particles,3));orbital.add(new THREE.Points(dustGeometry,new THREE.PointsMaterial({size:.012,color:0x6ba486,transparent:true,opacity:.3})));
  const grid=new THREE.GridHelper(10,28,0x285d44,0x173728);grid.position.y=-2.42;grid.material.transparent=true;grid.material.opacity=.21;scene.add(grid);
  const nodes:THREE.Mesh[]=[];const names=signature?signature.split('\u0000'):[];
  names.forEach((name,index)=>{const angle=index/Math.max(names.length,1)*Math.PI*2+.4,position=new THREE.Vector3(Math.cos(angle)*2.72,Math.sin(angle)*.92,Math.sin(angle)*2.3);const node=new THREE.Mesh(new THREE.SphereGeometry(.055,10,8),new THREE.MeshBasicMaterial({color:0xb6f6cf}));node.position.copy(position);node.userData.process=name;orbital.add(node);nodes.push(node);orbital.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0,-.2),position]),new THREE.LineBasicMaterial({color:0x63ae87,transparent:true,opacity:.1})));});
  const raycaster=new THREE.Raycaster(),mouse=new THREE.Vector2();let frame=0,disposed=false,inView=true,visible=!document.hidden,last=0,elapsed=0,px=0,py=0,currentX=0,currentY=0;
  function draw(){rig.rotation.set(-.07+currentY*.065,.23+currentX*.19,-.025);camera.position.x=currentX*.16;camera.position.y=.35+currentY*.08;camera.lookAt(0,0,0);renderer.render(scene,camera);}
  function render(now:number){frame=0;if(disposed||!inView||!visible)return;if(now-last>=33||reducedMotion){const delta=Math.min((now-last)/1000,.06);last=now;elapsed+=delta;currentX+=(px-currentX)*.08;currentY+=(py-currentY)*.08;if(!reducedMotion){core.position.y=Math.sin(elapsed*.64)*.065;crystal.rotation.set(Math.sin(elapsed*.3)*.08,elapsed*.12,.12);rings[0].rotation.z=elapsed*.035;rings[1].rotation.z=-elapsed*.024;orbital.rotation.y=Math.sin(elapsed*.16)*.07;}for(const tracer of tracers){const angle=tracer.offset+(reducedMotion?0:elapsed*tracer.speed);tracer.mesh.position.set(Math.cos(angle)*tracer.radius,Math.sin(angle)*tracer.radius,0);}draw();}if(!reducedMotion)frame=requestAnimationFrame(render);}
  const start=()=>{if(!frame&&!disposed&&inView&&visible)frame=requestAnimationFrame(render);};const stop=()=>{cancelAnimationFrame(frame);frame=0;};
  function resize(){if(disposed)return;const rect=element!.getBoundingClientRect();if(!rect.width||!rect.height)return;renderer.setSize(rect.width,rect.height);camera.aspect=rect.width/rect.height;camera.updateProjectionMatrix();draw();start();}
  function move(event:PointerEvent){const rect=renderer.domElement.getBoundingClientRect();mouse.set((event.clientX-rect.left)/rect.width*2-1,-(event.clientY-rect.top)/rect.height*2+1);if(!reducedMotion){px=mouse.x;py=mouse.y;}raycaster.setFromCamera(mouse,camera);renderer.domElement.style.cursor=raycaster.intersectObjects(nodes).length?'pointer':'default';}
  function leave(){px=0;py=0;}
  function select(){raycaster.setFromCamera(mouse,camera);const hit=raycaster.intersectObjects(nodes)[0];if(hit)selectRef.current?.(hit.object.userData.process);}
  function visibility(){visible=!document.hidden;visible?start():stop();}
  function lost(event:Event){event.preventDefault();stop();setFallback(true);}
  const observer=new ResizeObserver(resize);observer.observe(element);const intersection=new IntersectionObserver(entries=>{inView=entries[0]?.isIntersecting??true;inView?start():stop();});intersection.observe(element);
  renderer.domElement.addEventListener('pointermove',move);renderer.domElement.addEventListener('pointerleave',leave);renderer.domElement.addEventListener('click',select);renderer.domElement.addEventListener('webglcontextlost',lost);document.addEventListener('visibilitychange',visibility);resize();start();
  return()=>{disposed=true;stop();observer.disconnect();intersection.disconnect();document.removeEventListener('visibilitychange',visibility);renderer.domElement.removeEventListener('pointermove',move);renderer.domElement.removeEventListener('pointerleave',leave);renderer.domElement.removeEventListener('click',select);renderer.domElement.removeEventListener('webglcontextlost',lost);scene.traverse(object=>{if(object instanceof THREE.Mesh||object instanceof THREE.Points||object instanceof THREE.Line){object.geometry.dispose();for(const material of Array.isArray(object.material)?object.material:[object.material])material.dispose();}else if(object instanceof THREE.Sprite)object.material.dispose();});glowTexture?.dispose();renderer.dispose();renderer.domElement.remove();};
 },[signature,reducedMotion]);
 return <div ref={host} className={'orb'+(fallback?' fallback':'')} role="img" aria-label={t('Topologia 3D de {count} aplicativos. Os dados completos estão na tabela de conexões.',{count:processes.length})} data-locale={locale}>{fallback&&<div className="orb-fallback"><div/><span>{t('3D indisponível. Use a visualização em lista.')}</span></div>}</div>;
}
