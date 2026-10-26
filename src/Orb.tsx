import {useEffect,useMemo,useRef,useState} from 'react';
import * as THREE from 'three';
import type {Connection} from './types';
export function Orb({connections,reducedMotion,onSelect}:{connections:Connection[];reducedMotion:boolean;onSelect?:(process:string)=>void}){
 const host=useRef<HTMLDivElement>(null),selectRef=useRef(onSelect),[fallback,setFallback]=useState(false);
 selectRef.current=onSelect;
 const signature=useMemo(()=>Array.from(new Set(connections.map(c=>c.process||'Sistema'))).sort().slice(0,24).join('\u0000'),[connections]);
 useEffect(()=>{
  const element=host.current;if(!element)return;
  let renderer:THREE.WebGLRenderer;
  try{renderer=new THREE.WebGLRenderer({alpha:true,antialias:true,powerPreference:'low-power'});}catch{setFallback(true);return;}
  setFallback(false);
  renderer.setPixelRatio(Math.min(devicePixelRatio,1.6));renderer.setClearColor(0,0);
  renderer.outputColorSpace=THREE.SRGBColorSpace;renderer.toneMapping=THREE.ACESFilmicToneMapping;renderer.toneMappingExposure=1.2;
  element.appendChild(renderer.domElement);
  const scene=new THREE.Scene(),camera=new THREE.PerspectiveCamera(34,1,.1,60);
  camera.position.set(0,.45,10.3);
  const rig=new THREE.Group(),orbitals=new THREE.Group();scene.add(rig);rig.add(orbitals);
  const ambient=new THREE.AmbientLight(0xc8ddff,1.5);scene.add(ambient);
  const key=new THREE.DirectionalLight(0xccedff,4);key.position.set(4,5,4);scene.add(key);
  const rim=new THREE.DirectionalLight(0x5597ff,5);rim.position.set(-3,-1,-3);scene.add(rim);
  const shield=new THREE.Shape();
  shield.moveTo(0,1.38);shield.lineTo(1.1,.9);shield.lineTo(1,-.3);shield.bezierCurveTo(.9,-.82,.35,-1.15,0,-1.38);shield.bezierCurveTo(-.35,-1.15,-.9,-.82,-1,-.3);shield.lineTo(-1.1,.9);shield.closePath();
  const geometry=new THREE.ExtrudeGeometry(shield,{depth:.18,bevelEnabled:true,bevelThickness:.07,bevelSize:.06,bevelSegments:3,curveSegments:12});geometry.center();
  const core=new THREE.Group();rig.add(core);
  const shell=new THREE.Mesh(geometry,new THREE.MeshPhysicalMaterial({color:0x7399b9,metalness:.88,roughness:.2,transparent:true,opacity:.78,clearcoat:1,clearcoatRoughness:.12}));core.add(shell);
  const outline=new THREE.LineSegments(new THREE.EdgesGeometry(geometry,28),new THREE.LineBasicMaterial({color:0x9be4ff,transparent:true,opacity:.7}));core.add(outline);
  const inset=new THREE.Mesh(new THREE.IcosahedronGeometry(.43,0),new THREE.MeshPhysicalMaterial({color:0xc7eaff,metalness:.5,roughness:.15,emissive:0x1c4b68,emissiveIntensity:.65}));inset.position.z=.28;core.add(inset);
  const insetEdge=new THREE.LineSegments(new THREE.EdgesGeometry(inset.geometry),new THREE.LineBasicMaterial({color:0xc8f0ff,transparent:true,opacity:.9}));insetEdge.position.copy(inset.position);core.add(insetEdge);
  const rings:THREE.Mesh[]=[];
  [{radius:2.55,tilt:1.22,z:-.22,opacity:.42},{radius:2.82,tilt:1.1,z:.22,opacity:.14},{radius:2.3,tilt:.44,z:1.1,opacity:.12}].forEach(r=>{
   const mesh=new THREE.Mesh(new THREE.TorusGeometry(r.radius,.006,5,180),new THREE.MeshBasicMaterial({color:0x89c8ed,transparent:true,opacity:r.opacity}));
   mesh.rotation.set(r.tilt,r.z,r.z/3);orbitals.add(mesh);rings.push(mesh);
  });
  const points:number[]=[];for(let i=0;i<650;i++){const phi=Math.acos(1-2*(i+.5)/650),theta=i*2.399963;points.push(Math.sin(phi)*Math.cos(theta)*3.15,Math.cos(phi)*3.15,Math.sin(phi)*Math.sin(theta)*3.15);}
  const dustGeometry=new THREE.BufferGeometry();dustGeometry.setAttribute('position',new THREE.Float32BufferAttribute(points,3));
  orbitals.add(new THREE.Points(dustGeometry,new THREE.PointsMaterial({color:0x719abd,size:.012,transparent:true,opacity:.28})));
  const grid=new THREE.GridHelper(11,26,0x28435d,0x152532);grid.position.y=-2.3;grid.material.transparent=true;grid.material.opacity=.28;scene.add(grid);
  const nodes:THREE.Mesh[]=[];
  const processes=signature?signature.split('\u0000'):[];
  processes.forEach((name,i)=>{
   const angle=(i/processes.length)*Math.PI*2+.2;
   const position=new THREE.Vector3(Math.cos(angle)*2.55,Math.sin(angle)*.82,Math.sin(angle)*2.28);
   const node=new THREE.Mesh(new THREE.SphereGeometry(.047,10,8),new THREE.MeshBasicMaterial({color:0xbbebff}));node.position.copy(position);node.userData.process=name;orbitals.add(node);nodes.push(node);
   const line=new THREE.Line(new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(0,0,0),position]),new THREE.LineBasicMaterial({color:0x669bc1,transparent:true,opacity:.08}));orbitals.add(line);
  });
  const raycaster=new THREE.Raycaster(),mouse=new THREE.Vector2();
  let frame=0,disposed=false,inView=true,focused=!document.hidden,last=0,px=0,py=0,currentX=0,currentY=0,elapsed=0;
  function render(now:number){
   frame=0;if(disposed||!inView||!focused)return;
   const delta=Math.min((now-last)/1000,.05);
   if(now-last>=32||reducedMotion){
    last=now;elapsed+=delta;currentX+=(px-currentX)*.065;currentY+=(py-currentY)*.065;
    rig.rotation.y=reducedMotion?.16:.16+currentX*.12;rig.rotation.x=reducedMotion?-.04:-.04+currentY*.055;
    if(!reducedMotion){core.position.y=Math.sin(elapsed*.7)*.045;orbitals.rotation.y=Math.sin(elapsed*.15)*.06;inset.rotation.y=elapsed*.055;insetEdge.rotation.y=inset.rotation.y;}
    camera.position.x=reducedMotion?0:currentX*.14;camera.lookAt(0,0,0);renderer.render(scene,camera);
   }
   if(!reducedMotion)frame=requestAnimationFrame(render);
  }
  const start=()=>{if(!frame&&!disposed&&inView&&focused)frame=requestAnimationFrame(render);};
  const stop=()=>{cancelAnimationFrame(frame);frame=0;};
  function resize(){if(disposed)return;const {width,height}=element!.getBoundingClientRect();if(!width||!height)return;renderer.setSize(width,height);camera.aspect=width/height;camera.updateProjectionMatrix();renderer.render(scene,camera);start();}
  function move(event:PointerEvent){const rect=renderer.domElement.getBoundingClientRect();mouse.set((event.clientX-rect.left)/rect.width*2-1,-(event.clientY-rect.top)/rect.height*2+1);if(!reducedMotion){px=mouse.x;py=mouse.y;}raycaster.setFromCamera(mouse,camera);renderer.domElement.style.cursor=raycaster.intersectObjects(nodes).length?'pointer':'default';}
  function leave(){px=0;py=0;}
  function select(){raycaster.setFromCamera(mouse,camera);const hit=raycaster.intersectObjects(nodes)[0];if(hit)selectRef.current?.(hit.object.userData.process);}
  function visibility(){focused=!document.hidden;focused?start():stop();}
  function lost(event:Event){event.preventDefault();stop();setFallback(true);}
  const resizeObserver=new ResizeObserver(resize);resizeObserver.observe(element);
  const intersection=new IntersectionObserver(entries=>{inView=entries[0]?.isIntersecting??true;inView?start():stop();});intersection.observe(element);
  renderer.domElement.addEventListener('pointermove',move);renderer.domElement.addEventListener('pointerleave',leave);renderer.domElement.addEventListener('click',select);renderer.domElement.addEventListener('webglcontextlost',lost);document.addEventListener('visibilitychange',visibility);
  resize();start();
  return()=>{disposed=true;stop();resizeObserver.disconnect();intersection.disconnect();document.removeEventListener('visibilitychange',visibility);renderer.domElement.removeEventListener('pointermove',move);renderer.domElement.removeEventListener('pointerleave',leave);renderer.domElement.removeEventListener('click',select);renderer.domElement.removeEventListener('webglcontextlost',lost);scene.traverse(object=>{if(object instanceof THREE.Mesh||object instanceof THREE.Points||object instanceof THREE.Line){object.geometry.dispose();for(const m of Array.isArray(object.material)?object.material:[object.material])m.dispose();}});renderer.dispose();renderer.domElement.remove();};
 },[signature,reducedMotion]);
 return <div ref={host} className={'orb'+(fallback?' fallback':'')} role="img" aria-label={'Topologia 3D de '+(signature?signature.split('\u0000').length:0)+' aplicativos. Os dados completos estão na tabela de conexões.'}>{fallback&&<div className="orb-fallback"><div/><span>3D indisponível. Use a visualização em lista.</span></div>}</div>;
}

