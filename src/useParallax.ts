import {useEffect,type RefObject} from 'react';
export function useParallax(root:RefObject<HTMLElement|null>,reduced:boolean){
 useEffect(()=>{
  const element=root.current;if(!element||reduced)return;
  let frame=0,scrollFrame=0,target:HTMLElement|null=null,x=0,y=0;
  const reset=(node:HTMLElement|null)=>{node?.style.setProperty('--px','0');node?.style.setProperty('--py','0');};
  const move=(event:PointerEvent)=>{
   if(event.pointerType==='touch')return;
   const node=(event.target as Element).closest<HTMLElement>('[data-parallax]');
   if(target&&target!==node)reset(target);
   target=node;if(!node)return;
   const rect=node.getBoundingClientRect();x=Math.max(-1,Math.min(1,(event.clientX-rect.left)/rect.width*2-1));y=Math.max(-1,Math.min(1,(event.clientY-rect.top)/rect.height*2-1));
   if(!frame)frame=requestAnimationFrame(()=>{frame=0;target?.style.setProperty('--px',x.toFixed(3));target?.style.setProperty('--py',y.toFixed(3));});
  };
  const leave=()=>{reset(target);target=null;};
  const scroll=()=>{if(!scrollFrame)scrollFrame=requestAnimationFrame(()=>{scrollFrame=0;const hero=element.querySelector<HTMLElement>('[data-parallax="hero"]');if(hero){const rect=hero.getBoundingClientRect();hero.style.setProperty('--scroll',String(Math.max(-1,Math.min(1,(rect.top-180)/innerHeight))));}});};
  element.addEventListener('pointermove',move,{passive:true});element.addEventListener('pointerleave',leave);window.addEventListener('scroll',scroll,{passive:true});scroll();
  return()=>{cancelAnimationFrame(frame);cancelAnimationFrame(scrollFrame);element.removeEventListener('pointermove',move);element.removeEventListener('pointerleave',leave);window.removeEventListener('scroll',scroll);element.querySelectorAll<HTMLElement>('[data-parallax]').forEach(node=>{reset(node);node.style.setProperty('--scroll','0');});};
 },[root,reduced]);
}

