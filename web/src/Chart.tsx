import {useRef,useState} from 'react';
import type {Point} from './api';
export type Series = {label:string;color:string;value:(p:Point)=>number};
const number=new Intl.NumberFormat('ru',{notation:'compact',maximumFractionDigits:1});
export function Chart({title,unit,points,series,onZoom}:{title:string;unit:string;points:Point[];series:Series[];onZoom:(from:number,to:number)=>void}){
 const svg=useRef<SVGSVGElement>(null);const [start,setStart]=useState<number|null>(null);const [hover,setHover]=useState<number|null>(null);
 const W=800,H=180,L=55,R=15,T=15,B=30;const plotW=W-L-R,plotH=H-T-B;
 const max=Math.max(1,...points.flatMap(p=>series.map(s=>s.value(p))));
 const x=(i:number)=>L+(points.length<=1?0:i/(points.length-1))*plotW;
 const y=(v:number)=>T+plotH-v/max*plotH;
 function index(clientX:number){const rect=svg.current!.getBoundingClientRect();return Math.max(0,Math.min(points.length-1,Math.round(((clientX-rect.left)/rect.width*W-L)/plotW*(points.length-1))))}
 function finish(){if(start!==null&&hover!==null&&Math.abs(start-hover)>1){const a=points[Math.min(start,hover)],b=points[Math.max(start,hover)];onZoom(a.time,b.time+b.interval)}setStart(null)}
 const active=hover===null?null:points[hover];
 return <section className="panel chart"><div className="panel-head"><h2>{title}</h2><span>{unit}</span></div>
 <div className="legend">{series.map(s=><span key={s.label}><i style={{background:s.color}}/>{s.label}{active&&<b>{number.format(s.value(active))}</b>}</span>)}<small>{active?new Date(active.time*1000).toLocaleString('ru'):'Выделите область для увеличения'}</small></div>
 <svg ref={svg} viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`${title}. Выделите период мышью для увеличения.`} onPointerDown={e=>{if(!points.length)return;e.currentTarget.setPointerCapture(e.pointerId);const i=index(e.clientX);setStart(i);setHover(i)}} onPointerMove={e=>setHover(index(e.clientX))} onPointerUp={finish} onPointerCancel={()=>setStart(null)} onPointerLeave={()=>{if(start===null)setHover(null)}}>
 {[0,.5,1].map(t=><g key={t}><line x1={L} x2={W-R} y1={y(t*max)} y2={y(t*max)} stroke="#e8edf3"/><text x={L-8} y={y(t*max)+4} textAnchor="end">{number.format(t*max)}</text></g>)}
 {series.map(s=><polyline key={s.label} points={points.map((p,i)=>`${x(i)},${y(s.value(p))}`).join(' ')} fill="none" stroke={s.color} strokeWidth="2" vectorEffect="non-scaling-stroke"/>)}
 {start!==null&&hover!==null&&<rect x={Math.min(x(start),x(hover))} y={T} width={Math.abs(x(start)-x(hover))} height={plotH} fill="#3d6eeb22"/>}
 {hover!==null&&points[hover]&&<line x1={x(hover)} x2={x(hover)} y1={T} y2={H-B} stroke="#94a3b8" strokeDasharray="3 3"/>}
 {[0,.5,1].map(t=>{const i=Math.round(t*(points.length-1));return points[i]&&<text key={t} x={x(i)} y={H-7} textAnchor={t===0?'start':t===1?'end':'middle'}>{new Date(points[i].time*1000).toLocaleTimeString('ru',{hour:'2-digit',minute:'2-digit'})}</text>})}
 </svg></section>
}
