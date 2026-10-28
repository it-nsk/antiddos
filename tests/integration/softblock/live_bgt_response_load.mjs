// Fixed loopback target and bounded load; no cookies or response bodies are saved.
import https from 'node:https';
import {performance} from 'node:perf_hooks';

const samples=[];
for (let i=0;i<20;i++) {
  const start=performance.now();
  const sample=await new Promise(resolve=>{
    const req=https.request({hostname:'127.0.0.1',port:443,servername:'bgt.my',path:'/captcha-demo',method:'GET',headers:{Host:'bgt.my'},rejectUnauthorized:false,timeout:5000},res=>{
      let text='';res.setEncoding('utf8');res.on('data',chunk=>{if(text.length<4096)text+=chunk});
      res.on('end',()=>resolve({status:res.statusCode,kind:text.includes('challenge temporarily unavailable')?'challenge_unavailable':text.includes('altcha-widget')?'challenge_page':'other',ms:performance.now()-start}));
    });
    req.on('timeout',()=>req.destroy());req.on('error',()=>resolve({status:0,kind:'network_error',ms:performance.now()-start}));req.end();
  });
  samples.push(sample);
  if (i<19) await new Promise(resolve=>setTimeout(resolve,500));
}
const latencies=samples.map(x=>x.ms).sort((a,b)=>a-b);
const percentile=p=>Number(latencies[Math.ceil(latencies.length*p)-1].toFixed(2));
const responses={};for(const x of samples){const key=`${x.status} ${x.kind}`;responses[key]=(responses[key]||0)+1}
console.log(JSON.stringify({target:'bgt.my:443 via 127.0.0.1',requests:samples.length,interval_ms:500,responses,latency_ms:{p50:percentile(.5),p95:percentile(.95),p99:percentile(.99),max:percentile(1)}},null,2));
