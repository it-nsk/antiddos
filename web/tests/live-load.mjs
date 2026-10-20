import {appendFileSync,readFileSync} from 'node:fs';
const fixture=JSON.parse(readFileSync('../runtime/web-e2e/fixture.json','utf8'));
const config=JSON.parse(readFileSync(fixture.config,'utf8'));
const logfile=Object.values(config.log_sources)[0];
let written=0,burst=0,ipIndex=0;
function stamp(){
 const d=new Date(Date.now()+7*60*60*1000);
 const months=['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
 const pad=n=>String(n).padStart(2,'0');
 return `${pad(d.getUTCDate())}/${months[d.getUTCMonth()]}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0700`;
}
function request(ip,path='/'){
 const bytes=1200+Math.floor(Math.random()*30000);
 appendFileSync(logfile,`${ip} - - [${stamp()}] "GET ${path} HTTP/1.1" 200 ${bytes} "-" "antiddos-live-chart-test/1.0"\n`);
 written++;
}
function randomBurst(){
 const ip=`192.0.2.${50+(ipIndex++%20)}`;
 for(let i=0;i<8;i++)setTimeout(()=>request(ip),i*120);
 burst++;
 setTimeout(randomBurst,30000+Math.floor(Math.random()*30001));
}
console.log(`Appending synthetic Nginx requests to ${logfile}; stop with Ctrl+C`);
const baseline=setInterval(()=>{
 const n=1+Math.floor(Math.random()*2);
 for(let i=0;i<n;i++)request(`198.51.100.${20+Math.floor(Math.random()*20)}`,Math.random()<.7?'/':'/news');
},1000);
const report=setInterval(()=>console.log(`${new Date().toLocaleTimeString()} written=${written} bursts=${burst}`),10000);
setTimeout(randomBurst,2000);
process.on('SIGINT',()=>{clearInterval(baseline);clearInterval(report);console.log(`Stopped: ${written} requests, ${burst} bursts`);process.exit(0)});
