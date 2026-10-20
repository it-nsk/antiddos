import {spawn,execFileSync} from 'node:child_process';
import {mkdirSync,mkdtempSync,writeFileSync,existsSync,openSync,closeSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const port=process.env.ANTIDDOS_E2E_PORT||'18082';
const dir=mkdtempSync('/tmp/antiddos-web-e2e-');
const artifact=path.join(root,'runtime/web-e2e');mkdirSync(artifact,{recursive:true});
const bin=path.join(dir,'antiddos');
execFileSync('go',['build','-o',bin,'./cmd/antiddos'],{cwd:root,stdio:'inherit'});
const config=path.join(dir,'config.json'),users=path.join(dir,'users.sqlite'),socket=path.join(dir,'control.sock');
const password='test-only-long-password';
for(const role of ['admin','viewer'])execFileSync(bin,['user','add','--users-db',users,'--role',role,'--password-stdin',role],{input:password+'\n'});
const log1=path.join(dir,'one.log'),log2=path.join(dir,'two.log');
const rules=[{id:'homepage',log_source:'main',path_regex:'^/$',window:'5s',threshold:5,group_by:'ip',ignore_ips:[]},{id:'login',log_source:'admin',path_regex:'^/login$',window:'5s',threshold:5,group_by:'ip',ignore_ips:['198.51.100.7']}];
writeFileSync(config,JSON.stringify({log_sources:{main:log1,admin:log2},database_path:path.join(dir,'stats.sqlite'),start_position:'end',block_mode:'dry_run',block_duration:'1m',engine:{ignore_ips:['192.0.2.100'],rules}},null,2),{mode:0o600});
function line(time,ip,uri){const d=new Date(time);const stamp=`${String(d.getUTCDate()).padStart(2,'0')}/${['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getUTCMonth()]}/${d.getUTCFullYear()}:${d.toISOString().slice(11,19)} +0000`;return `${ip} - - [${stamp}] "GET ${uri} HTTP/1.1" 200 1024 "-" "web-e2e"\n`}
let contents='';const now=Date.now();let seed=0x5eed;function random(){seed=(seed*1664525+1013904223)>>>0;return seed/0x100000000}
let cursor=now-60*60*1000,burstCount=0;while(cursor<=now-2000){for(let j=0;j<8;j++)contents+=line(cursor+j*100,'192.0.2.10','/');burstCount++;cursor+=(30+Math.floor(random()*31))*1000}
writeFileSync(log1,contents);writeFileSync(log2,Array.from({length:8},(_,i)=>line(now-2000+i*100,'198.51.100.7','/login')).join(''));
const fd=openSync(path.join(artifact,'processes.log'),'w');
let daemon,web,stopping=false;
function startDaemon(fromStart=false){daemon=spawn(bin,['run','--config',config,'--web-socket',socket,...(fromStart?['--from-start']:[])],{stdio:['ignore',fd,fd]});}
startDaemon(true);
writeFileSync(path.join(artifact,'fixture.json'),JSON.stringify({dir,config,users,bin,socket,harnessPID:process.pid,burstCount,expectedRequests:burstCount*8+8}),{mode:0o600});
async function waitFor(check){for(let i=0;i<300;i++){if(check())return;await new Promise(r=>setTimeout(r,100))}throw Error('fixture timeout')}
await waitFor(()=>existsSync(socket));await new Promise(r=>setTimeout(r,55000));
web=spawn(bin,['web','--users-db',users,'--daemon-socket',socket,'--listen',`127.0.0.1:${port}`,'--origin',`http://127.0.0.1:${port}`],{stdio:['ignore',fd,fd]});
web.on('exit',code=>{if(!stopping)process.exit(code||1)});
process.on('SIGUSR1',()=>{daemon.once('exit',()=>startDaemon());daemon.kill('SIGTERM')});
async function stop(){if(stopping)return;stopping=true;for(const child of [web,daemon])if(child&&child.exitCode===null){const ended=new Promise(r=>child.once('exit',r));child.kill('SIGTERM');await ended}closeSync(fd);process.exit(0)}
process.on('SIGTERM',stop);process.on('SIGINT',stop);
