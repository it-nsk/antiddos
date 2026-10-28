#!/usr/bin/env python3
"""Isolated Nginx -> real challenge runtime over UDS; synthetic feed only."""
import argparse, base64, grp, http.client, http.server, json, os, pathlib, shlex, signal, socket, socketserver, sqlite3, ssl, subprocess, sys, time, urllib.error, urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[3]

class Feed(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        raw = pathlib.Path(self.server.data).read_bytes()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)

class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

class Fault(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        self.send_response(503); self.end_headers()

if len(sys.argv) == 3 and sys.argv[1] == '--fault':
    with UnixServer(sys.argv[2], Fault) as server: server.serve_forever()
    sys.exit(0)

if len(sys.argv) == 4 and sys.argv[1] == '--feed':
    with UnixServer(sys.argv[2], Feed) as server:
        server.data = sys.argv[3]
        server.serve_forever()
    sys.exit(0)

parser = argparse.ArgumentParser(); parser.add_argument('--output', required=True); args = parser.parse_args()
d = pathlib.Path(args.output).resolve(); d.mkdir(parents=True, exist_ok=True)
checks=[]; processes=[]; auxiliary_processes=[]; logs=[]; commands=[]; blocked=[]
def check(name, condition, detail=''):
    checks.append(dict(name=name, ok=bool(condition), detail=str(detail))); print(('PASS ' if condition else 'FAIL ')+name+' '+str(detail), flush=True)
def run(cmd, **kwargs):
    p=subprocess.run(cmd, capture_output=True, text=True, **kwargs); commands.append({'command':cmd,'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}); return p
def start(name, cmd, env=None):
    f=open(d/(name+'.log'),'ab',buffering=0); logs.append(f)
    p=subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=ROOT, env=env, start_new_session=True); processes.append((name,p,cmd)); return p
def port():
    with socket.socket() as s: s.bind(('127.0.0.1',0)); return s.getsockname()[1]
def waitpath(path, proc):
    for _ in range(200):
        if path.exists(): return
        if proc.poll() is not None: raise RuntimeError('process exited '+str(proc.args))
        time.sleep(.05)
    raise RuntimeError('socket not ready '+str(path))
def waittcp(listen_port, proc):
    for _ in range(200):
        if proc.poll() is not None: raise RuntimeError('process exited '+str(proc.args))
        try:
            with socket.create_connection(('127.0.0.1',listen_port),timeout=.1): return
        except OSError: time.sleep(.05)
    raise RuntimeError('port not ready '+str(listen_port))
def request(path, method='GET', data=None, headers=None):
    req=urllib.request.Request(base+path, data=data, method=method, headers={'Host':f'example.test:{https}', **(headers or {})})
    try: r=opener.open(req,timeout=4)
    except urllib.error.HTTPError as e: r=e
    with r: return r.status,r.read().decode(),dict(r.headers)
def direct_check():
    s=socket.socket(socket.AF_UNIX); s.settimeout(2); s.connect(str(checkpath))
    s.sendall(b'GET /__antiddos_check HTTP/1.1\r\nHost: checker\r\nX-AntiDDoS-Host: example.test\r\nX-AntiDDoS-Authority: example.test\r\nX-AntiDDoS-Scheme: https\r\nX-AntiDDoS-IP: 127.0.0.1\r\nX-AntiDDoS-URI: /protected\r\nX-AntiDDoS-Method: GET\r\nConnection: close\r\n\r\n')
    r=http.client.HTTPResponse(s); r.begin(); value=(r.status,r.getheader('X-AntiDDoS-Reason')); r.read(); s.close(); return value
def until_status(want, timeout=6):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        code,body,_=request('/protected')
        if code==want: return code,body
        time.sleep(.1)
    return code,body

try:
    (d/'environment.json').write_text(json.dumps({x:run([x,'-v' if x=='nginx' else 'version']).stderr+commands[-1]['stdout'] for x in ('nginx','go')},indent=2))
    env={**os.environ,'GOCACHE':'/tmp/antiddos-go-cache-20261021'}
    p=run(['go','build','-o',str(d/'antiddos'),'./cmd/antiddos'],cwd=ROOT,env=env); check('build checker',p.returncode==0,p.stderr)
    if p.returncode: raise RuntimeError('build failed')
    probe_env={**env,'CGO_ENABLED':'0'}
    p=run(['go','build','-o',str(d/'uds-probe'),'./tests/integration/softblock/uds_probe.go'],cwd=ROOT,env=probe_env); check('build UDS permission probe',p.returncode==0,p.stderr)
    if p.returncode: raise RuntimeError('probe build failed')
    p=run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(d/'tls.key'),'-out',str(d/'tls.crt'),'-subj','/CN=example.test','-addext','subjectAltName=DNS:example.test']); check('temporary TLS certificate',p.returncode==0)
    if p.returncode: raise RuntimeError('openssl failed')
    secret=lambda:base64.b64encode(os.urandom(32)).decode()
    (d/'keys.json').write_text(json.dumps({'provider_secret':secret(),'current':{'id':'temporary','secret':secret()},'previous':[]})); (d/'keys.json').chmod(0o600)
    feedpath=d/'feed.sock'; checkpath=d/'check'/'check.sock'; upstream=port(); fastcgi=port(); https=port()
    checker=start('checker',[str(d/'antiddos'),'challenge','--credential-file',str(d/'keys.json'),'--feed-socket',str(feedpath),'--check-socket',str(checkpath),'--check-group',grp.getgrgid(os.getgid()).gr_name]); waitpath(checkpath,checker)
    app=start('upstream',[sys.executable,str(ROOT/'tests/integration/softblock/nginx_contract.py'),'--serve','upstream',str(upstream)])
    php_script=d/'fixture.php'
    php_script.write_text('<?php\nheader("Content-Type: application/json");\n$uri=$_SERVER["REQUEST_URI"] ?? "";\nforeach ([401,403,429,500] as $status) { if (str_contains($uri, "/".$status)) { http_response_code($status); break; } }\necho json_encode(["method"=>$_SERVER["REQUEST_METHOD"] ?? "", "uri"=>$uri, "body"=>file_get_contents("php://input")]);\n')
    fpm_config=d/'php-fpm.conf'
    fpm_config.write_text(f'''[global]
pid = {d/'php-fpm.pid'}
error_log = {d/'php-fpm-error.log'}
daemonize = no
[www]
user = {os.environ.get('USER','nobody')}
group = {grp.getgrgid(os.getgid()).gr_name}
listen = 127.0.0.1:{fastcgi}
pm = static
pm.max_children = 2
clear_env = no
catch_workers_output = yes
''')
    fcgi=start('php-fpm',['/usr/sbin/php-fpm8.4','-F','-y',str(fpm_config)])
    waittcp(upstream,app); waittcp(fastcgi,fcgi)
    headers='''proxy_set_header X-AntiDDoS-IP $remote_addr;
      proxy_set_header X-AntiDDoS-Host $host;
      proxy_set_header X-AntiDDoS-Authority $http_host;
      proxy_set_header X-AntiDDoS-URI $request_uri;
      proxy_set_header X-AntiDDoS-Method $request_method;
      proxy_set_header X-AntiDDoS-Scheme $scheme;
      proxy_set_header X-Forwarded-For "";
      proxy_set_header Authorization "";
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection $http_connection;'''
    config=f'''worker_processes 1;
pid {d}/nginx.pid;
error_log {d}/nginx-error.log notice;
events {{ worker_connections 128; }}
http {{
 map $sent_http_x_antiddos_response_origin $antiddos_response_origin {{ challenge challenge; service service; default application; }}
 log_format antiddos '$remote_addr [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $antiddos_response_origin';
 access_log {d}/access.log antiddos;
 server {{
  listen 127.0.0.1:{https} ssl;
  server_name example.test;
  ssl_certificate {d}/tls.crt; ssl_certificate_key {d}/tls.key;
  location = /_check {{
   internal;
   proxy_pass http://unix:{checkpath}:/__antiddos_check;
   proxy_pass_request_body off; proxy_set_header Content-Length "";
   {headers}
   proxy_set_header Cookie $http_cookie;
   proxy_connect_timeout 200ms; proxy_read_timeout 200ms; proxy_send_timeout 200ms;
   proxy_intercept_errors on; error_page 500 501 502 503 504 505 506 507 508 510 511 = @fail_open;
  }}
  location @fail_open {{ return 204; }}
  location @challenge {{
   if ($auth_decision != challenge) {{ return 403; }}
   rewrite ^ /__antiddos/challenge? break;
   proxy_pass http://unix:{checkpath}:;
   {headers}
   proxy_set_header Cookie $http_cookie;
   add_header X-AntiDDoS-Response-Origin challenge always;
  }}
  location = /__antiddos/verify {{
   auth_request off; proxy_pass http://unix:{checkpath}:;
   {headers}
   add_header X-AntiDDoS-Response-Origin service always;
  }}
  location ^~ /__antiddos/assets/ {{
   auth_request off; proxy_pass http://unix:{checkpath}:;
   {headers}
   add_header X-AntiDDoS-Response-Origin service always;
  }}
  location ^~ /protected {{
   auth_request /_check;
   auth_request_set $auth_decision $upstream_http_x_antiddos_decision;
   error_page 403 =429 @challenge;
   proxy_intercept_errors off;
   proxy_hide_header X-AntiDDoS-Response-Origin;
   add_header X-AntiDDoS-Response-Origin application always;
   proxy_pass http://127.0.0.1:{upstream};
  }}
  location = /trigger {{
   auth_request /_check;
   auth_request_set $auth_decision $upstream_http_x_antiddos_decision;
   error_page 403 =429 @challenge;
   proxy_intercept_errors off;
   add_header X-AntiDDoS-Response-Origin application always;
   proxy_pass http://127.0.0.1:{upstream};
  }}
  location = /rewrite {{ rewrite ^ /protected?rewritten=1 last; }}
  location = /native-deny {{ deny all; }}
  location ^~ /fcgi/ {{
   auth_request /_check;
   auth_request_set $auth_decision $upstream_http_x_antiddos_decision;
   error_page 403 =429 @challenge;
   fastcgi_intercept_errors off;
   include /etc/nginx/fastcgi_params;
   fastcgi_param SCRIPT_FILENAME {php_script};
   fastcgi_param REQUEST_URI $request_uri;
   fastcgi_param REQUEST_METHOD $request_method;
   fastcgi_param CONTENT_LENGTH $content_length;
   fastcgi_param CONTENT_TYPE $content_type;
   fastcgi_pass 127.0.0.1:{fastcgi};
  }}
  location / {{ return 404; }}
 }}
}}
'''
    (d/'nginx.conf').write_text(config)
    p=run(['nginx','-t','-e',str(d/'nginx-bootstrap.log'),'-p',str(d)+'/', '-c','nginx.conf']); (d/'nginx-test.log').write_text(p.stdout+p.stderr); check('nginx -t',p.returncode==0,p.stderr)
    if p.returncode: raise RuntimeError('nginx config invalid')
    nginx=start('nginx',['nginx','-e',str(d/'nginx-bootstrap.log'),'-p',str(d)+'/', '-c','nginx.conf','-g','daemon off; master_process off;'])
    base=f'https://127.0.0.1:{https}'; opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    for _ in range(100):
        try: code,body=until_status(200,.2); break
        except Exception: time.sleep(.05)
    direct=direct_check()
    check('starting checker returns 204 before first feed',direct==(204,'no_snapshot'),direct)
    check('starting checker fails open through Nginx',code==200,body[:150])
    daemon_config={
      'log_sources':{'web':{'path':str(d/'access.log'),'format':'nginx_custom','log_format':'$remote_addr [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" $antiddos_response_origin'}},
      'database_path':str(d/'state.sqlite'),'start_position':'end','block_mode':'soft_block','block_duration':'10m',
      'soft_block':{'cookie_ttl':'30m','sites':{'main':{'hosts':['example.test'],'log_sources':['web']}}},
      'engine':{'rules':[{'id':'trigger','log_source':'web','path_regex':'^/trigger$','window':'5s','threshold':1,'group_by':'ip'}]}}
    (d/'daemon-config.json').write_text(json.dumps(daemon_config,indent=2)+'\n')
    daemon=start('daemon',[str(d/'antiddos'),'run','--config',str(d/'daemon-config.json'),'--soft-feed-socket',str(feedpath),'--soft-feed-group',grp.getgrgid(os.getgid()).gr_name]); waitpath(feedpath,daemon)
    for _ in range(60):
        direct=direct_check()
        if direct==(204,'no_decision'): break
        time.sleep(.1)
    check('authorized socket client and no-decision 204',direct==(204,'no_decision'),direct)
    check('no decision allows upstream',code==200,body[:150])
    container_base=f'antiddos-uds-{os.getpid()}'
    docker_base=['docker','run','--rm','--network','none','--mount',f'type=bind,src={d},dst=/fixture,readonly']
    outsider=run(docker_base+['--name',container_base+'-outsider','--user','65534:65534','ubuntu:24.04','/fixture/uds-probe','/fixture/check/check.sock'])
    check('outsider socket denied',outsider.returncode!=0 and ('permission denied' in outsider.stderr.lower() or 'connect: permission denied' in outsider.stderr.lower()),outsider.stderr.strip())
    group_client=run(docker_base+['--name',container_base+'-group','--user',f'65534:{os.getgid()}','ubuntu:24.04','/fixture/uds-probe','/fixture/check/check.sock'])
    check('separate user in authorized group connects',group_client.returncode==0,group_client.stderr.strip())
    containers=run(['docker','ps','-a','--filter',f'name={container_base}','--format','{{.Names}}'])
    check('permission containers removed',containers.returncode==0 and containers.stdout.strip()=='',(containers.stdout+containers.stderr).strip())
    code,body,_=request('/rewrite'); check('internal rewrite preserves upstream behavior',code==200 and json.loads(body).get('uri')=='/protected?rewritten=1',f'status={code} body={body[:120]}')
    code,body,_=request('/native-deny'); check('native Nginx deny remains 403',code==403 and '<altcha-widget' not in body,f'status={code}')
    code,body,_=request('/fcgi/ok'); check('FastCGI no-decision allow',code==200 and json.loads(body).get('uri')=='/fcgi/ok',f'status={code} body={body[:120]}')
    payload=b'fastcgi-preserved-body'; code,body,_=request('/fcgi/post',method='POST',data=payload)
    check('FastCGI POST bypass preserves body',code==200 and json.loads(body).get('method')=='POST' and json.loads(body).get('body')==payload.decode(),f'status={code} body={body[:120]}')
    for status in (401,403,429,500):
        code,body,_=request(f'/protected/status/{status}'); check('application status '+str(status),code==status and body==f'upstream-{status}',f'status={code}')
        code,body,_=request(f'/fcgi/{status}'); check('FastCGI application status '+str(status),code==status and json.loads(body).get('uri')==f'/fcgi/{status}',f'status={code} body={body[:120]}')
    code,body,_=request('/trigger'); check('threshold request initially reaches upstream',code==200,f'status={code}')
    code,body=until_status(429); direct=direct_check(); check('active decision checker 403',direct==(403,'decision_active'),direct); check('threshold decision shows ALTCHA',code==429 and '<altcha-widget' in body, f'status={code}')
    with sqlite3.connect(d/'state.sqlite') as db:
        decision=db.execute("SELECT site_id,rule_id,source_id,ip FROM soft_block_decisions").fetchone()
    check('decision persisted in temporary SQLite',decision==('main','trigger','web','127.0.0.1'),decision)
    forged={'X-AntiDDoS-IP':'203.0.113.77','X-AntiDDoS-URI':'/forged','X-AntiDDoS-Method':'POST','X-AntiDDoS-Scheme':'http'}
    code,body,_=request('/protected?forged=1',headers=forged); check('forged metadata overwritten',code==429 and '<altcha-widget' in body,f'status={code}')
    code,body,_=request('/protected?upgrade=1',headers={'Upgrade':'websocket','Connection':'upgrade'}); check('upgrade bypasses challenge',code==200,f'status={code} body={body[:120]}')
    for method in ('POST','PUT','DELETE','OPTIONS'):
        code,body,_=request('/protected?bypass=1',method,b'preserved-body',{'Authorization':'Bearer must-not-reach-checker'});
        try: observed=json.loads(body)
        except Exception: observed={}
        check('bypass '+method,code==200 and observed.get('method')==method and observed.get('uri')=='/protected?bypass=1' and observed.get('body')=='preserved-body',f'status={code} body={body[:120]}')
    browser=start('browser',['node',str(ROOT/'tests/integration/softblock/uds_browser.mjs'),f'https://example.test:{https}',str(d/'browser-results.json')]); browser.wait(timeout=60)
    check('browser proof, verify and pass cookie',browser.returncode==0,(d/'browser.log').read_text()[-800:])
    chrome_pid=int((d/'chrome.pid').read_text().strip())
    for _ in range(50):
        if not pathlib.Path(f'/proc/{chrome_pid}').exists(): break
        time.sleep(.1)
    chrome_stopped=not pathlib.Path(f'/proc/{chrome_pid}').exists()
    auxiliary_processes.append({'name':'chrome','pid':chrome_pid,'command':['/usr/bin/google-chrome'],'status':'stopped' if chrome_stopped else 'running'})
    check('browser process stopped',chrome_stopped,f'pid={chrome_pid}')
    code,_,_=request('/_check'); check('check location internal',code==404,f'status={code}')
    code,_=until_status(429); check('decision remains active before outage',code==429,code)
    daemon.terminate(); daemon.wait(timeout=5); time.sleep(6)
    direct=direct_check(); check('stale feed checker 204',direct==(204,'feed_stale'),direct)
    code,body,_=request('/protected'); check('stale feed fails open',code==200,f'status={code}')
    daemon2=start('daemon-restart',[str(d/'antiddos'),'run','--config',str(d/'daemon-config.json'),'--soft-feed-socket',str(feedpath),'--soft-feed-group',grp.getgrgid(os.getgid()).gr_name]); waitpath(feedpath,daemon2)
    for _ in range(80):
        direct=direct_check()
        if direct==(403,'decision_active'): break
        time.sleep(.1)
    check('feed recovery restores SQLite decision',direct==(403,'decision_active'),direct)
    daemon2.terminate(); daemon2.wait(timeout=5)
    os.kill(checker.pid,signal.SIGSTOP); start_time=time.monotonic()
    try:
        code,body,_=request('/protected'); elapsed=time.monotonic()-start_time; check('checker read timeout fails open',code==200 and elapsed<1,f'status={code} elapsed={elapsed:.3f}s')
    finally: os.kill(checker.pid,signal.SIGCONT)
    checker.terminate(); checker.wait(timeout=5); code,_,_=request('/protected'); check('checker unavailable fails open',code==200,f'status={code}')
    fault=start('fault-503',[sys.executable,str(pathlib.Path(__file__).resolve()),'--fault',str(checkpath)]); waitpath(checkpath,fault)
    code,_,_=request('/protected'); check('checker 503 fails open',code==200,f'status={code}')
    log_lines=(d/'access.log').read_text().splitlines()
    markers={line.rsplit(' ',1)[-1] for line in log_lines}
    challenge_429=any(' 429 ' in line and line.endswith(' challenge') for line in log_lines)
    application_429=any(' /protected/status/429 ' in line and line.endswith(' application') for line in log_lines)
    check('access markers',markers=={'application','challenge','service'} and challenge_429 and application_429,f'markers={sorted(markers)}')
except Exception as e:
    check('runner exception',False,repr(e))
finally:
    for name,p,cmd in reversed(processes):
        if p.poll() is None:
            p.terminate()
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
    for f in logs: f.close()
    manifest=[dict(name=n,pid=p.pid,command=c,status='stopped' if p.poll() is not None else 'running',exit=p.returncode) for n,p,c in processes]
    manifest.extend(auxiliary_processes)
    (d/'processes.json').write_text(json.dumps(manifest,indent=2)+'\n')
    (d/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
    (d/'commands.log').write_text(''.join(f"{shlex.join(item['command'])} exit={item['exit']}\n" for item in commands))
    (d/'results.json').write_text(json.dumps({'checks':checks,'blocked':blocked},indent=2)+'\n')
    for name in ('keys.json','tls.key'):
        try: (d/name).unlink()
        except FileNotFoundError: pass
    print('Artifacts:',d,flush=True)
sys.exit(1 if any(not x['ok'] for x in checks) else 2 if blocked else 0)
