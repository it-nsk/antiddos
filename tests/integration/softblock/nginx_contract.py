#!/usr/bin/env python3
"""Isolated real-Nginx contract check. Child processes are tracked by Popen."""
import argparse
import http.server
import json
import os
import pathlib
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request


children = []
process_manifest = []
checks = []
blockers = []
skipped = []
requests_seen = []
run_dir = None
command_log = None


def record(name, ok, detail=""):
    checks.append({"name": name, "ok": bool(ok), "detail": str(detail)})
    print(("PASS" if ok else "FAIL") + " " + name + (": " + str(detail) if detail else ""), flush=True)
    if command_log is not None:
        command_log.write(f"check {name!r} exit={0 if ok else 1} detail={detail!r}\n")


def start_child(args, log_name):
    log = open(run_dir / log_name, "ab", buffering=0)
    proc = subprocess.Popen(args, cwd=run_dir, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    children.append((proc, log))
    process_manifest.append({"pid": proc.pid, "command": args, "status": "running"})
    with open(run_dir / "pids.txt", "a") as pids:
        pids.write(f"{proc.pid} running {' '.join(args)}\n")
    return proc


def stop_child(proc):
    for current, log in list(children):
        if current is proc:
            if current.poll() is None:
                current.terminate()
                try:
                    current.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    current.kill()
                    current.wait(timeout=2)
            log.close()
            children.remove((current, log))
            for entry in process_manifest:
                if entry["pid"] == current.pid:
                    entry["status"] = "stopped"
            with open(run_dir / "pids.txt", "a") as pids:
                pids.write(f"{current.pid} stopped exit={current.returncode}\n")
            return


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def ready(url, proc, timeout=5):
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited before ready: {proc.args}")
        try:
            parsed = urllib.parse.urlparse(url)
            with socket.create_connection((parsed.hostname, parsed.port), timeout=.2):
                return True
        except Exception as exc:
            last_error = repr(exc)
            time.sleep(.05)
    raise RuntimeError(f"service not ready: {url}; last error: {last_error}; process status: {proc.poll()}")


class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def send(self, status, body=b"", headers=None):
        self.send_response(status)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        print(f"request role={self.server.role} path={self.path}", flush=True)
        role = self.server.role
        if self.path == "/health":
            self.send(200, b"ready")
            return
        if role == "checker":
            item = {key.lower(): value for key, value in self.headers.items()}
            item["requestline"] = self.requestline
            item["cookie_seen"] = bool(item.get("cookie"))
            item.pop("cookie", None)
            requests_seen.append(item)
            mode = self.headers.get("X-Test-Mode", "allow")
            method = self.headers.get("X-AntiDDoS-Method", "GET")
            if mode == "slow":
                time.sleep(1)
            bypass = method not in ("GET", "HEAD")
            status = 204 if bypass else 403 if mode == "challenge" else 500 if mode == "error" else 204
            decision = "bypass_method" if bypass else "challenge" if status == 403 else "allow"
            item["response_status"] = status
            item["response_decision"] = decision
            print(json.dumps(item, sort_keys=True), flush=True)
            self.send(status, headers={"X-AntiDDoS-Decision": decision})
            return
        if "/status/" in self.path:
            status = int(self.path.rsplit("/status/", 1)[1].split("/", 1)[0])
            self.send(status, f"upstream-{status}".encode(), {"Content-Type": "text/plain"})
            return
        body = json.dumps({"method": self.command, "uri": self.path, "body": ""}, sort_keys=True).encode()
        self.send(200, body, {"Content-Type": "application/json"})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size)
        response = json.dumps({"method": self.command, "uri": self.path, "body": body.decode(errors="replace")}, sort_keys=True).encode()
        self.send(200, response, {"Content-Type": "application/json"})

    do_PUT = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST


def fastcgi_record(record_type, request_id, content):
    padding = (8 - (len(content) % 8)) % 8
    return struct.pack("!BBHHBB", 1, record_type, request_id, len(content), padding, 0) + content + (b"\0" * padding)


def read_exact(stream, count):
    data = b""
    while len(data) < count:
        part = stream.recv(count - len(data))
        if not part:
            raise EOFError
        data += part
    return data


def parse_fastcgi_params(raw):
    result = {}
    offset = 0
    while offset < len(raw):
        first = raw[offset]
        offset += 1
        if first & 0x80:
            nlen = struct.unpack("!I", raw[offset:offset + 4])[0]
            offset += 4
        else:
            nlen = first
        first = raw[offset]
        offset += 1
        if first & 0x80:
            vlen = struct.unpack("!I", raw[offset:offset + 4])[0]
            offset += 4
        else:
            vlen = first
        name = raw[offset:offset + nlen].decode()
        offset += nlen
        value = raw[offset:offset + vlen].decode()
        offset += vlen
        result[name] = value
    return result


def fastcgi_client(conn):
    try:
        request_id = 1
        params, body = b"", b""
        while True:
            header = read_exact(conn, 8)
            version, kind, rid, length, padding, _ = struct.unpack("!BBHHBB", header)
            content = read_exact(conn, length)
            if padding:
                read_exact(conn, padding)
            request_id = rid
            if kind == 4:
                if not content:
                    break
                params += content
            elif kind == 5:
                if not content:
                    break
                body += content
        env = parse_fastcgi_params(params)
        method = env.get("REQUEST_METHOD", "GET")
        uri = env.get("REQUEST_URI", "")
        status = 200
        if "/401" in uri:
            status = 401
        elif "/403" in uri:
            status = 403
        elif "/429" in uri:
            status = 429
        elif "/500" in uri:
            status = 500
        payload = (f"Status: {status} Test\r\nContent-Type: application/json\r\n\r\n" +
                   json.dumps({"method": method, "uri": uri, "body": body.decode(errors="replace")}, sort_keys=True)).encode()
        conn.sendall(fastcgi_record(6, request_id, payload) + fastcgi_record(6, request_id, b"") +
                     fastcgi_record(3, request_id, struct.pack("!IB3s", 0, 0, b"\0\0\0")))
    except (EOFError, OSError, struct.error):
        pass
    finally:
        conn.close()


class FastCGIServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def process_request(self, request, client_address):
        threading.Thread(target=fastcgi_client, args=(request,), daemon=True).start()


def serve(role, listen_port):
    if role == "fastcgi":
        server = FastCGIServer(("127.0.0.1", listen_port), socketserver.BaseRequestHandler)
        # The server dispatches protocol connections in get_request; its handler is unused.
        server.serve_forever()
    else:
        server = ReusableTCPServer(("127.0.0.1", listen_port), FixtureHandler)
        server.role = role
        print(f"fixture ready role={role} port={listen_port}", flush=True)
        server.serve_forever()


def http_request(url, method="GET", body=None, headers=None):
    request = urllib.request.Request(url, data=body, method=method, headers=headers or {})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl_context))
    try:
        with opener.open(request, timeout=3) as response:
            return response.status, response.read().decode(errors="replace"), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace"), dict(error.headers)


def check(name, condition, detail=""):
    record(name, condition, detail)
    if not condition:
        raise AssertionError(name)


def main():
    global run_dir, ssl_context, command_log
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    run_dir = pathlib.Path(args.output).resolve()
    signal.signal(signal.SIGINT, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "pids.txt").write_text("")
    command_log = open(run_dir / "commands.log", "w", buffering=1)
    nginx = subprocess.run(["nginx", "-v"], text=True, capture_output=True)
    version = (nginx.stderr or nginx.stdout).strip()
    nginx_build = subprocess.run(["nginx", "-V"], text=True, capture_output=True)
    php_fpm = subprocess.run(["bash", "-lc", "command -v php-fpm || command -v php-fpm8.4 || command -v php-fpm8.3 || command -v php-fpm8.2 || command -v php-fpm8.1"], text=True, capture_output=True).stdout.strip()
    fpm_version = subprocess.run([php_fpm, "-v"], text=True, capture_output=True).stdout.strip() if php_fpm else "not installed"
    record("environment", True, f"{version}; Python {sys.version.split()[0]}; PHP-FPM={'available: ' + php_fpm if php_fpm else 'not installed'}")
    command_log.write(f"nginx -v exit={nginx.returncode}: {version}\nnginx -V exit={nginx_build.returncode}\npython3 --version exit=0: {sys.version.split()[0]}\n")
    if php_fpm:
        command_log.write(f"{php_fpm} -v exit=0: {fpm_version.splitlines()[0] if fpm_version else 'version output empty'}\n")
    else:
        command_log.write("php-fpm version check exit=127: binary not found\n")
    (run_dir / "environment.json").write_text(json.dumps({"nginx": version, "nginx_build": nginx_build.stderr or nginx_build.stdout, "python": sys.version, "php_fpm": {"path": php_fpm, "version": fpm_version} if php_fpm else None}, indent=2) + "\n")
    auth_port, upstream_port, fastcgi_port, https_port = (port() for _ in range(4))
    ssl_context = __import__("ssl")._create_unverified_context()
    cert = run_dir / "cert.pem"
    key = run_dir / "key.pem"
    try:
        cert_proc = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=softblock.test", "-keyout", str(key), "-out", str(cert)], text=True, capture_output=True)
        command_log.write(f"openssl req ... exit={cert_proc.returncode}\n")
        check("temporary HTTPS certificate", cert_proc.returncode == 0, cert_proc.stderr[-300:])
        key.chmod(0o600)
        for role, listen_port in (("checker", auth_port), ("upstream", upstream_port)):
            proc = start_child([sys.executable, str(pathlib.Path(__file__).resolve()), "--serve", role, str(listen_port)], f"{role}.log")
            ready(f"http://127.0.0.1:{listen_port}/health", proc)
        fastcgi_location = ""
        if php_fpm:
            php_script = run_dir / "fixture.php"
            php_script.write_text('''<?php
header("Content-Type: application/json");
$uri = $_SERVER["REQUEST_URI"] ?? "";
foreach ([401, 403, 429, 500] as $status) { if (str_contains($uri, "/" . $status)) { http_response_code($status); break; } }
echo json_encode(["method" => $_SERVER["REQUEST_METHOD"] ?? "", "uri" => $uri, "body" => file_get_contents("php://input")]);
''')
            fpm_config = run_dir / "php-fpm.conf"
            fpm_config.write_text(f'''[global]
pid = {run_dir / 'php-fpm.pid'}
error_log = {run_dir / 'php-fpm-error.log'}
daemonize = no
[www]
user = {os.environ.get('USER', 'nobody')}
group = nogroup
listen = 127.0.0.1:{fastcgi_port}
pm = static
pm.max_children = 2
clear_env = no
catch_workers_output = yes
''')
            fpm_proc = start_child([php_fpm, "-F", "-y", str(fpm_config)], "php-fpm.log")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if fpm_proc.poll() is not None:
                    raise RuntimeError("isolated PHP-FPM exited; see php-fpm.log")
                try:
                    with socket.create_connection(("127.0.0.1", fastcgi_port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError("isolated PHP-FPM did not open its loopback listener")
            fastcgi_location = f'''    location ^~ /fcgi/ {{
      auth_request /_check;
      auth_request_set $auth_decision $upstream_http_x_antiddos_decision;
      error_page 403 = @auth_gate;
      fastcgi_intercept_errors off;
      add_header X-AntiDDoS-Response-Origin application always;
      fastcgi_param QUERY_STRING $query_string;
      fastcgi_param CONTENT_TYPE $content_type;
      fastcgi_param CONTENT_LENGTH $content_length;
      fastcgi_param SCRIPT_FILENAME {php_script};
      fastcgi_param SCRIPT_NAME /fixture.php;
      fastcgi_param REQUEST_URI $request_uri;
      fastcgi_param REQUEST_METHOD $request_method;
      fastcgi_param DOCUMENT_URI $document_uri;
      fastcgi_param DOCUMENT_ROOT /;
      fastcgi_param SERVER_PROTOCOL $server_protocol;
      fastcgi_param GATEWAY_INTERFACE CGI/1.1;
      fastcgi_param SERVER_SOFTWARE nginx;
      fastcgi_param REMOTE_ADDR $remote_addr;
      fastcgi_param REMOTE_PORT $remote_port;
      fastcgi_param SERVER_ADDR $server_addr;
      fastcgi_param SERVER_PORT $server_port;
      fastcgi_param SERVER_NAME $server_name;
      fastcgi_pass 127.0.0.1:{fastcgi_port};
    }}'''
        else:
            blockers.append("php-fpm dependency missing; FastCGI checks were not run")
            skipped.extend(["FastCGI statuses 401/403/429/500", "FastCGI POST body preservation"])
        config = f'''worker_processes 1;
pid {run_dir / 'nginx.pid'};
error_log {run_dir / 'nginx-error.log'} notice;
events {{ worker_connections 128; }}
http {{
  map $sent_http_x_antiddos_response_origin $antiddos_response_origin {{
    challenge challenge;
    service service;
    default application;
  }}
  log_format antiddos "$request_method $request_uri $status $antiddos_response_origin";
  access_log {run_dir / 'access.log'} antiddos;
  server {{
    listen 127.0.0.1:{https_port} ssl;
    server_name softblock.test;
    ssl_certificate {cert}; ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    location = /_check {{
      internal;
      proxy_pass http://127.0.0.1:{auth_port}/check;
      proxy_pass_request_body off;
      proxy_set_header Content-Length "";
      proxy_set_header Authorization "";
      proxy_set_header X-Forwarded-For "";
      proxy_set_header X-AntiDDoS-IP $remote_addr;
      proxy_set_header X-AntiDDoS-Host $host;
      proxy_set_header X-AntiDDoS-URI $request_uri;
      proxy_set_header X-AntiDDoS-Method $request_method;
      proxy_set_header X-AntiDDoS-Scheme $scheme;
      proxy_set_header X-Test-Mode $test_mode;
      proxy_set_header Cookie $http_cookie;
      proxy_connect_timeout 200ms; proxy_read_timeout 200ms; proxy_send_timeout 200ms;
      proxy_intercept_errors on;
      error_page 500 502 504 = @auth_fail_open;
    }}
    location @auth_fail_open {{ return 204; }}
    location @auth_gate {{
      add_header X-AntiDDoS-Response-Origin challenge always;
      if ($auth_decision = challenge) {{ return 429 "local challenge page\\n"; }}
      return 403;
    }}
    location = /__antiddos/ {{ add_header X-AntiDDoS-Response-Origin service always; default_type text/plain; return 200 "local challenge service"; }}
    location = /__antiddos/challenge {{ add_header X-AntiDDoS-Response-Origin service always; default_type text/plain; return 200 "local challenge service"; }}
    location = /__antiddos/verify {{ add_header X-AntiDDoS-Response-Origin service always; default_type text/plain; return 200 "local verify service"; }}
    location ^~ /__antiddos/assets/ {{ add_header X-AntiDDoS-Response-Origin service always; default_type application/javascript; return 200 "/* local fixture asset */"; }}
    location ^~ /protected {{
      set $test_mode $arg_mode;
      auth_request /_check;
      auth_request_set $auth_decision $upstream_http_x_antiddos_decision;
      error_page 403 = @auth_gate;
      proxy_intercept_errors off;
      proxy_hide_header X-AntiDDoS-Response-Origin;
      add_header X-AntiDDoS-Response-Origin application always;
      proxy_pass http://127.0.0.1:{upstream_port};
    }}
    location = /native-deny {{
      auth_request /_check;
      auth_request_set $auth_decision $upstream_http_x_antiddos_decision;
      deny all;
    }}
    location = /rewrite {{ rewrite ^ /protected?rewritten=1 last; }}
{fastcgi_location}
    location / {{ return 404; }}
  }}
}}
'''
        (run_dir / "nginx.conf").write_text(config)
        test = subprocess.run(["nginx", "-t", "-e", str(run_dir / "nginx-bootstrap.log"), "-p", str(run_dir) + "/", "-c", "nginx.conf"], text=True, capture_output=True)
        command_log.write(f"nginx -t -e {run_dir}/nginx-bootstrap.log -p {run_dir}/ -c nginx.conf exit={test.returncode}\n")
        (run_dir / "nginx-test.log").write_text(test.stdout + test.stderr)
        check("nginx -t", test.returncode == 0, test.stderr.strip())
        nginx_proc = start_child(["nginx", "-e", str(run_dir / "nginx-bootstrap.log"), "-p", str(run_dir) + "/", "-c", "nginx.conf", "-g", "daemon off; master_process off;"], "nginx-process.log")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if nginx_proc.poll() is not None:
                raise RuntimeError("test nginx exited; see nginx-process.log")
            try:
                with socket.create_connection(("127.0.0.1", https_port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        base = f"https://127.0.0.1:{https_port}"
        code, body, _ = http_request(base + "/protected")
        check("allow 204 reaches proxy upstream", code == 200 and json.loads(body)["uri"] == "/protected", f"status={code} body={body}")
        code, body, _ = http_request(base + "/protected?mode=challenge")
        check("auth 403 challenge becomes local 429", code == 429 and "local challenge" in body, f"status={code} body={body}")
        for status in (401, 403, 429, 500):
            code, body, _ = http_request(base + f"/protected/status/{status}")
            check(f"proxy upstream {status} preserved", code == status and body == f"upstream-{status}", f"status={code} body={body}")
        if php_fpm:
            for status in (401, 403, 429, 500):
                code, body, _ = http_request(base + f"/fcgi/{status}")
                check(f"FastCGI upstream {status} preserved", code == status and json.loads(body)["uri"] == f"/fcgi/{status}", f"status={code} body={body}")
            fcgi_payload = "fcgi-body-intact"
            code, body, _ = http_request(base + "/fcgi/post", "POST", fcgi_payload.encode())
            fcgi_post = json.loads(body)
            check("FastCGI POST preserves method/body", code == 200 and fcgi_post["method"] == "POST" and fcgi_post["body"] == fcgi_payload, f"status={code} body={body}")
        code, body, _ = http_request(base + "/protected", "HEAD")
        check("HEAD allowed without challenge HTML", code == 200 and body == "", f"status={code}")
        payload = "payload-intact"
        code, body, _ = http_request(base + "/protected?mode=challenge", "POST", payload.encode(), {"Authorization": "Bearer fixture-secret"})
        post = json.loads(body)
        post_observed = json.loads(next(line for line in reversed((run_dir / "checker.log").read_text().splitlines()) if line.startswith("{")))
        check("POST bypass keeps method/body", code == 200 and post["method"] == "POST" and post["body"] == payload and post_observed.get("x-antiddos-method") == "POST" and post_observed.get("x-antiddos-uri") == "/protected?mode=challenge" and post_observed.get("response_decision") == "bypass_method" and "authorization" not in post_observed and "content-length" not in post_observed, f"status={code} body={body}; check={post_observed}")
        code, body, _ = http_request(base + "/rewrite")
        check("internal rewrite reaches protected location", code == 200 and json.loads(body)["uri"] == "/protected?rewritten=1", f"status={code} body={body}")
        rewrite_observed = json.loads(next(line for line in reversed((run_dir / "checker.log").read_text().splitlines()) if line.startswith("{")))
        check("auth metadata retains original URI after rewrite", rewrite_observed.get("x-antiddos-uri") == "/rewrite" and rewrite_observed.get("x-antiddos-method") == "GET", json.dumps(rewrite_observed, sort_keys=True))
        forged = {"X-AntiDDoS-IP": "203.0.113.77", "X-AntiDDoS-Host": "evil.invalid", "X-AntiDDoS-URI": "/forged", "X-AntiDDoS-Method": "DELETE", "X-AntiDDoS-Scheme": "http"}
        code, _, _ = http_request(base + "/protected", headers=forged)
        checker_lines = (run_dir / "checker.log").read_text().splitlines()
        observed = json.loads(next(line for line in reversed(checker_lines) if line.startswith("{")))
        check("client metadata headers overwritten", code == 200 and observed.get("x-antiddos-ip") == "127.0.0.1" and observed.get("x-antiddos-host") == "127.0.0.1" and observed.get("x-antiddos-uri") == "/protected" and observed.get("x-antiddos-method") == "GET" and observed.get("x-antiddos-scheme") == "https", json.dumps({k.lower(): observed.get(k.lower()) for k in forged}, sort_keys=True))
        code, _, _ = http_request(base + "/protected", headers={"Cookie": "__Host-antiddos_pass=fixture-only"})
        cookie_observed = json.loads(next(line for line in reversed((run_dir / "checker.log").read_text().splitlines()) if line.startswith("{")))
        check("Cookie forwarded without storing its value", code == 200 and cookie_observed.get("cookie_seen") is True and "cookie" not in cookie_observed and "fixture-only" not in (run_dir / "checker.log").read_text(), json.dumps(cookie_observed, sort_keys=True))
        code, _, _ = http_request(base + "/_check")
        check("internal check route denied externally", code == 404, f"status={code}")
        for route in ("/__antiddos/", "/__antiddos/challenge", "/__antiddos/verify", "/__antiddos/assets/widget.js"):
            code, body, _ = http_request(base + route)
            check(f"public route {route}", code == 200, f"status={code} body={body}")
        code, _, _ = http_request(base + "/__antiddos/private")
        check("unlisted public namespace route denied", code == 404, f"status={code}")
        code, body, _ = http_request(base + "/native-deny?mode=challenge")
        check("native Nginx deny stays a non-challenge 403", code == 403 and "local challenge" not in body, f"status={code} body={body}")
        for name, mode in (("checker 500 fails open", "error"), ("checker slow read fails open", "slow")):
            started = time.monotonic()
            code, body, _ = http_request(base + "/protected?mode=" + mode)
            elapsed = time.monotonic() - started
            check(name, code == 200 and json.loads(body)["uri"].startswith("/protected") and elapsed < .8, f"status={code} elapsed={elapsed:.3f}s")
        checker = next(proc for proc, _ in children if "checker" in str(proc.args))
        stop_child(checker)
        started = time.monotonic()
        code, body, _ = http_request(base + "/protected")
        elapsed = time.monotonic() - started
        check("checker connection refused fails open", code == 200 and json.loads(body)["uri"] == "/protected" and elapsed < .8, f"status={code} elapsed={elapsed:.3f}s")
        if php_fpm:
            code, body, _ = http_request(base + "/fcgi/ok")
            check("FastCGI allow and URI/method", code == 200 and json.loads(body)["uri"] == "/fcgi/ok" and json.loads(body)["method"] == "GET", f"status={code} body={body}")
            code, body, _ = http_request(base + "/fcgi/403")
            check("FastCGI application 403 preserved", code == 403 and json.loads(body)["uri"] == "/fcgi/403", f"status={code} body={body}")
            code, body, _ = http_request(base + "/fcgi/500")
            check("FastCGI application 500 preserved", code == 500 and json.loads(body)["uri"] == "/fcgi/500", f"status={code} body={body}")
        logs = (run_dir / "access.log").read_text().splitlines()
        markers = {line.rsplit(" ", 1)[-1] for line in logs}
        check("origin markers include application/challenge/service", {"application", "challenge", "service"}.issubset(markers), f"markers={sorted(markers)}")
        challenge_429 = [line for line in logs if " 429 challenge" in line]
        app_429 = [line for line in logs if "/status/429 429 application" in line]
        check("application 429 remains application origin", bool(app_429) and bool(challenge_429), f"challenge={challenge_429}; application={app_429}")
        check("auth subrequests are not logged as source requests", all("/check" not in line for line in logs), f"log lines={len(logs)}")
    except Exception as exc:
        record("runner exception", False, repr(exc))
    finally:
        for proc, _ in list(reversed(children)):
            stop_child(proc)
        command_log.close()
        (run_dir / "processes.json").write_text(json.dumps(process_manifest, indent=2) + "\n")
        summary = {"passed": sum(1 for item in checks if item["ok"]), "failed": sum(1 for item in checks if not item["ok"]), "blocked": len(blockers), "blockers": blockers, "skipped": skipped, "checks": checks}
        (run_dir / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
        (run_dir / "report.md").write_text("# Этап A — проверка контракта Nginx\n\n" +
          f"Результат: **{'FAIL' if summary['failed'] else 'BLOCKED' if summary['blocked'] else 'PASS'}**, проверок: {summary['passed']} успешно, {summary['failed']} ошибок, {summary['blocked']} блокеров.\n\n" +
          "| Проверка | Результат | Детали |\n|---|---|---|\n" +
          "".join("| {} | {} | {} |\n".format(c["name"], "PASS" if c["ok"] else "FAIL", " ".join(c["detail"].split()).replace("|", "\\|")[:500]) for c in checks) +
          "\nИспользованы системный Nginx и изолированный PHP-FPM на loopback, если доступен. HTTPS-сертификат временный самоподписанный. Runner завершил все созданные процессы; PID и статусы — в `processes.json`. Тест подтверждает шаблон proxy_pass и прямой FastCGI location; production-конфиг и PHP try_files конкретного сайта отдельно не проверялись.\n" +
          ("\n## Не выполнено из-за зависимости\n\n" + "\n".join(f"- {item}" for item in blockers + skipped) + "\n" if blockers else ""))
        print(f"Artifacts: {run_dir}", flush=True)
    if checks and any(not item["ok"] for item in checks):
        return 1
    return 2 if blockers else 0


if __name__ == "__main__" and len(sys.argv) == 4 and sys.argv[1] == "--serve":
    serve(sys.argv[2], int(sys.argv[3]))
elif __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        for proc, _ in list(reversed(children)):
            stop_child(proc)
        raise
