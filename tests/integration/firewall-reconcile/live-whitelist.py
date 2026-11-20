"""Exercise the daemon API used by the UI against the live managed firewall."""
import http.client
import json
import socket
import sqlite3
import subprocess
import sys
import time

ADDRESS = "198.18.0.253"


class UnixHTTP(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect("/run/antiddos/web.sock")


def api(method, path, body=None):
    conn = UnixHTTP("localhost", timeout=10)
    try:
        conn.request(method, path, body=None if body is None else json.dumps(body),
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read().decode()
        if response.status != 200:
            raise RuntimeError(f"{method} {path}: {response.status}: {data}")
        return json.loads(data)
    finally:
        conn.close()


def command(*args):
    return subprocess.check_output(args, text=True)


with open('/etc/antiddos/config.json') as f:
    config = json.load(f)
assert config['block_mode'] == 'nftables', 'this live test requires nftables mode'
rule = next(r['id'] for r in config['engine']['rules'] if r.get('enabled', True))
database = config['database_path']
original = api('GET', '/v1/config')['config']
original_rule = next(r for r in original['rules'] if r['id'] == rule)['ignore_ips']
pid = command('systemctl', 'show', 'antiddos', '-p', 'MainPID', '--value').strip()


def count():
    with sqlite3.connect(database) as db:
        return db.execute('select count(*) from active_blocks where ip=?', (ADDRESS,)).fetchone()[0]


def present():
    return ADDRESS in command('nft', 'list', 'set', 'inet', 'antiddos', 'blocked_ipv4')


assert count() == 0 and not present(), 'test address already in use; refusing'


def save(global_ips, rule_ips):
    current = api('GET', '/v1/config')['config']
    return api('PUT', '/v1/config/rules', {
        'revision': current['revision'], 'ignore_ips': global_ips,
        'rules': {rule: {'ignore_ips': rule_ips}},
    })


try:
    for scope in ('rule', 'global'):
        now = int(time.time() * 1000)
        with sqlite3.connect(database) as db:
            db.execute("insert into active_blocks(ip,rule_id,started_at_unix_ms,expires_at_unix_ms,origin) values(?,?,?,?, 'detected')",
                       (ADDRESS, rule, now, now + 120000))
        api('POST', '/v1/blocks/reconcile')
        assert present() and count() == 1, 'failed to prepare test ban'
        save(original['ignore_ips'] + ([ADDRESS] if scope == 'global' else []),
             original_rule + ([ADDRESS] if scope == 'rule' else []))
        assert not present() and count() == 0, f'{scope} whitelist did not remove ban'
        assert command('systemctl', 'show', 'antiddos', '-p', 'MainPID', '--value').strip() == pid, 'daemon restarted'
        print(f'PASS: {scope} whitelist API removes live firewall and SQLite ban without restart', flush=True)
        save(original['ignore_ips'], original_rule)
finally:
    try:
        command('/usr/local/bin/antiddos', 'unblock', ADDRESS)
    finally:
        save(original['ignore_ips'], original_rule)
