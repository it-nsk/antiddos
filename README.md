# antiddos

Linux service that analyzes Nginx access logs, records traffic and detections in SQLite, and can temporarily block client IPs through nftables.

## Quick start: чистый Ubuntu-сервер, SSH и dry-run

Первый запуск состоит из трёх действий. Сервер и Nginx перезапускать не нужно;
после сохранения настроек перезапускается только `antiddos.service`.

1. По SSH установить daemon и UI одной командой:

```shell
curl -fsSL https://raw.githubusercontent.com/it-nsk/antiddos/dev/scripts/install.sh -o /tmp/antiddos-install.sh && sudo bash /tmp/antiddos-install.sh --web
```

Установщик создаст системные сервисы, попросит пароль первого администратора и
запустит безопасный режим `dry_run`.

2. На рабочем компьютере открыть туннель и перейти на
`http://127.0.0.1:8080`:

```shell
ssh -N -L 8080:127.0.0.1:8080 <ssh-user>@<server-address>
```

В **Правила и фильтры → Источники логов → Добавить источник** указать имя,
абсолютный путь и формат. Доступны Nginx access, Nginx error, OpenSSH auth.log и
UFW/kernel netfilter. При сохранении daemon сам проверяет существование файла и
право чтения. Для нового источника UI одновременно создаёт безопасное базовое
правило с действием `dry_run`:

| Формат | Автоматическое базовое правило |
| --- | --- |
| Nginx access | 10 запросов к `/` от IP за 5 секунд |
| Nginx error | 5 ошибок Basic Auth от IP за минуту |
| OpenSSH auth.log | 5 неуспешных входов от IP за минуту |
| UFW/kernel netfilter | 8 уникальных портов от IP за 30 секунд |

Дополнительные правила (`.env`, admin scan, SQLi, invalid SSH users, уникальные
URL) добавляются там же из готовых пресетов.

3. Сохранить настройки и применить их одной командой:

```shell
sudo systemctl restart antiddos
```

После перезапуска **Обзор трафика** показывает данные каждого источника, а
**Срабатывания и блокировки** -- совпавшие правила. В `dry_run` CAPTCHA и
firewall не применяются.

The log-to-rule mapping is:

| Source | Preset | Initial signal |
| --- | --- | --- |
| Nginx access | `web-home-burst` | 10 `GET /` from one IP in 5 seconds |
| Nginx access | `web-sensitive` | `.env`, `.git`, `.aws`, `/etc/passwd`, `/proc/self` once |
| Nginx access | `web-admin-probe` | 10 admin/login paths from one IP in 60 seconds |
| Nginx access | `web-sqli-query` | basic SQLi expression in query string once |
| Nginx error | `nginx-basic-auth` | 5 Basic Auth failures from one IP in 60 seconds |
| `auth.log` | `ssh-password` / `ssh-invalid-user` | failed passwords / invalid SSH users from one IP |
| UFW or kernel log | `port-scan` | 8 distinct TCP/UDP destination ports from one IP in 30 seconds |

These are observations mapped to MITRE ATT&CK techniques; the thresholds are
safe starting hypotheses, not universal constants. Run them in `dry_run` for
24--72 hours, investigate detections, whitelist known monitors/proxies, then
adjust windows and thresholds. CAPTCHA and nftables are a separate explicit
rollout and require no Nginx change during this monitoring phase.

<a id="nginx-custom-log-format"></a>
### Как найти `log_format` для Nginx custom access

Сначала найдите `access_log` нужного сайта и имя формата после пути:

```shell
sudo nginx -T 2>/dev/null | grep -nE '^[[:space:]]*(server_name|access_log|log_format)[[:space:]]'
```

Например, запись `access_log /var/log/nginx/site.log main;` использует формат
`main`. В том же выводе найдите начинающуюся с `log_format main` директиву и
целиком вставьте её в поле **Формат Nginx**, включая имя и завершающую `;`:

```nginx
log_format main '$remote_addr [$time_local] "$request" $status $body_bytes_sent';
```

Это именно директива из конфигурации Nginx, а не строка из файла журнала. Формат
должен содержать `$remote_addr`, время, `$status` и `$request` (либо отдельно
метод и URI). Если у `access_log` после пути нет имени, выберите в UI
**Nginx combined access** — поле формата заполнять не нужно.

<a id="nftables-blocking-setup"></a>
### Как включить реальные блокировки через nftables

Переходите к блокировкам только после 24–72 часов проверки правил в `dry_run`:

1. Проверьте, что в access log записан настоящий IP посетителя. Если перед
   Nginx стоит CDN или reverse proxy, сначала настройте real IP, иначе можно
   заблокировать адрес прокси сразу для всего сервера.

2. Добавьте свои адреса, мониторинг и доверенные сети в глобальный или
   относящийся к правилу whitelist в UI.

3. Проверьте наличие nftables и текущие правила хоста:

   ```shell
   command -v nft
   sudo nft list ruleset
   ```

4. В `/etc/antiddos/config.json` ограничьте блокировку нужными TCP-портами:

   ```json
   "block_tcp_ports": [80, 443]
   ```

   Не добавляйте `22`, если не хотите блокировать SSH. Пустой список блокирует
   адрес на всех протоколах и портах. AntiDDoS создаёт отдельную таблицу
   `inet antiddos` и не очищает чужие таблицы nftables.

5. В UI выберите **nftables** для всех правил или **Гибридный режим** и действие
   **nftables** только для проверенных правил. Сохраните изменения и примените их:

   ```shell
   sudo systemctl restart antiddos
   sudo systemctl status antiddos --no-pager
   sudo nft list table inet antiddos
   ```

   Установленная systemd-служба уже выдаёт launcher право `CAP_NET_ADMIN`;
   вручную запускать daemon от root или назначать бинарнику `setcap` не нужно.

Для отката выберите в UI **Только наблюдение**, сохраните конфигурацию и снова
перезапустите `antiddos`. Один адрес можно снять командой
`sudo /usr/local/bin/antiddos unblock IP`.

<a id="soft-block-captcha-setup"></a>
### Как подключить Soft-block CAPTCHA

CAPTCHA требует checker и небольших include-файлов Nginx. Делайте это после
проверки правил в `dry_run`:

1. Установите checker той же командой установки, добавив `--soft-block`:

   ```shell
   sudo bash /tmp/antiddos-install.sh --web --soft-block
   ```

2. В `/etc/antiddos/config.json` добавьте `soft_block.sites`: задайте короткий
   ID сайта, его домены и источник отдельного access log. Пример конфигурации
   находится ниже в разделе **CAPTCHA: мягкий уровень для одного сайта**.

3. Создайте Nginx snippets для ID сайта (здесь он называется `site`):

   ```shell
   sudo /usr/local/bin/antiddos nginx-snippet \
     --config /etc/antiddos/config.json \
     --site site \
     --output /etc/nginx/snippets/antiddos-site \
     --write
   sudo less /etc/nginx/snippets/antiddos-site/README.txt
   ```

   Сгенерированный `README.txt` перечисляет точные `include` для `http`,
   `server` и существующего `proxy` либо `fastcgi` location. Не подключайте
   одновременно proxy и FastCGI snippet в один location.

4. Узнайте worker user Nginx и добавьте его в группу checker. На Ubuntu обычно
   это `www-data`:

   ```shell
   sudo nginx -T 2>/dev/null | grep -m1 '^[[:space:]]*user[[:space:]]'
   sudo usermod -a -G antiddos-check www-data
   ```

5. Проверьте конфигурацию, перезапустите Nginx для применения новой группы и
   запустите службы:

   ```shell
   sudo nginx -t
   sudo systemctl restart nginx antiddos antiddos-challenge
   sudo /usr/local/bin/antiddos soft-block doctor \
     --config /etc/antiddos/config.json --site site
   ```

После успешного `doctor` можно выбрать режим **Soft-block с CAPTCHA** или
назначить `soft_block` отдельному правилу в hybrid-режиме. Без этого подключения
оставьте режим `dry_run`.

### Как строка лога становится detection

AntiDDoS не обрабатывает только `GET /`. Каждый parser приводит строку своего
журнала к одному событию: `timestamp`, `source`, `IP`, нормализованный `path`,
а при наличии -- `method`, `query`, HTTP status и destination port. Правило
выбирает эти поля, а не исходный текст лога.

| Исходная строка | Нормализованное событие | Что означает правило |
| --- | --- | --- |
| `"GET /.env HTTP/1.1" 404 ...` в Nginx access | IP, `GET`, path `/.env` | `web-sensitive`: одно совпадение. Это типичный web wordlist/vulnerability scan (MITRE T1595). |
| `"GET /?id=1+union+select..."` | IP, path `/`, query `id=...` | `web-sqli-query`: сигнатура в query, одно совпадение. Это попытка атаки на public-facing application (T1190). |
| `user "admin": password mismatch, client: 203.0.113.7` в Nginx error | IP `203.0.113.7`, path `/auth/basic/failure` | `nginx-basic-auth`: 5 отказов за минуту -- подбор Basic Auth. |
| `Failed password for root from 203.0.113.7 ...` в `auth.log` | IP `203.0.113.7`, path `/ssh/failed` | `ssh-password`: 5 отказов за минуту -- SSH brute force (T1110). |
| `Failed password for invalid user admin from 203.0.113.7 ...` | IP `203.0.113.7`, path `/ssh/invalid-user` | `ssh-invalid-user`: 3 события за минуту -- разведка имён SSH-аккаунтов. |
| `SRC=203.0.113.7 PROTO=TCP DPT=3306` в UFW/kernel log | IP `203.0.113.7`, path `/port/tcp/3306`, port `3306` | `port-scan`: 8 **разных** портов за 30 секунд -- network service discovery (T1046). |

Базовый установочный `config.example.json` оставлен минимальным и совместимым с
`--log-file`: один access log, правило главной страницы в `dry_run`. Полный
`config.security.example.json` содержит также Nginx error, SSH и port-scan
пресеты. В нём нет включённой реакции: все правила имеют `action: dry_run`;
шумные SSH, UFW, unique URL и homepage правила выключены до калибровки. Их
можно включить галкой в UI или полем `enabled: true` в JSON.

### Примеры режимов конфигурации

<details>
<summary><strong>1. Обычный dry-run: безопасный первый запуск</strong></summary>

Это единственный режим, который включается по умолчанию. Detection записывается
в SQLite, журнал и UI; клиент, Nginx и firewall не меняются.

```json
{
  "block_mode": "dry_run",
  "log_sources": {
    "web_access": {"path": "/var/log/nginx/site_access.log", "format": "nginx_combined"},
    "ssh_auth": {"path": "/var/log/auth.log", "format": "syslog_sshd"},
    "netfilter": {"path": "/var/log/ufw.log", "format": "netfilter_log"}
  },
  "engine": {"rules": [
    {"id":"home-burst","enabled":true,"type":"rate","action":"dry_run","log_source":"web_access","path_regex":"^/$","window":"5s","threshold":10,"group_by":"ip"},
    {"id":"ssh-password","enabled":false,"type":"rate","action":"dry_run","log_source":"ssh_auth","path_regex":"^/ssh/failed$","window":"60s","threshold":5,"group_by":"ip"},
    {"id":"port-scan","enabled":false,"type":"cardinality","unique_by":"destination_port","action":"dry_run","log_source":"netfilter","path_regex":"^/port/(?:tcp|udp)/[0-9]{1,5}$","window":"30s","threshold":8,"group_by":"ip"}
  ]}
}
```

Сначала включаются только те источники, чьи файлы реально есть и читаются
пользователем `antiddos`. После сохранения нужен только
`sudo systemctl restart antiddos`.
</details>

<details>
<summary><strong>2. Точечный nftables-ban для подтверждённого правила</strong></summary>

Не включать до dry-run калибровки. В `hybrid` можно сделать ровно одно правило
жёстким, а остальные оставить наблюдением. Ban действует на IP всего сервера на
настроенных портах, а не только на один virtual host.

```json
{
  "block_mode": "hybrid",
  "block_duration": "5m",
  "block_tcp_ports": [80, 443],
  "engine": {"rules": [
    {"id":"web-sensitive-audit","enabled":true,"type":"signature","action":"dry_run","log_source":"web_access","path_regex":"(?i)(?:^|/)(?:\\.env|\\.git|etc/passwd)","window":"1s","threshold":1,"group_by":"ip"},
    {"id":"confirmed-hard-burst","enabled":false,"type":"rate","action":"nftables","log_source":"web_access","path_regex":"^/$","window":"1s","threshold":50,"group_by":"ip"}
  ]}
}
```

Перед включением `confirmed-hard-burst` надо проверить whitelist мониторингов,
выполнить `sudo nft list ruleset`, а после -- `sudo systemctl restart antiddos`.
</details>

<details>
<summary><strong>3. CAPTCHA: мягкий уровень для одного сайта</strong></summary>

Это HTTP-only механизм. До смены JSON необходимо установить checker
`sudo bash /tmp/antiddos-install.sh --soft-block`, создать dedicated access log
сайта и подключить сгенерированные Nginx snippets. Для этого требуется ручная
проверка `nginx -t` и reload Nginx; на обычный dry-run это не влияет.

```json
{
  "block_mode": "hybrid",
  "soft_block": {
    "cookie_ttl": "30m",
    "sites": {
      "site": {"hosts": ["example.org"], "log_sources": ["site_access"]}
    }
  },
  "engine": {"rules": [
    {"id":"captcha-level","enabled":false,"type":"rate","action":"soft_block","log_source":"site_access","path_regex":"^/$","window":"10s","threshold":8,"group_by":"ip"}
  ]}
}
```

При пороге daemon создаёт решение для `site` и передаёт его checker через
приватный Unix socket. Nginx делает внутренний `auth_request` checker-у; тот
показывает ALTCHA и после успешного решения отдаёт подписанную cookie. Cookie
пропускает пользователя до `cookie_ttl`. Без рабочего checker/socket Nginx
работает fail-open, а не ломает сайт.
</details>

<details>
<summary><strong>4. Два уровня: CAPTCHA, затем nftables</strong></summary>

В одном `hybrid` конфиге два независимых правила смотрят на один access log:
медленная аномалия ведёт на CAPTCHA, резкий burst -- в firewall. При совпадении
обоих firewall имеет практический приоритет, пока не истечёт его TTL.

```json
{
  "block_mode": "hybrid",
  "engine": {"rules": [
    {"id":"soft-level","enabled":false,"type":"rate","action":"soft_block","log_source":"site_access","path_regex":"^/$","window":"10s","threshold":8,"group_by":"ip"},
    {"id":"hard-level","enabled":false,"type":"rate","action":"nftables","log_source":"site_access","path_regex":"^/$","window":"1s","threshold":50,"group_by":"ip"}
  ]}
}
```

Для этого примера нужны одновременно подготовленные `soft_block.sites`, checker,
Nginx snippets и `block_tcp_ports`. Начинать следует с обоих правил в
`action: dry_run` или `enabled: false`, затем включать по одному.
</details>

To change settings, edit `/etc/antiddos/config.json` and restart the service:

```shell
sudoedit /etc/antiddos/config.json
sudo systemctl restart antiddos
```

### Optional web interface

The Quick Start command above installs the GUI and creates its first administrator. To enable it after installing the daemon without `--web`, rerun the installer with `--web`. The GUI listens on `127.0.0.1:8080` by default; open it on the server or create an SSH tunnel from your computer:

```shell
sudo bash /tmp/antiddos-install.sh --web
# On your computer, in a separate terminal:
ssh -N -L 8080:127.0.0.1:8080 <ssh-user>@<server-address>
# Then open http://127.0.0.1:8080 in your computer's browser
```

Replace `<ssh-user>` and `<server-address>` with your server's SSH login and hostname or IP. Keep the SSH command running while using the GUI. The installer prints these steps after a successful web install.

On a fresh GUI install, the installer creates login `admin` and securely prompts for its password. There is no public registration or default password. User records and sessions are stored in `/var/lib/antiddos-web/users.sqlite`. The GUI shows traffic graphs, detections, active blocks, all configured log sources, and lets an `admin` edit each rule's `path_regex` and whitelist, the global whitelist, and the `dry_run`/`nftables` mode. Enabling real blocking requires explicit confirmation. A `viewer` can only view data. Edits are validated and saved to `/etc/antiddos/config.json`; restart `antiddos` to apply them. The GUI does not restart systemd services. The overview keeps the combined charts and, for multiple logs, provides collapsible per-source charts; per-source history starts after upgrading because older samples were stored only as a combined total. Detection rows show their source log. Manage additional accounts locally:

```shell
sudo -u antiddos-web /usr/local/bin/antiddos user add --role viewer operator
sudo -u antiddos-web /usr/local/bin/antiddos user list
sudo -u antiddos-web /usr/local/bin/antiddos user password operator
sudo -u antiddos-web /usr/local/bin/antiddos user delete operator
```

To test the GUI on a development checkout, build its embedded assets and run the browser tests:

```shell
cd /www/antiddos
npm --prefix web ci
npm --prefix web run test:e2e
go test ./cmd/... ./internal/...
go test -race ./cmd/... ./internal/...
go vet ./cmd/... ./internal/...
```

To open the GUI locally with isolated synthetic logs, statistics, and users (no `sudo` and no system service):

```shell
npm --prefix web run build
cd web
node tests/serve.mjs
```

Open `http://127.0.0.1:18082` and sign in as `admin` with the test-only password `test-only-long-password`. The fixture has two log sources and separate rule whitelists. Stop it with `Ctrl+C`. To view the browser-test report, from `web/` run `npx playwright show-report ../runtime/web-e2e/report`.

To install the current checkout on a Linux test server as real systemd services, first build the UI and binary, then run the installer locally. It preserves `/etc/antiddos/config.json`, installs both units, creates the web account, and prompts for the first admin password:

```shell
npm --prefix web run build && go build -o antiddos ./cmd/antiddos
sudo bash scripts/install.sh --local --web
```

The installer prints the GUI URL and SSH tunnel command. After changing rules or block mode in the GUI, restart only the daemon with `sudo systemctl restart antiddos`; the GUI service stays up.

For a manual server test, sign in as `admin`. Check **Overview** for traffic graphs and configured log sources; **Detections** for recent detections and active blocks; **Rules and filters** for each rule's path expression and whitelist. Change a rule expression to `^/login$`, add a documentation IP such as `192.0.2.10`, save, and confirm the page says a daemon restart is required. Restart with `sudo systemctl restart antiddos`, reload the page, and confirm the saved values remain. Add a `viewer` with the CLI and sign in as that user: the data remains visible, while rule editing and the Users page are unavailable. Changing a user's password with the CLI revokes that user's existing sessions.

For remote access, keep the GUI bound to loopback and use `ssh -L 8080:127.0.0.1:8080 user@server`. A public deployment should use a dedicated HTTPS virtual host in the existing reverse proxy; set its exact URL as `ANTIDDOS_WEB_ORIGIN` in `/etc/default/antiddos-web`, then restart `antiddos-web`. The web service has no firewall capability and talks to the daemon through a restricted Unix socket that exposes statistics and validated rule/whitelist edits.

The default config watches one access log. For multiple logs, use `log_sources` and bind each rule to a source with `log_source` (example below).

For a safe multi-source security starting point, use
[`deploy/config.security.example.json`](deploy/config.security.example.json) and the
Russian [installation and first-run guide](docs/first-run-security-presets.md).
The installer also places this profile at
`/etc/antiddos/config.security.example.json` without replacing the active config.

<details>
<summary>Find the right Nginx access log and its format</summary>

```shell
sudo nginx -T 2>/dev/null | grep -nE '^[[:space:]]*(server_name|log_format|access_log|error_log)'
```

Match the `access_log` directive to the site's `server_name`. Supported inputs are
Nginx access logs (`nginx_combined`, `nginx_custom`), Nginx errors
(`nginx_error`), OpenSSH authentication logs (`syslog_sshd`), and kernel/UFW
netfilter records (`netfilter_log`). If an Nginx access directive does not name a
format, Nginx uses `combined`. For a custom format, copy its complete `log_format`
directive into the matching source's `log_format` setting. AntiDDoS does not read
or modify `nginx.conf`.

</details>

## Configuration

The installed file is `/etc/antiddos/config.json`; the template is [`deploy/config.example.json`](deploy/config.example.json). A one-log configuration uses `log_file`. For several logs, use `log_sources` instead; do not combine the two forms.

Example with two access logs, two parsers, per-rule URL patterns, and rule-level whitelists:

```json
{
  "log_sources": {
    "main_site": {
      "path": "/var/log/nginx/site_access.log",
      "format": "nginx_custom",
      "log_format": "log_format antiddos '$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent \"$http_referer\" \"$http_user_agent\"';"
    },
    "admin_site": "/var/log/nginx/admin_access.log"
  },
  "database_path": "/var/lib/antiddos/antiddos.sqlite",
  "start_position": "end",
  "block_mode": "dry_run",
  "block_duration": "1m",
  "block_tcp_ports": [80, 443],
  "engine": {
    "ignore_ips": [],
    "rules": [
      {
        "id": "web-homepage",
        "log_source": "main_site",
        "path_regex": "^/$",
        "window": "5s",
        "threshold": 5,
        "group_by": "ip",
        "ignore_ips": ["192.0.2.10"]
      },
      {
        "id": "inside-login",
        "log_source": "admin_site",
        "path_regex": "^/login$",
        "window": "10s",
        "threshold": 5,
        "group_by": "ip",
        "ignore_ips": ["198.51.100.7"]
      }
    ]
  }
}
```

`192.0.2.10` and `198.51.100.7` are documentation-only addresses. Replace them with trusted client IPs visible in the Nginx log, or remove them. The global `engine.ignore_ips` applies to all rules; a rule's `ignore_ips` applies only to that rule. Whitelisted requests remain in traffic statistics but do not enter that rule's detection window.

The paths and URL patterns above are examples. Confirm the log paths and `log_format` in your Nginx config, and set each `path_regex` to a path that the corresponding site actually serves. The parser checks the URL path without query parameters. Multiple rules can use one source; each input line is read and parsed once, then evaluated against that source's rules.

<details>
<summary>Config fields and behavior</summary>

| Field | Meaning |
| --- | --- |
| `log_file` | One Nginx access log; uses `nginx_combined`. |
| `log_sources` | Named log files. A value can be a path string or an object with `path`, `format`, and, for custom logs, `log_format`. |
| `log_source` | Source name a rule evaluates. Required when `log_sources` has multiple entries. |
| `path_regex` | Regular expression matched against the URL path, without query parameters. |
| `window`, `threshold` | Detection occurs on every matching request when the count in the sliding window reaches the threshold. |
| `group_by` | One field: `ip`, `user_agent`, `method`, `path`, or `status`. Only `ip` rules can block. |
| `ignore_ips` | IPv4/IPv6 addresses or CIDR networks. Supports a global list and per-rule lists. |
| `start_position` | `end` processes new lines; `beginning` reads the existing log from the start. |

`nginx_custom` requires `$remote_addr`, a timestamp (`$time_local`, `$time_iso8601`, or `$msec`), `$status`, and either `$request` or `$request_method` with `$uri`/`$request_uri`. The directive is compiled once at startup. The service account must be able to read every configured log. `monitor` shows all source names and paths.

After switching to `log_sources`, remove any active `ANTIDDOS_LOG_FILE` override from `/etc/default/antiddos`. Restart the daemon after config changes.

</details>

## Observe or block

`dry_run` is the default: detections are recorded and logged, but nftables is unchanged. To enable real blocking, install `nftables`, set `block_mode` to `nftables`, and restart `antiddos`. `block_duration` accepts whole minutes from `1m` to `60m`. Repeated detections do not extend an active block.

`hybrid` gives every rule an independent `action`: `dry_run`, `soft_block`, or `nftables`. A site can therefore use two enforcement levels, another log source can be observation-only, and a third can use only firewall blocking in the same daemon. Every hybrid rule must set `action`; hybrid does not require all action types to be present. `soft_block` and `nftables` require `group_by: "ip"`, while `dry_run` remains analytical and may use the other supported groupings. If soft and firewall rules both match, the firewall block takes practical precedence until it expires; their leases remain independent.

Outside `hybrid`, the global mode overrides the stored rule actions without deleting them: `dry_run` observes every rule, `soft_block` challenges every IP-grouped rule, and `nftables` firewall-blocks every IP-grouped rule. Returning to `hybrid` restores the per-rule choices.

`block_tcp_ports` limits blocking to TCP destination ports, for example `[80, 443]`. If omitted or empty, the address is blocked on all protocols and ports. For Docker traffic, the `forward` rule sees the container-side port after destination NAT. Blocking is server-wide, not limited to one Nginx site. Behind a proxy, make sure Nginx records the real client IP before enabling enforcement.

The systemd unit grants `CAP_NET_ADMIN` (Linux permission to manage host networking) to the launcher. It is retained only when the effective rule actions include `nftables`; otherwise the launcher first removes any persisted old firewall leases and then drops the capability before starting the analyzer. AntiDDoS creates its own `inet antiddos` table and does not flush other nftables tables. An nftables action is selected by one site's log but blocks the client IP on the configured server ports, not only on that virtual host.

<details>
<summary>Monitor, unblock, and service commands</summary>

```shell
# Live monitor; defaults to 20 rows per section
sudo -u antiddos /usr/local/bin/antiddos monitor

# Show up to 100 rows per section; refresh remains every two seconds
sudo -u antiddos /usr/local/bin/antiddos monitor --limit 100

# One snapshot
sudo -u antiddos /usr/local/bin/antiddos monitor --once --limit 5

# Remove one active firewall block
sudo -u antiddos /usr/local/bin/antiddos unblock 203.0.113.10

# Control the background service
sudo systemctl stop antiddos
sudo systemctl start antiddos
sudo systemctl restart antiddos
```

`unblock` accepts one IPv4 or IPv6 address. The CLI asks the running daemon over `/run/antiddos/control.sock` to change nftables; the CLI itself has no firewall capability.

</details>

## Data and runtime

The daemon runs as the `antiddos` system user. Its main paths are:

| Item | Path |
| --- | --- |
| Config | `/etc/antiddos/config.json` |
| Binary | `/usr/local/bin/antiddos` |
| SQLite database | `/var/lib/antiddos/antiddos.sqlite` |
| systemd unit | `antiddos.service` |
| Web users and sessions | `/var/lib/antiddos-web/users.sqlite` |
| Optional web unit | `antiddos-web.service` |

SQLite contains `traffic_samples`, `detections`, and `active_blocks`. Traffic is aggregated into 15-second buckets and flushed every 15 seconds. Detection rows are written when thresholds are reached. Active block records contain the IP and expiry; unexpired blocks are restored after daemon restart with only their remaining duration. Expired block history is removed from `active_blocks`.

## Development

### Soft-block CAPTCHA demo

Для демонстрации страницы ALTCHA локально откройте видимый Chrome:

```shell
bash tests/integration/softblock/demo.sh local
```

Страница работает только на loopback, использует временный самоподписанный сертификат и не делает внешних HTTP(S)-запросов. Дождитесь `Verified`, нажмите `Continue`, а после показа результата завершите демонстрацию через `Ctrl+C`. Для smoke-запуска без окна браузера используйте `SOFTBLOCK_DEMO_HEADLESS=1`.

Для демонстрации полного сценария на Debian VM (реальный Nginx → checker через Unix-сокет) используйте отдельный пустой каталог отчёта:

```shell
bash tests/integration/softblock/demo.sh vm --output runtime/softblock/demo-vm-$(date +%Y%m%d-%H%M%S)
```

Итоги будут в `progress.md` и `results.json` указанного каталога.

```shell
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/antiddos
```

## Release

The GitHub Actions release workflow builds Linux amd64 archives for tags beginning with `v`. To install a specific release, pass `--version` to the installer, for example:

```shell
sudo bash /tmp/antiddos-install.sh --version v0.3.0
```
