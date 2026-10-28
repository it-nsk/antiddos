# План изучения атак по выгрузке `bgtweb_logs`

Источник: `/home/semyon/Downloads/bgtweb_logs/bgtweb_logs`, выгружен с `bgt-web`.
На первом прогоне все правила имеют действие `dry_run`: только detections, без CAPTCHA,
nftables и изменения Nginx.

## Обнаруженные источники

| Источник | Формат | Что покрывает |
|---|---|---|
| `nginx_bgt_access` | `nginx_combined` | URL, статус, IP, User-Agent, частотные атаки |
| `nginx_all_access` | `nginx_combined` | общий входящий трафик и сканирование разных host/path |
| `nginx_error` | `nginx_error` | rate-limit, auth/upstream/error-события |
| `ssh_auth` | `syslog_sshd` | Failed password и Invalid user |
| `netfilter` | `netfilter_log` | попытки подключения к портам по `PROTO`/`DPT` |
| `fail2ban` | пока справочный источник | уже принятые решения Fail2ban; подключать после отдельного parser-а |

## Правила первого detection-only прогона

Пороги стартовые и будут откалиброваны по реальному распределению IP/времени.

### Web access

- `web-scan-sensitive`: `^/(?:\.env|\.git(?:/|$)|\.aws(?:/|$)|etc/passwd|proc/self|vendor/phpunit|wp-login\.php|xmlrpc\.php)(?:/|$)` — поиск секретов, служебных файлов и типовых scanner probes; `10s/3` по IP.
- `web-admin-probe`: `^/(?:admin|administrator|login|wp-admin|phpmyadmin|manager)(?:/|$)` — перебор административных входов; `60s/10` по IP.
- `web-sqli-probe`: `(?i)(?:union(?:%20|\+|\s)+select|select(?:%20|\+|\s)+.+(?:from|into)|or(?:%20|\+|\s)+1=1|sleep\(|benchmark\()` — SQLi-подобные URL/query; `60s/3` по IP.
- `web-path-scan`: `^/(?:cgi-bin|actuator|server-status|\.well-known/security\.txt)` — массовое перечисление служебных endpoint-ов; `30s/8` по IP.
- `web-error-burst`: `^/(?:.*)$` на отдельном access source с условием статусов `4xx/5xx` пока не выражается текущим `path_regex`; временно используем общий rate по подозрительным путям, затем добавим status predicate.
- `web-user-agent-scan`: те же URL-правила с `group_by=ip`; после накопления статистики добавим отдельную группировку по User-Agent.

### Nginx error

- `nginx-rate-limit-burst`: `^/nginx/error$` — всплески `limiting requests`; `30s/10` по IP.
- `nginx-basic-auth-fail`: `^/auth/basic/failure$` — ошибки Basic Auth; `60s/5` по IP.

### SSH

- `ssh-password-bruteforce`: `^/ssh/failed$` — Failed password; `60s/5` по IP.
- `ssh-invalid-user-scan`: `^/ssh/invalid-user$` — перебор несуществующих пользователей; `60s/3` по IP.

### Сканирование портов

- `port-scan-burst`: `^/port/(?:tcp|udp)/[0-9]{1,5}$` — много разных DPT; `30s/8` по IP.
- На следующем шаге добавим группировку по IP+порт, чтобы отличать один сервисный burst от горизонтального скана.

## Этапы проверки

1. Проверить parse success на каждой строке всех пяти форматов.
2. Прогнать профиль на коротком выбранном срезе реальных логов, `dry_run`.
3. Сверить detections с ручными выборками `rg` и исключить поисковых роботов/валидные crawler-ы.
4. Подобрать окна и пороги отдельно для web, SSH и netfilter.
5. Только после этого переносить отдельные правила в soft-block или nftables.

## Запланированная доработка UI detections

Сейчас таблица срабатываний показывает правило, IP, User-Agent, счётчик и окно,
но не показывает URL, который совпал с правилом. Это затрудняет разбор сигнатурных
срабатываний вроде `web-scan-sensitive`.

Нужно добавить в контракт detection поле `path` (и при необходимости `method` и
`status`) и вывести его в таблице:

```text
Время | Источник | Правило | Метод | Path | Status | IP | Count/Threshold | User-Agent
```

Для запроса `/wp-login.php` оператор должен видеть не только `web-scan-sensitive`,
но и конкретную причину совпадения. Для событий `nginx_error`, SSH и netfilter
показывать нормализованный path (`/nginx/error`, `/ssh/failed`, `/port/tcp/22`),
а исходную строку оставлять доступной в tooltip или в деталях записи.

Текущая выгрузка действительно содержит примеры `.env`, `.aws/credentials`, phpMyAdmin/MySQL-проб,
SSH Failed password/Invalid user и Nginx rate-limit, поэтому этот профиль можно проверять сразу.
