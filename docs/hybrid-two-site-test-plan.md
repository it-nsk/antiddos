# План приёмки hybrid AntiDDoS на двух сайтах

Цель: проверить не отдельные функции, а полный путь на реальном Nginx для двух изолированных сайтов:

`клиент → Nginx auth_request → checker по Unix-сокету → приложение → отдельный access log → daemon → soft lease или nftables → GUI/SQLite`.

`bgt.my` проверяет существующий FastCGI-контур. `bgt2.test` проверяет proxy-контур, отдельный `log_source`, отдельный site ID и отсутствие утечки решений/cookie между сайтами. Обычный DNS не меняется: добавляется только точечная запись `bgt2.test` в `/etc/hosts`; нагрузчик дополнительно фиксирует адрес через `--resolve`.

## 1. Подготовить второй сайт независимо от AntiDDoS

```bash
cd /www/antiddos
chmod +x scripts/two-site-lab.sh scripts/two-site-load.sh
sudo scripts/two-site-lab.sh prepare
sudo scripts/two-site-lab.sh status
```

Ожидается `bgt2 HTTP 200`. На этом шаге к `bgt2.test` ещё не подключён `auth_request`, поэтому AntiDDoS можно останавливать и удалять, а второй сайт останется рабочим.

## 1.1. Пересобрать текущую ветку

`install.sh --local` не компилирует исходники: он устанавливает готовый файл `/www/antiddos/antiddos`. Поэтому перед установкой выполнить:

```bash
cd /www/antiddos
scripts/build-local.sh
```

Скрипт последовательно запускает Go-тесты, `go vet`, production-сборку web assets и атомарно заменяет локальный бинарник. Если зависимости web ещё не установлены, один раз выполнить `(cd web && npm ci)`.

Установка собранной версии с web и checker:

```bash
sudo bash /www/antiddos/scripts/install.sh --local --web --soft-block
```

Существующие `/etc/antiddos/config.json`, challenge keys и база пользователей сохраняются. Для действительно чистой приёмки их удаление или перенос выполняется отдельно и только осознанно.

## 2. Чистая ручная установка администратором

1. Отсоединить текущие Nginx include перед удалением checker: `sudo scripts/two-site-lab.sh detach`; для `bgt.my` также временно убрать созданные ранее AntiDDoS include по штатной инструкции удаления.
2. Остановить/удалить AntiDDoS. Не удалять Nginx, PHP-FPM, `bgt.my` и lab-upstream.
3. Установить бинарник, daemon, web и checker согласно инструкции продукта.
4. Собрать `/etc/antiddos/config.json` по [примеру](../tests/integration/two-site/config.hybrid.example.json). Не копировать вслепую: сначала проверить пути логов и пороги.
5. Проверить JSON: `sudo jq . /etc/antiddos/config.json`.
6. Сгенерировать два комплекта include:

```bash
sudo /usr/local/bin/antiddos nginx-snippet --config /etc/antiddos/config.json --site bgt  --output /etc/nginx/snippets/antiddos-bgt  --write
sudo /usr/local/bin/antiddos nginx-snippet --config /etc/antiddos/config.json --site bgt2 --output /etc/nginx/snippets/antiddos-bgt2 --write
```

Если каталог уже существует, генератор специально не перезаписывает файлы: старый каталог надо сначала осознанно переименовать в backup.

7. Для `bgt.my` подключить `server-context.conf`, `fastcgi-location.conf`, выделенный access log и http-level include. Для `bgt2.test` это делает лабораторная команда после генерации:

```bash
sudo scripts/two-site-lab.sh attach
```

8. Добавить фактического Nginx worker user в `antiddos-check`, перезапустить Nginx (reload недостаточен после изменения supplementary groups), затем запустить сервисы.
9. Выполнить doctor и preflight:

```bash
sudo /usr/local/bin/antiddos soft-block doctor --config /etc/antiddos/config.json --site bgt
sudo /usr/local/bin/antiddos soft-block doctor --config /etc/antiddos/config.json --site bgt2
sudo scripts/two-site-load.sh preflight hybrid
```

## 3. Функциональная матрица

Для первой проверки независимых политик использовать [config.independent.example.json](../tests/integration/two-site/config.independent.example.json): `bgt.my` имеет CAPTCHA + nftables, а `bgt2.test` только фиксирует detections. `bgt2` в этом профиле остаётся в baseline-Nginx без `auth_request`: это отдельно доказывает, что `dry_run` не требует checker.

```bash
sudo cp /etc/antiddos/config.json /etc/antiddos/config.json.before-independent
sudo install -o root -g root -m 0644 tests/integration/two-site/config.independent.example.json /etc/antiddos/config.json
sudo jq . /etc/antiddos/config.json >/dev/null
sudo systemctl restart antiddos.service antiddos-challenge.service
sudo scripts/two-site-load.sh independent
```

Ожидается: медленный burst на `bgt.my` даёт CAPTCHA, быстрый — nftables, а быстрый burst на `bgt2.test` остаётся ответом приложения и даёт только detection.

Для смены `block_mode` переустановка не нужна. Сохранить JSON/GUI, затем сделать контролируемый restart `antiddos.service`. Для `soft_block`/`hybrid` перезапустить и checker, потому что он также загружает конфигурацию; в чистом `nftables` checker можно остановить. Это смена режима в эксплуатации, но не бесшовный hot reload.

```bash
sudo systemctl restart antiddos.service antiddos-challenge.service
sudo systemctl status antiddos.service antiddos-challenge.service --no-pager
```

| Режим | Подача | Ожидаемый результат |
|---|---|---|
| `dry_run` | soft и hard burst | detections видны, ни CAPTCHA, ни nft block нет |
| `soft_block` | slow и hard burst | оба правила трактуются как CAPTCHA, firewall block нет |
| `hybrid` | slow burst | только правило `*-soft`, HTTP 429 со страницей ALTCHA |
| `hybrid` | 10 запросов <1 s | `*-hard`, источник появляется в nftables; жёсткий уровень приоритетнее |
| `nftables` | оба burst | оба правила трактуются как firewall block, checker не нужен |

После каждого ручного переключения запустить единый режимный probe:

```bash
sudo scripts/two-site-load.sh mode-probe dry_run
sudo scripts/two-site-load.sh mode-probe soft_block
sudo scripts/two-site-load.sh mode-probe hybrid
sudo scripts/two-site-load.sh mode-probe nftables
```

Запускается только строка, соответствующая текущему `block_mode`. Probe использует отдельные source IP и сам проверяет ожидаемый application/CAPTCHA/nftables результат.

Команды для текущего hybrid:

```bash
sudo scripts/two-site-load.sh soft hybrid
sudo scripts/two-site-load.sh hard hybrid
sudo scripts/two-site-load.sh browser hybrid
sudo scripts/two-site-load.sh fault-checker hybrid
```

Browser-проверка проходит ALTCHA реальным Chrome, проверяет `Secure`/`HttpOnly` pass-cookie и десять последующих пропусков. Выполнить её для обоих сайтов. Cookie одного host не должна давать пропуск на другом.

Дополнительно вручную проверить:

- неправильный Origin, CSRF, повтор verify и изменённый payload отклоняются;
- после истечения `cookie_ttl` снова выдаётся CAPTCHA;
- restart daemon/checker восстанавливает активные soft-решения из SQLite;
- restart daemon восстанавливает ещё действующие nft leases;
- глобальный и rule-level whitelist не создают действий;
- остановленный checker даёт fail-open приложения максимум после локального timeout 200 ms;
- logrotate обоих файлов не теряет новые строки, старый inode дренируется;
- остановка daemon не ломает приложение, но прекращает появление новых решений;
- обычные внешние сайты и системный DNS работают до и после теста.

## 4. Часовой сквозной soak

```bash
sudo scripts/two-site-load.sh soak 3600
```

Нагрузчик не меняет конфиг и не переустанавливает сервис. Он отправляет реальные HTTPS-запросы на оба virtual host, создаёт baseline, медленные soft-bursts и быстрые hard-bursts, снимает RSS/PID/NRestarts и `monitor`. Для hard traffic используются временные loopback-адреса из benchmark-сети `198.18.0.0/15`, поэтому nftables не блокирует `127.0.0.1` и не ломает локальные сайты. Временные адреса и блокировки убираются trap-ом.

Во время прогона открыть `http://127.0.0.1:8080/` и проверить обновление примерно раз в 2 секунды:

- трафик и detections идут от двух log source;
- видны `bgt-soft`, `bgt-hard`, `bgt2-soft`, `bgt2-hard`;
- метрики CAPTCHA разделены на `bgt` и `bgt2`;
- `Выдано`, `Решено`, `Пропуск по cookie` согласуются с browser-приёмкой;
- `Потеряно агрегатов = 0`, checker/feed остаются ready;
- график не замирает после restart или ротации логов.

Артефакты создаются в `/var/log/antiddos/two-site-soak-<timestamp>/`: события, ресурсы, последний/final monitor, снимок конфига и финальные состояния systemd.

## 5. Критерии приёмки

- Оба сайта доступны до защиты, под защитой и после её снятия.
- Решение одного сайта никогда не влияет на второй; логи не смешиваются.
- Реакция daemon → feed → checker наблюдается без периодического ожидания; сама статистика появляется в GUI не позднее следующего двухсекундного flush.
- Soft threshold не создаёт nft block; hard threshold в hybrid создаёт именно nft block.
- CAPTCHA решается, cookie пропускает повторные запросы только для своего host и живёт не дольше `cookie_ttl`.
- Checker fail-open не превращает сбой защиты в недоступность сайта.
- За час нет падений/самопроизвольных рестартов, устойчивого роста RSS/FD, parse failures, dropped aggregates и необъяснимых пропусков detections.
- Смена всех четырёх режимов требует только изменения конфигурации и restart, а не переустановки.

## 6. Уборка лаборатории

Сначала отсоединить AntiDDoS include, затем удалить checker. Полностью удалить второй тестовый сайт:

```bash
sudo scripts/two-site-lab.sh detach
sudo scripts/two-site-lab.sh cleanup
```

`cleanup` удаляет только файлы с маркером этой лаборатории и точечную строку `bgt2.test`; настройки DNS/resolver и конфигурацию `bgt.my` он не меняет.
