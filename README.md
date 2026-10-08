# antiddos

Monitoring and blocking suspicious activity on your webserver

Go service for analyzing Nginx access logs. The current MVP works in dry-run
mode and does not block requests or modify the firewall.

## Implemented

- direct and systemd execution;
- continuous Nginx log reading through fsnotify/inotify;
- partial-line, truncate, and rename/create rotation handling;
- parsing log lines into typed request events;
- exact sliding-window analysis using log timestamps;
- configurable request-count threshold and time window;
- one configurable grouping field per rule;
- structured dry-run detections;
- graceful shutdown on SIGINT and SIGTERM;
- automatic expiration of inactive rule groups during live tailing;
- terminal monitoring of traffic and detections stored in SQLite.

## Quick start

On a Linux amd64 server, replace the path with the Nginx access log that should
be monitored:

```shell
curl -fsSL https://raw.githubusercontent.com/it-nsk/antiddos/dev/scripts/install.sh -o /tmp/antiddos-install.sh
sudo bash /tmp/antiddos-install.sh --log-file /var/log/nginx/access.log
sudo -u antiddos /usr/local/bin/antiddos monitor
```

The installer downloads the latest GitHub Release, verifies its SHA256 checksum,
creates the `antiddos` account, installs the binary, example configuration and
systemd unit, enables and starts the service, creates the SQLite database, and
verifies that the terminal monitor can read it.
On first install it creates `/etc/antiddos/config.json` from the example; later
installer runs preserve an existing configuration.
`monitor` refreshes every two seconds; exit it with `Ctrl+C`. The systemd
service continues running in the background.

If the daemon is running and you need to change a setting, for example to add
an IP to the whitelist:

```shell
sudoedit /etc/antiddos/config.json
sudo systemctl restart antiddos
```

Installation and runtime paths:

```text
Nginx log:  path passed through --log-file
Config:     /etc/antiddos/config.json
Binary:     /usr/local/bin/antiddos
SQLite:     /var/lib/antiddos/antiddos.sqlite
Systemd:    antiddos.service
```

Existing configuration and SQLite data are preserved when the installer is run
again. The server does not need Git, Go, GCC, or the project source code. Install
a specific release with `--version v0.1.0`.

## Configuration and service control

Edit `/etc/antiddos/config.json` when its defaults do not match the server.
Minimal example:

```json
{
  "log_file": "/var/log/nginx/access.log",
  "database_path": "/var/lib/antiddos/antiddos.sqlite",
  "start_position": "end",
  "engine": {
    "ignore_ips": [],
    "rules": [{
      "id": "homepage",
      "path_regex": "^/$",
      "window": "5s",
      "threshold": 5,
      "group_by": "ip"
    }]
  }
}
```

Apply configuration changes with:

```shell
sudo systemctl restart antiddos
```

The log path can instead be overridden in `/etc/default/antiddos`:

```shell
ANTIDDOS_LOG_FILE=/var/log/nginx/access.log
```

Start and stop the daemon:

```shell
sudo systemctl start antiddos
sudo systemctl stop antiddos
```

Watch both SQLite tables in the terminal:

```shell
sudo -u antiddos /usr/local/bin/antiddos monitor
sudo -u antiddos /usr/local/bin/antiddos monitor --limit 100
```

`monitor` refreshes every two seconds. By default it shows the latest 20 traffic
intervals and 20 detections. Pass `--limit N` to change both row limits, for
example `--limit 100`; valid values are 1–1000. The refresh interval stays two
seconds regardless of the limit. Use `Ctrl+C` to leave monitoring; the service
keeps running. Use `monitor --once` for one snapshot. It opens SQLite read-only
and does not require the external `sqlite3` command.

The binary uses `ANTIDDOS_CONFIG` and `ANTIDDOS_LOG_FILE`. The supplied systemd
unit sets `ANTIDDOS_CONFIG` to `/etc/antiddos/config.json` and reads the optional
log override from `/etc/default/antiddos`. Direct foreground execution remains
available for development with `antiddos run`.

## Rule configuration

The template is [deploy/config.example.json](deploy/config.example.json).
Systemd uses `/etc/antiddos/config.json`.
In live mode (`start_position: "end"`), expired groups are released from memory
every second, including while the input log is quiet. Historical mode
(`start_position: "beginning"` or `--from-start`) uses only timestamps from the
replayed log and does not advance cleanup from wall-clock time.
`database_path` selects the SQLite file and defaults to
`/var/lib/antiddos/antiddos.sqlite`, which is writable by the supplied systemd
unit through `StateDirectory=antiddos`.

SQLite stores `traffic_samples` and `detections`. Traffic counters are grouped
into 15-second buckets by the timestamp in the Nginx log. They are flushed to
SQLite every 15 seconds of runtime; late events update the bucket matching
their log timestamp. Each traffic row contains request counts and the sum and
known-value count for response bytes, so average response size and byte rate can
be calculated without storing per-request rows. Detection rows are inserted
immediately for every request whose group is at or above the threshold and
preserve the request timestamp and its timezone as written in the log. The
database file is restricted to the service account.

`traffic_samples.bucket_start_unix` identifies the start of each interval;
`interval_seconds` gives its duration. No separate last-update timestamp is
stored because it can be derived from the interval boundaries.

Each detection stores the selected `group_by` field in `grouping_id` and its
single value in `group_values_json`. Every request at or above the threshold is
recorded. Detections run in dry-run mode and do not mean a request was blocked.

Example query for recent traffic buckets:

The `sqlite3` command examples require the optional SQLite command-line client.
The service itself does not require that client to run.

```shell
sqlite3 /var/lib/antiddos/antiddos.sqlite \
  <<'SQL'
SELECT datetime(bucket_start_unix, 'unixepoch'),
       1.0 * requests / interval_seconds AS requests_per_second,
       matched_requests, response_bytes, known_response_byte_rows,
       CASE WHEN known_response_byte_rows = 0 THEN NULL
            ELSE 1.0 * response_bytes / known_response_byte_rows END AS average_response_bytes
FROM traffic_samples ORDER BY bucket_start_unix DESC LIMIT 20;
SQL

sqlite3 /var/lib/antiddos/antiddos.sqlite \
  <<'SQL'
SELECT event_time_text, rule_id, grouping_id, group_values_json,
       trigger_ip, trigger_user_agent, request_count, window_millis,
       threshold, dry_run
FROM detections ORDER BY event_time_unix_ns DESC LIMIT 50;
SQL
```

Each rule counts matching `GET` requests in the exact `(t-W, t]` window:

- `path_regex` is matched against the parsed URL path only; query parameters
  are deliberately excluded, so `^/$` matches both `/` and `/?key=value`;
- `window` sets `W`;
- `threshold` sets the violation threshold `N`;
- `group_by` selects exactly one of `ip`, `user_agent`, `method`, `path`, or
  `status`.

The fifth request triggers when `N=5`. The sixth and every later request also
produce detections while the exact window count remains at least five. Once the
count falls below five, detections stop until it reaches the threshold again.

Each rule has its own path expression, grouping field, and independent window
state.

`engine.ignore_ips` accepts individual IPv4 and IPv6 addresses, plus CIDR
prefixes for either address family. It does not resolve DNS names or load
external files. Ignored requests remain in traffic statistics, including
rule-matched counts, but do not enter rule windows or produce detections.
Add the addresses and networks to the `ignore_ips` array, replacing these
documentation-only examples with the addresses used by your server:

```json
"ignore_ips": [
  "192.0.2.10",
  "198.51.100.0/24",
  "2001:db8::1",
  "2001:db8:1::/48"
]
```

Events are processed immediately in the order read from the log. An event with
a timestamp earlier than the last processed event is excluded from rule windows
and counted as late.

## Publishing a release

The workflow in `.github/workflows/release.yml` runs for tags beginning with
`v`. It tests the project, builds the Linux amd64 archive, creates its SHA256
file, and publishes both files in a GitHub Release. Repository Actions settings
must allow `Read and write permissions` for the workflow token.

Publish a version from the commit that should be released:

```shell
git switch dev
git pull
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

Watch the run in GitHub Actions. After it succeeds, the normal installer uses
that release automatically through the `releases/latest/download` URL.

## TODO

- [x] Daemon and systemd unit.
- [x] Continuous Nginx log reader.
- [x] Nginx parser and typed request events.
- [x] Configurable path rules and exact sliding windows.
- [x] One configurable grouping field per rule.
- [x] Structured detections for every request at or above the threshold.
- [x] Metrics and SQLite persistence.
- [x] Terminal monitoring of SQLite traffic and detections.
- [x] Installation script.
- [ ] Performance measurements.
