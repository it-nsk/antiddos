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
- IP, User-Agent, and combined groupings;
- structured dry-run detections;
- graceful shutdown on SIGINT and SIGTERM;
- automatic expiration of inactive rule groups during live tailing;
- terminal monitoring of traffic and detections stored in SQLite.

## Run and monitor

The service is always started and stopped by systemd. On startup it opens the
Nginx log, creates the SQLite database when necessary, writes traffic statistics
every 15 seconds, and writes detections as they occur.

0. The demo runs directly from the source code. On Ubuntu/Debian, install Go
and GCC first:

```shell
sudo apt-get update && sudo apt-get install -y golang-go gcc
```

These tools are required only to build and run the demo: the script uses
`go run`, and the SQLite driver is compiled through CGO. An already built
production binary does not require Go or GCC.

Run the self-contained demo from the repository root:

```shell
./scripts/demo.sh
```

It needs no configuration or systemd installation. Press `Ctrl+C` to stop; the
generated log, config, SQLite database, and service log remain in `runtime/demo/`.

1. Create the configuration file:

```shell
sudo install -D -m 0644 deploy/config.example.json /etc/antiddos/config.json
```

2. Edit `/etc/antiddos/config.json`. Minimal example:

```json
{
  "log_file": "/var/log/nginx/access.log",
  "database_path": "/var/lib/antiddos/antiddos.sqlite",
  "start_position": "end",
  "engine": {
    "rules": [{
      "id": "homepage",
      "window": "5s",
      "threshold": 5,
      "suspicious_threshold": 0,
      "groupings": [
        {"id": "by_ip", "fields": ["ip"]},
        {"id": "by_user_agent", "fields": ["user_agent"]},
        {"id": "by_ip_user_agent", "fields": ["ip", "user_agent"]}
      ]
    }]
  }
}
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
```

`monitor` refreshes every two seconds and shows the latest 20 traffic intervals
and latest 20 detections. Use `Ctrl+C` to leave monitoring; the service keeps
running. Use `monitor --once` for one snapshot. It opens SQLite read-only and
does not require the external `sqlite3` command.

The binary uses `ANTIDDOS_CONFIG` and `ANTIDDOS_LOG_FILE`. The supplied systemd
unit sets `ANTIDDOS_CONFIG` to `/etc/antiddos/config.json` and reads the optional
log override from `/etc/default/antiddos`. Direct foreground execution remains
available for development with `antiddos run`.

## Rule configuration

The template is [deploy/config.example.json](deploy/config.example.json).
Systemd uses `/etc/antiddos/config.json`.
In live mode (`start_position: "end"`), `engine.live_event_lateness` defaults
to `30s`. It is the accepted delay between an event timestamp and wall clock;
after that watermark advances, older events are counted as late and excluded.
This bounded delay lets the service release expired groups during quiet periods
without advancing the event-time frontier. Historical mode
(`start_position: "beginning"` or `--from-start`) disables wall-clock expiry
and uses only timestamps from the replayed log.
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

Each detection stores one `group_values_json` field for the value or values
that identify the group, along with `grouping_id` to say which grouping was
used. Every request at or above the main threshold is recorded. Detections run in
dry-run mode and do not mean a request was blocked.

Example query for recent traffic buckets:

The `sqlite3` command examples require the optional SQLite command-line client.
The service itself does not require that client to run.

```shell
sqlite3 /var/lib/antiddos/antiddos.sqlite \
  <<'SQL'
SELECT datetime(bucket_start_unix, 'unixepoch'),
       1.0 * requests / interval_seconds AS requests_per_second,
       homepage_requests, response_bytes, known_response_byte_rows,
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

The current rule counts `GET /` requests, including query parameters, in the
exact `(t-W, t]` window:

- `window` sets `W`;
- `threshold` sets the violation threshold `N`;
- Early-warning (`suspicious`) detections are disabled; only the main threshold
  produces detection records.

The fifth request triggers when `N=5`. The sixth and every later request also
produce detections while the exact window count remains at least five. Once the
count falls below five, detections stop until it reaches the threshold again.

Groupings use one or more fields: `ip`, `user_agent`, `method`, `path`, and
`status`. Each rule and grouping has independent window state.

Events are processed immediately in the order read from the log. An event with
a timestamp earlier than the last processed event is excluded from rule windows
and counted as late. In live mode, events older than the configured wall-clock
lateness watermark are also excluded; replay mode has no wall-clock watermark.

## TODO

- [x] Daemon and systemd unit.
- [x] Continuous Nginx log reader.
- [x] Nginx parser and typed request events.
- [x] Homepage rule and exact sliding window.
- [x] Configurable and combined groupings.
- [x] Structured detections for every request at or above the main threshold.
- [x] Metrics and SQLite persistence.
- [x] Terminal monitoring of SQLite traffic and detections.
- [ ] Installation script.
- [ ] Performance measurements.
