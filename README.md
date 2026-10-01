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
- automatic expiration of inactive rule groups during live tailing.

## Run

```shell
cp deploy/config.example.json config.local.json
# Set log_file in config.local.json.
go run ./cmd/antiddos run --config config.local.json

# Historical replay
go run ./cmd/antiddos run --config config.local.json --from-start

# Installed systemd service
sudo systemctl start antiddos
systemctl status antiddos
journalctl -u antiddos -f
```

Requires Linux amd64, Go 1.26.8, and read access to the configured log. Building
requires `CGO_ENABLED=1` and GCC for the SQLite driver; the driver includes
SQLite, so GCC and a separate SQLite library are not needed to run the binary.

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
immediately when a rule crosses a threshold and preserve the request timestamp
and its timezone as written in the log. The database file is restricted to the
service account.

`traffic_samples.bucket_start_unix` identifies the start of each interval;
`interval_seconds` gives its duration. No separate last-update timestamp is
stored because it can be derived from the interval boundaries.

Each detection stores one `group_values_json` field for the value or values
that identify the group, along with `grouping_id` to say which grouping was
used. Only crossings of the main threshold are recorded. Detections run in
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

The fifth request triggers when `N=5`. Detections are emitted when a threshold
is crossed, while all observed requests continue to be counted.

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
- [x] Structured detections for main-threshold crossings.
- [x] Metrics and SQLite persistence.
- [ ] Statistics CLI.
- [ ] Installation script.
- [ ] Performance measurements.
