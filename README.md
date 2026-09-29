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
- configurable window and severity thresholds;
- IP, User-Agent, and combined groupings;
- structured dry-run detections;
- graceful shutdown on SIGINT and SIGTERM.

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

Requires Linux amd64, Go 1.26.8, and read access to the configured log.

## Rule configuration

The template is [deploy/config.example.json](deploy/config.example.json).
Systemd uses `/etc/antiddos/config.json`.

The current rule counts `GET /` requests, including query parameters, in the
exact `(t-W, t]` window:

- `window` sets `W`;
- `threshold` sets the violation threshold `N`;
- `suspicious_threshold` sets the earlier warning threshold.

The fifth request triggers when `N=5`. Detections are emitted when a threshold
is crossed, while all observed requests continue to be counted.

Groupings use one or more fields: `ip`, `user_agent`, `method`, `path`, and
`status`. Each rule and grouping has independent window state.

`allowed_lateness` is optional and defaults to `0s` for immediate processing.

## TODO

- [x] Daemon and systemd unit.
- [x] Continuous Nginx log reader.
- [x] Nginx parser and typed request events.
- [x] Homepage rule and exact sliding window.
- [x] Configurable and combined groupings.
- [x] Structured detections and severity levels.
- [ ] Metrics and SQLite persistence.
- [ ] Statistics CLI.
- [ ] Installation script.
- [ ] Performance measurements.
