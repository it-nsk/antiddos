# antiddos

Monitoring and blocking suspicious activity on your webserver

A Linux service written in Go for analyzing Nginx access logs. The current MVP
runs in dry-run mode: it reads the log but does not block requests or modify the
firewall.

## Implemented

- direct and systemd-based execution;
- reading new lines through fsnotify/inotify;
- retaining incomplete lines until they are complete;
- basic truncate and rename/create handling;
- live mode from EOF and historical mode from the beginning;
- graceful shutdown on SIGINT and SIGTERM.

Current launch commands, until the installer is implemented:

```shell
# Run directly
cp deploy/config.example.json config.local.json
# Set log_file in config.local.json, then run:
go run ./cmd/antiddos run --config config.local.json

# Run the installed systemd service
sudo systemctl start antiddos
systemctl status antiddos
journalctl -u antiddos -f
```

## Requirements

- Linux amd64;
- Go 1.26.8;
- read access to the Nginx access log.

## Configuration

```json
{
  "log_file": "/var/log/nginx/access.log",
  "start_position": "end"
}
```

The configuration template is available at
[deploy/config.example.json](deploy/config.example.json). Local configuration
belongs in the ignored `config.local.json`; systemd uses
`/etc/antiddos/config.json`.

## TODO

- [ ] Nginx parser and typed `RequestEvent`.
- [ ] Homepage rule and exact sliding window.
- [ ] IP and User-Agent grouping.
- [ ] Structured detections and severity levels.
- [ ] Metrics and SQLite persistence.
- [ ] Statistics CLI.
- [ ] Installation script.
- [ ] Performance measurements.
