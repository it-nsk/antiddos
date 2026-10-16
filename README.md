# antiddos

Linux service that analyzes Nginx access logs, records traffic and detections in SQLite, and can temporarily block client IPs through nftables.

## Quick start

On a Linux amd64 server, replace the path with the access log for the site you want to monitor:

```shell
curl -fsSL https://raw.githubusercontent.com/it-nsk/antiddos/dev/scripts/install.sh -o /tmp/antiddos-install.sh
sudo bash /tmp/antiddos-install.sh --log-file /var/log/nginx/access.log
sudo -u antiddos /usr/local/bin/antiddos monitor
```

The installer downloads the latest release, creates `/etc/antiddos/config.json`, and starts the service in `dry_run` mode. This records detections without changing the firewall. `monitor` refreshes every two seconds; press `Ctrl+C` to exit. The daemon keeps running.

To change settings, edit `/etc/antiddos/config.json` and restart the service:

```shell
sudoedit /etc/antiddos/config.json
sudo systemctl restart antiddos
```

The default config watches one access log. For multiple logs, use `log_sources` and bind each rule to a source with `log_source` (example below).

<details>
<summary>Find the right Nginx access log and its format</summary>

```shell
sudo nginx -T 2>/dev/null | grep -nE '^[[:space:]]*(server_name|log_format|access_log|error_log)'
```

Match the `access_log` directive to the site's `server_name`. The supported inputs are Nginx **access logs** in `nginx_combined` or `nginx_custom` format. If the directive does not name a format, Nginx uses `combined`. For a custom format, copy its complete `log_format` directive into the matching source's `log_format` setting. AntiDDoS does not read or modify `nginx.conf`.

`error_log` and SSH/authentication logs are not supported: they need different parsers and event rules.

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

`block_tcp_ports` limits blocking to TCP destination ports, for example `[80, 443]`. If omitted or empty, the address is blocked on all protocols and ports. For Docker traffic, the `forward` rule sees the container-side port after destination NAT. Blocking is server-wide, not limited to one Nginx site. Behind a proxy, make sure Nginx records the real client IP before enabling enforcement.

The systemd unit grants `CAP_NET_ADMIN` (Linux permission to manage host networking) to the service. In `dry_run`, the launcher drops this capability before starting the analyzer. AntiDDoS creates its own `inet antiddos` table and does not flush other nftables tables.

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

SQLite contains `traffic_samples`, `detections`, and `active_blocks`. Traffic is aggregated into 15-second buckets and flushed every 15 seconds. Detection rows are written when thresholds are reached. Active block records contain the IP and expiry; unexpired blocks are restored after daemon restart with only their remaining duration. Expired block history is removed from `active_blocks`.

## Development

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
