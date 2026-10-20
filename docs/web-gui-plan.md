# Web GUI implementation

1. Local SQLite users (CLI provisioning), admin/viewer roles, revocable cookie sessions,
   CSRF protection and bounded login throttling. No public signup or default passwords.
2. Separate unprivileged Go web process, embedded React assets, read-only statistics
   queries with bounded time ranges and pagination. No per-request daemon interaction.
3. A restricted daemon API changes only global/per-rule ignore_ips and each rule's
   path_regex in the primary JSON file: validate the complete configuration, prevent
   stale writes, save atomically, and require an explicit daemon restart. The same API
   serves bounded statistics and reports whether the file differs from the daemon's
   startup configuration.
4. React dashboard: traffic rates/bytes/averages, detections, active blocks, users,
   global time selector and chart zoom, rule/whitelist editor. Authentication and permissions
   enforced on the server. Documentation, unit/security/integration/browser verification.

References: Zabbix internal users/roles and shared dashboard time selector.
https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/users/user_roles
https://www.zabbix.com/documentation/current/en/manual/web_interface/frontend_sections/dashboards

Deployment: loopback HTTP by default; HTTPS reverse proxy with an explicit public origin
for remote access. Separate web users/sessions database, no CAP_NET_ADMIN or config-file
access in the web unit. Firewall control uses another daemon-only socket. No restart API.
