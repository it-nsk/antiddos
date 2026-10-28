#!/usr/bin/env bash
set -Eeuo pipefail

command_name="${1:-help}"
lab_dir=/var/lib/antiddos-two-site-lab
site_conf=/etc/nginx/conf.d/bgt2-antiddos-lab.conf
http_conf=/etc/nginx/conf.d/01-antiddos-bgt2-lab.conf
unit_file=/etc/systemd/system/antiddos-lab-upstream.service
cert_file="$lab_dir/bgt2.crt"
key_file="$lab_dir/bgt2.key"
content_dir="$lab_dir/www"
host_line='127.0.0.1 bgt2.test # antiddos-two-site-lab'

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { ((EUID == 0)) || fail "run through sudo"; }
require_commands() {
    local name
    for name in nginx systemctl openssl python3 install awk grep sed curl getent touch chgrp chmod; do
        command -v "$name" >/dev/null || fail "$name is required"
    done
}
managed_or_absent() {
    local path=$1
    [[ ! -e "$path" ]] || grep -q 'managed by scripts/two-site-lab.sh' "$path" || fail "$path exists and is not managed by this lab"
}
write_base_site() {
    cat >"$site_conf" <<EOF
# managed by scripts/two-site-lab.sh
server {
    listen 80;
    server_name bgt2.test;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name bgt2.test;
    ssl_certificate $cert_file;
    ssl_certificate_key $key_file;
    access_log /var/log/nginx/bgt2_access.log;
    location / {
        proxy_pass http://127.0.0.1:18081;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
}
write_attached_site() {
    [[ -f /etc/nginx/snippets/antiddos-bgt2/server-context.conf ]] || fail "generate bgt2 snippets first"
    [[ -f /etc/nginx/snippets/antiddos-bgt2/proxy-location.conf ]] || fail "bgt2 proxy snippet is missing"
    [[ -f /etc/nginx/snippets/antiddos-bgt2/http-site.conf ]] || fail "bgt2 http snippet is missing"
    cat >"$site_conf" <<EOF
# managed by scripts/two-site-lab.sh
server {
    listen 80;
    server_name bgt2.test;
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl;
    server_name bgt2.test;
    ssl_certificate $cert_file;
    ssl_certificate_key $key_file;
    include /etc/nginx/snippets/antiddos-bgt2/server-context.conf;
    location / {
        include /etc/nginx/snippets/antiddos-bgt2/proxy-location.conf;
        access_log /var/log/nginx/bgt2_antiddos.log antiddos_bgt2_bgt2_access;
        proxy_pass http://127.0.0.1:18081;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF
    cat >"$http_conf" <<'EOF'
# managed by scripts/two-site-lab.sh
include /etc/nginx/snippets/antiddos-bgt2/http-site.conf;
EOF
}
case "$command_name" in
    prepare)
        require_root; require_commands
        managed_or_absent "$site_conf"; managed_or_absent "$unit_file"
        install -d -o root -g root -m 0755 "$lab_dir" "$content_dir"
        if [[ ! -s "$cert_file" || ! -s "$key_file" ]]; then
            openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
                -subj /CN=bgt2.test -addext subjectAltName=DNS:bgt2.test \
                -keyout "$key_file" -out "$cert_file" >/dev/null 2>&1
            chmod 0600 "$key_file"; chmod 0644 "$cert_file"
        fi
        cat >"$content_dir/index.html" <<'EOF'
<!doctype html><html lang="ru"><meta charset="utf-8"><title>bgt2 AntiDDoS lab</title><body><h1>bgt2.test</h1><p>Отдельный proxy-контур AntiDDoS.</p></body></html>
EOF
        cat >"$unit_file" <<EOF
# managed by scripts/two-site-lab.sh
[Unit]
Description=AntiDDoS two-site lab upstream
After=network.target
[Service]
Type=simple
ExecStart=/usr/bin/python3 -m http.server 18081 --bind 127.0.0.1 --directory $content_dir
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
        write_base_site
        grep -Fqx "$host_line" /etc/hosts || printf '%s\n' "$host_line" >>/etc/hosts
        systemctl daemon-reload
        systemctl enable --now antiddos-lab-upstream.service
        nginx -t
        systemctl reload nginx
        curl --noproxy '*' -ksSf --resolve bgt2.test:443:127.0.0.1 https://bgt2.test/ >/dev/null
        printf 'bgt2.test baseline is ready; AntiDDoS is not attached yet.\n'
        ;;
    attach)
        require_root; require_commands
        managed_or_absent "$site_conf"; managed_or_absent "$http_conf"
        getent group adm >/dev/null || fail "group adm is required for daemon log access"
        touch /var/log/nginx/bgt2_antiddos.log
        chgrp adm /var/log/nginx/bgt2_antiddos.log
        chmod 0640 /var/log/nginx/bgt2_antiddos.log
        write_attached_site
        nginx -t
        systemctl reload nginx
        printf 'bgt2.test is attached to generated AntiDDoS snippets.\n'
        ;;
    detach)
        require_root; require_commands
        managed_or_absent "$site_conf"
        rm -f -- "$http_conf"
        write_base_site
        nginx -t
        systemctl reload nginx
        printf 'bgt2.test remains available, AntiDDoS includes are detached.\n'
        ;;
    cleanup)
        require_root; require_commands
        managed_or_absent "$site_conf"; managed_or_absent "$unit_file"
        systemctl disable --now antiddos-lab-upstream.service 2>/dev/null || true
        rm -f -- "$site_conf" "$http_conf" "$unit_file"
        awk '$0 != "127.0.0.1 bgt2.test # antiddos-two-site-lab"' /etc/hosts >"$lab_dir/hosts.new"
        install -o root -g root -m 0644 "$lab_dir/hosts.new" /etc/hosts
        systemctl daemon-reload
        nginx -t
        systemctl reload nginx
        printf 'Two-site lab Nginx host and upstream were removed. Data remains in %s.\n' "$lab_dir"
        ;;
    status)
        printf 'bgt2 DNS: '; getent hosts bgt2.test || true
        systemctl --no-pager --full status antiddos-lab-upstream.service || true
        nginx -T 2>&1 | grep -n -B2 -A8 -E 'server_name bgt2\.test|antiddos-bgt2' || true
        curl --noproxy '*' -ksS -o /dev/null -w 'bgt2 HTTP %{http_code}\n' --resolve bgt2.test:443:127.0.0.1 https://bgt2.test/
        ;;
    *)
        printf 'Usage: sudo %s prepare|attach|detach|status|cleanup\n' "$0"
        printf 'prepare: independent bgt2 proxy site; attach: enable generated AntiDDoS includes.\n'
        ;;
esac
