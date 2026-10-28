package nginxsnippet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/it-nsk/antiddos/internal/config"
)

func TestRenderSiteIncludes(t *testing.T) {
	files, err := Render(config.SiteConfig{
		ID:         "bgt",
		Hosts:      []string{"bgt.my"},
		LogSources: []string{"web"},
	}, []config.LogSourceConfig{{
		ID:        "web",
		Path:      "/var/log/nginx/bgt-access.log",
		Format:    config.LogFormatNginxCustom,
		LogFormat: `$remote_addr [$time_local] "$request" $status $body_bytes_sent $antiddos_response_origin`,
	}}, "/etc/nginx/snippets/antiddos-bgt")
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]string, len(files))
	for _, file := range files {
		byName[file.Name] = file.Content
	}
	for _, name := range []string{"http-shared.conf", "http-site.conf", "server-context.conf", "proxy-location.conf", "fastcgi-location.conf", "README.txt"} {
		if byName[name] == "" {
			t.Errorf("missing generated file %q", name)
		}
	}
	for name, wants := range map[string][]string{
		"http-shared.conf":      {"map $sent_http_x_antiddos_response_origin $antiddos_response_origin"},
		"http-site.conf":        {`log_format antiddos_bgt_web '$remote_addr [$time_local]`},
		"server-context.conf":   {"location = /__antiddos_check", "proxy_pass http://unix:/run/antiddos-challenge-check/check.sock:/__antiddos_check;", "proxy_set_header Upgrade $http_upgrade;", "@antiddos_bgt_challenge", "add_header X-AntiDDoS-Response-Origin service always;"},
		"proxy-location.conf":   {"auth_request /__antiddos_check;", "proxy_intercept_errors off;"},
		"fastcgi-location.conf": {"fastcgi_intercept_errors off;", "fastcgi_hide_header X-AntiDDoS-Response-Origin;"},
		"README.txt":            {`Include "/etc/nginx/snippets/antiddos-bgt/http-shared.conf" once`, `access_log "/var/log/nginx/bgt-access.log" antiddos_bgt_web;`, "worker account must belong to the antiddos-check group", "After changing group membership, restart Nginx"},
	} {
		for _, want := range wants {
			if !strings.Contains(byName[name], want) {
				t.Errorf("%s missing %q:\n%s", name, want, byName[name])
			}
		}
	}
}

func TestRenderRejectsUnsafeSiteAndLogSourceIDs(t *testing.T) {
	tests := []struct {
		name    string
		site    config.SiteConfig
		sources []config.LogSourceConfig
	}{
		{name: "site path injection", site: config.SiteConfig{ID: "../bgt"}, sources: []config.LogSourceConfig{{ID: "web"}}},
		{name: "source path injection", site: config.SiteConfig{ID: "bgt"}, sources: []config.LogSourceConfig{{ID: "web; include /tmp/x"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Render(tt.site, tt.sources, "/tmp/snippets"); err == nil {
				t.Fatal("Render() error = nil, want validation error")
			}
		})
	}
}

func TestWriteDoesNotOverwriteExistingFiles(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, []File{{Name: "a.conf", Content: "first"}}); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, []File{{Name: "a.conf", Content: "second"}, {Name: "b.conf", Content: "other"}}); err == nil {
		t.Fatal("Write() error = nil, want refusal to overwrite")
	}
	got, err := os.ReadFile(filepath.Join(dir, "a.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "first" {
		t.Fatalf("existing file was changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.conf")); !os.IsNotExist(err) {
		t.Fatalf("b.conf exists after preflight failure: err=%v", err)
	}
}
