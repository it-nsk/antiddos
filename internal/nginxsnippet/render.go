package nginxsnippet

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/it-nsk/antiddos/internal/challenge"
	"github.com/it-nsk/antiddos/internal/config"
)

type File struct {
	Name    string
	Content string
}

var safeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Render creates preview files for one already-validated soft-block site.
// http-shared.conf must be included once per Nginx http context; all other
// files are site-specific and are included in the contexts documented in README.
func Render(site config.SiteConfig, sources []config.LogSourceConfig, outputDir string) ([]File, error) {
	if !safeID.MatchString(site.ID) {
		return nil, fmt.Errorf("invalid site ID %q", site.ID)
	}
	if len(site.Hosts) == 0 {
		return nil, fmt.Errorf("site %q has no hosts", site.ID)
	}
	if len(site.LogSources) == 0 || len(sources) != len(site.LogSources) {
		return nil, fmt.Errorf("site %q requires one configured log source for every log_sources entry", site.ID)
	}
	if !filepath.IsAbs(outputDir) || strings.ContainsAny(outputDir, "\x00\r\n") {
		return nil, fmt.Errorf("output directory must be an absolute single-line path")
	}

	byID := make(map[string]config.LogSourceConfig, len(sources))
	for _, source := range sources {
		if !safeID.MatchString(source.ID) {
			return nil, fmt.Errorf("invalid log source ID %q", source.ID)
		}
		if !filepath.IsAbs(source.Path) || strings.ContainsAny(source.Path, "\x00\r\n") {
			return nil, fmt.Errorf("log source %q path must be an absolute single-line path", source.ID)
		}
		if source.Format != config.LogFormatNginxCustom || !strings.Contains(source.LogFormat, "$antiddos_response_origin") || strings.ContainsAny(source.LogFormat, "\x00\r\n") {
			return nil, fmt.Errorf("log source %q requires a single-line nginx_custom format containing $antiddos_response_origin", source.ID)
		}
		if _, exists := byID[source.ID]; exists {
			return nil, fmt.Errorf("duplicate log source ID %q", source.ID)
		}
		byID[source.ID] = source
	}

	var httpSite strings.Builder
	var readme strings.Builder
	fmt.Fprintf(&httpSite, "# Site %s log formats. Include in the http context.\n", site.ID)
	fmt.Fprintf(&readme, "AntiDDoS soft-block Nginx preview for site %s\nHosts: %s\n\n", site.ID, strings.Join(site.Hosts, ", "))
	readme.WriteString("Before enabling, the Nginx worker account must belong to the antiddos-check group to connect to the checker Unix socket. After changing group membership, restart Nginx so workers receive the new group list.\n\n")
	fmt.Fprintf(&readme, "1. Include %s once in the Nginx http context.\n", nginxQuote(filepath.Join(outputDir, "http-shared.conf")))
	fmt.Fprintf(&readme, "2. Include %s in the http context. It defines formats for this site's configured access logs.\n", nginxQuote(filepath.Join(outputDir, "http-site.conf")))
	fmt.Fprintf(&readme, "3. Include %s inside each matching HTTPS server block. It does not create or replace server/listen/TLS directives.\n", nginxQuote(filepath.Join(outputDir, "server-context.conf")))
	fmt.Fprintf(&readme, "4. In each selected existing proxy location, include %s. In each selected FastCGI location, include %s. Do not include both in one location.\n", nginxQuote(filepath.Join(outputDir, "proxy-location.conf")), nginxQuote(filepath.Join(outputDir, "fastcgi-location.conf")))
	fmt.Fprintf(&readme, "5. In those same application locations, add the matching access_log directive below. Keep the source-to-location mapping accurate; do not attach every source to every server if that would duplicate or mix traffic.\n")
	fmt.Fprintf(&readme, "6. Review inherited add_header directives on both the protected application locations and the generated server locations. Merge/copy existing security headers where needed; Nginx header inheritance can otherwise change. Review route conflicts before including.\n\n")
	fmt.Fprintf(&readme, "Access log directives to add to the corresponding protected application locations:\n")

	for _, sourceID := range site.LogSources {
		source, ok := byID[sourceID]
		if !ok {
			return nil, fmt.Errorf("site %q references missing log source %q", site.ID, sourceID)
		}
		formatName := "antiddos_" + site.ID + "_" + source.ID
		fmt.Fprintf(&httpSite, "log_format %s '%s';\n", formatName, nginxSingleQuote(source.LogFormat))
		fmt.Fprintf(&readme, "access_log %s %s; # source %s\n", nginxQuote(source.Path), formatName, source.ID)
	}

	server := renderServer(site.ID)
	proxyLocation := renderProtectedLocation(site.ID, true)
	fastcgiLocation := renderProtectedLocation(site.ID, false)
	readme.WriteString("\nThis is a preview bundle. It does not edit the active Nginx configuration or reload Nginx.\n")
	readme.WriteString("Before enabling: check existing auth_request, error_page, satisfy, add_header, and challenge-route conflicts; run nginx -t; then reload manually.\n")
	readme.WriteString("Application proxy/FastCGI error interception stays off so application 401/403/429/500 responses remain application responses.\n")
	readme.WriteString("The check subrequest uses a 200 ms socket timeout and fails open on checker 5xx/unavailability. This adds a synchronous local auth_request to protected requests; it does not wait for the one-second feed poll.\n")

	return []File{
		{Name: "http-shared.conf", Content: renderSharedHTTP()},
		{Name: "http-site.conf", Content: httpSite.String()},
		{Name: "server-context.conf", Content: server},
		{Name: "proxy-location.conf", Content: proxyLocation},
		{Name: "fastcgi-location.conf", Content: fastcgiLocation},
		{Name: "README.txt", Content: readme.String()},
	}, nil
}

func renderSharedHTTP() string {
	return `# Include once in the Nginx http context.
map $sent_http_x_antiddos_response_origin $antiddos_response_origin {
    challenge challenge;
    service service;
    default application;
}
`
}

func renderServer(siteID string) string {
	var b strings.Builder
	checkSocket := challenge.DefaultCheckSocketPath
	fmt.Fprintf(&b, "# Include inside each matching HTTPS server block for site %s.\n", siteID)
	b.WriteString("location = /__antiddos_check {\n")
	b.WriteString("    internal;\n")
	fmt.Fprintf(&b, "    proxy_pass http://unix:%s:/__antiddos_check;\n", checkSocket)
	b.WriteString("    proxy_pass_request_body off;\n    proxy_set_header Content-Length \"\";\n")
	b.WriteString(metadataHeaders(siteID))
	b.WriteString("    proxy_connect_timeout 200ms;\n    proxy_read_timeout 200ms;\n    proxy_send_timeout 200ms;\n")
	b.WriteString("    proxy_intercept_errors on;\n")
	b.WriteString("    error_page 500 501 502 503 504 505 506 507 508 510 511 = @antiddos_")
	b.WriteString(siteID)
	b.WriteString("_fail_open;\n}\n\n")
	fmt.Fprintf(&b, "location @antiddos_%s_fail_open {\n    add_header X-AntiDDoS-Response-Origin service always;\n    return 204;\n}\n\n", siteID)
	fmt.Fprintf(&b, "location @antiddos_%s_challenge {\n", siteID)
	fmt.Fprintf(&b, "    if ($antiddos_%s_decision != challenge) { return 403; }\n", siteID)
	b.WriteString("    rewrite ^ /__antiddos/challenge? break;\n")
	fmt.Fprintf(&b, "    proxy_pass http://unix:%s:;\n", checkSocket)
	b.WriteString(metadataHeaders(siteID))
	b.WriteString("    add_header X-AntiDDoS-Response-Origin challenge always;\n}\n\n")

	for _, route := range []struct{ path, marker string }{
		{path: "/__antiddos/challenge", marker: "challenge"},
		{path: "/__antiddos/verify", marker: "service"},
	} {
		fmt.Fprintf(&b, "location = %s {\n    auth_request off;\n", route.path)
		fmt.Fprintf(&b, "    proxy_pass http://unix:%s:;\n", checkSocket)
		b.WriteString(metadataHeaders(siteID))
		fmt.Fprintf(&b, "    add_header X-AntiDDoS-Response-Origin %s always;\n}\n\n", route.marker)
	}
	fmt.Fprintf(&b, "location ^~ /__antiddos/assets/ {\n    auth_request off;\n    proxy_pass http://unix:%s:;\n", checkSocket)
	b.WriteString(metadataHeaders(siteID))
	b.WriteString("    add_header X-AntiDDoS-Response-Origin service always;\n}\n")
	return b.String()
}

func renderProtectedLocation(siteID string, proxy bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Include inside an existing protected application location for site %s.\n", siteID)
	b.WriteString("auth_request /__antiddos_check;\n")
	fmt.Fprintf(&b, "auth_request_set $antiddos_%s_decision $upstream_http_x_antiddos_decision;\n", siteID)
	fmt.Fprintf(&b, "error_page 403 =429 @antiddos_%s_challenge;\n", siteID)
	if proxy {
		b.WriteString("proxy_intercept_errors off;\nproxy_hide_header X-AntiDDoS-Response-Origin;\n")
	} else {
		b.WriteString("fastcgi_intercept_errors off;\nfastcgi_hide_header X-AntiDDoS-Response-Origin;\n")
	}
	b.WriteString("add_header X-AntiDDoS-Response-Origin application always;\n")
	return b.String()
}

func metadataHeaders(siteID string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "    proxy_set_header X-AntiDDoS-Site %s;\n", siteID)
	b.WriteString("    proxy_set_header X-AntiDDoS-IP $remote_addr;\n")
	b.WriteString("    proxy_set_header X-AntiDDoS-Host $host;\n")
	b.WriteString("    proxy_set_header X-AntiDDoS-Authority $http_host;\n")
	b.WriteString("    proxy_set_header X-AntiDDoS-URI $request_uri;\n")
	b.WriteString("    proxy_set_header X-AntiDDoS-Method $request_method;\n")
	b.WriteString("    proxy_set_header X-AntiDDoS-Scheme $scheme;\n")
	b.WriteString("    proxy_set_header Upgrade $http_upgrade;\n")
	b.WriteString("    proxy_set_header Connection $http_connection;\n")
	b.WriteString("    proxy_set_header X-Forwarded-For \"\";\n")
	b.WriteString("    proxy_set_header Host localhost;\n")
	b.WriteString("    proxy_set_header Authorization \"\";\n")
	b.WriteString("    proxy_set_header Cookie $http_cookie;\n")
	return b.String()
}

func nginxSingleQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `'`, `\'`)
}

func nginxQuote(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, `$`, `\$`)
	return `"` + value + `"`
}
