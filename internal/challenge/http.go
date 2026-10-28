package challenge

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/it-nsk/antiddos/internal/softfeed"
)

//go:embed assets/*.js
var assets embed.FS

var challengePage = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verify your browser</title>
<style>html,body{min-height:100%;margin:0}body{min-height:100vh;box-sizing:border-box;background:#f4f6fa;color:#24324a;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;display:grid;place-items:center;padding:24px}main{box-sizing:border-box;width:min(100%,520px);padding:36px 40px;background:#fff;border:1px solid #e1e6ee;border-radius:12px;box-shadow:0 14px 40px #20324a12;text-align:center}h1{margin:0 0 12px;font-size:26px}p{line-height:1.6;color:#66758c}form{display:grid;justify-items:center;gap:18px}altcha-widget{display:block;max-width:100%}button{border:1px solid #3866df;border-radius:6px;background:#3866df;color:#fff;padding:10px 22px;font:inherit;cursor:pointer}button:hover{background:#2857cf}#challenge-error{min-height:1.5em;color:#b43e39;margin:0}</style>
<script type="module" src="/__antiddos/assets/altcha.min.js" defer></script><script type="module" src="/__antiddos/assets/challenge.js" defer></script></head>
<body><main><h1>Verify your browser</h1><p>This site is checking that your browser can complete a small proof of work.</p>
<form id="challenge-form" method="post" action="/__antiddos/verify"><input type="hidden" name="task_id" value="{{.TaskID}}"><input type="hidden" name="csrf" value="{{.CSRF}}">
<altcha-widget auto="onload" minDuration="100" challenge="{{.Challenge}}"></altcha-widget><button type="submit">Continue</button><p id="challenge-error" role="alert" aria-live="polite"></p></form>
<noscript><p>JavaScript is required for browser verification.</p></noscript></main></body></html>`))

var errFeedUnavailable = errors.New("feed unavailable")

func boundedCheckHandler(handler http.Handler) http.Handler {
	return http.TimeoutHandler(handler, 150*time.Millisecond, "checker deadline exceeded\n")
}

func (service *Service) PublicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__antiddos/challenge", service.serveChallenge)
	mux.HandleFunc("POST /__antiddos/verify", service.serveVerify)
	mux.Handle("/__antiddos_check", boundedCheckHandler(http.HandlerFunc(service.serveCheck)))
	mux.HandleFunc("GET /__antiddos/assets/altcha.min.js", service.serveAsset)
	mux.HandleFunc("GET /__antiddos/assets/challenge.js", service.serveChallengeAsset)
	return mux
}

func (service *Service) CheckHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/__antiddos_check", boundedCheckHandler(http.HandlerFunc(service.serveCheck)))
	return mux
}

func (service *Service) serveCheck(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("Authorization") != "" || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		checkResponse(w, http.StatusForbidden, "integration_error", "unexpected_credentials_or_body")
		return
	}
	method := r.Header.Get("X-AntiDDoS-Method")
	if method == "" {
		method = r.Method
	}
	if method != http.MethodGet && method != http.MethodHead {
		checkResponse(w, http.StatusNoContent, "bypass", "unsupported_method")
		return
	}
	if r.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		checkResponse(w, http.StatusNoContent, "bypass", "protocol_upgrade")
		return
	}
	host, _, scheme, ip, returnURL, siteID, err := service.trustedMetadata(r)
	if errors.Is(err, errFeedUnavailable) {
		service.recordMetric("global", metricFailOpen)
		checkResponse(w, http.StatusNoContent, "allow", "no_snapshot")
		return
	}
	if err != nil {
		checkResponse(w, http.StatusForbidden, "integration_error", "invalid_metadata")
		return
	}
	if strings.HasPrefix(returnURL, "/__antiddos/") || returnURL == "/__antiddos_check" {
		checkResponse(w, http.StatusNoContent, "service", "service_route")
		return
	}
	if scheme != "https" {
		checkResponse(w, http.StatusNoContent, "bypass", "https_required")
		return
	}
	result := service.state.Check(siteID, ip, service.clock())
	if !result.Challenge {
		checkResponse(w, http.StatusNoContent, "allow", result.Reason)
		return
	}
	pass := ""
	passCount := 0
	for _, cookie := range r.Cookies() {
		if cookie.Name == PassCookieName {
			pass, passCount = cookie.Value, passCount+1
		}
	}
	if passCount == 1 && service.ValidPassCookie(pass, host, service.clock()) {
		service.recordMetric(siteID, metricImmunity)
		checkResponse(w, http.StatusNoContent, "allow", "pass_cookie")
		return
	}
	checkResponse(w, http.StatusForbidden, "challenge", result.Reason)
}

func checkResponse(w http.ResponseWriter, status int, decision, reason string) {
	w.Header().Set("X-AntiDDoS-Decision", decision)
	w.Header().Set("X-AntiDDoS-Reason", reason)
	w.WriteHeader(status)
}

func (service *Service) serveChallenge(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	if r.URL.RawQuery != "" {
		http.Error(w, "unexpected query parameters", http.StatusBadRequest)
		return
	}
	host, _, scheme, ip, returnURL, _, err := service.trustedMetadata(r)
	if err != nil {
		http.Error(w, "invalid checker metadata", http.StatusBadRequest)
		return
	}
	if scheme != "https" {
		http.Error(w, "challenge requires HTTPS", http.StatusBadRequest)
		return
	}
	session := ""
	if cookie, err := r.Cookie(SessionCookieName); err == nil && validSession(cookie.Value) {
		session = cookie.Value
	} else {
		session, err = service.NewSession()
		if err != nil {
			http.Error(w, "challenge unavailable", http.StatusServiceUnavailable)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: SessionCookieName, Value: session, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(TaskTTL.Seconds())})
	}
	task, err := service.CreateTask(host, ip, session, returnURL, time.Now())
	if err != nil {
		if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "capacity") || strings.Contains(err.Error(), "too many active") {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "challenge temporarily unavailable", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "challenge temporarily unavailable", http.StatusServiceUnavailable)
		return
	}
	if !task.reused {
		service.recordMetric(task.SiteID, metricIssued)
	}
	challengeJSON, err := json.Marshal(task.Challenge)
	if err != nil {
		http.Error(w, "challenge unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	setNoStore(w)
	setChallengeSecurityHeaders(w)
	if err := challengePage.Execute(w, struct{ TaskID, CSRF, Challenge string }{task.ID, task.CSRF, string(challengeJSON)}); err != nil {
		return
	}
}

func (service *Service) serveVerify(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	host, authority, scheme, _, _, siteID, err := service.trustedMetadata(r)
	if err != nil {
		http.Error(w, "invalid checker metadata", http.StatusBadRequest)
		return
	}
	verified := false
	defer func() {
		if !verified {
			service.recordMetric(siteID, metricRejected)
		}
	}()
	if scheme != "https" {
		http.Error(w, "verification requires HTTPS", http.StatusBadRequest)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "unexpected query parameters", http.StatusBadRequest)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		http.Error(w, "expected form submission", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "form is invalid or too large", http.StatusBadRequest)
		return
	}
	for key, values := range r.PostForm {
		if len(values) != 1 || key != "task_id" && key != "csrf" && key != "altcha" {
			http.Error(w, "unexpected form fields", http.StatusBadRequest)
			return
		}
	}
	sessionCookie, err := r.Cookie(SessionCookieName)
	if err != nil || !validSession(sessionCookie.Value) {
		http.Error(w, "browser session expired; reload the challenge", http.StatusBadRequest)
		return
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		http.Error(w, "Origin is required", http.StatusForbidden)
		return
	}
	result, err := service.Verify(r.Context(), VerifyRequest{TaskID: r.PostForm.Get("task_id"), SessionID: sessionCookie.Value, SiteID: siteID, Host: host, Authority: authority, Scheme: scheme, Origin: origin, CSRF: r.PostForm.Get("csrf"), Payload: r.PostForm.Get("altcha")}, time.Now())
	if err != nil {
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "rate limit") || strings.Contains(err.Error(), "capacity") || strings.Contains(err.Error(), "busy") {
			status = http.StatusTooManyRequests
		}
		http.Error(w, "verification failed; reload the challenge and try again", status)
		return
	}
	returnURL, err := ValidateReturnURL(result.ReturnURL)
	if err != nil {
		http.Error(w, "saved return path is invalid", http.StatusBadRequest)
		return
	}
	snapshot, _ := service.state.Current()
	ttl, _ := time.ParseDuration(snapshot.CookieTTL)
	http.SetCookie(w, &http.Cookie{Name: PassCookieName, Value: result.PassCookie, Path: "/", Expires: time.Now().Add(ttl), MaxAge: int(ttl.Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	verified = true
	service.recordMetric(siteID, metricSolved)
	w.Header().Set("Location", returnURL)
	w.WriteHeader(http.StatusSeeOther)
}

func (service *Service) serveChallengeAsset(w http.ResponseWriter, r *http.Request) {
	data, err := assets.ReadFile("assets/challenge.js")
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

func (service *Service) serveAsset(w http.ResponseWriter, r *http.Request) {
	data, err := assets.ReadFile("assets/altcha.min.js")
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

func (service *Service) trustedMetadata(r *http.Request) (host, authority, scheme string, ip netip.Addr, returnURL, siteID string, err error) {
	host = r.Header.Get("X-AntiDDoS-Host")
	authority = r.Header.Get("X-AntiDDoS-Authority")
	scheme = r.Header.Get("X-AntiDDoS-Scheme")
	rawIP := r.Header.Get("X-AntiDDoS-IP")
	authorityHost, authorityOK := parseAuthority(authority)
	if !validHost(host) || !authorityOK || authorityHost != host || (scheme != "https" && scheme != "http") || !verifyOrigin(scheme, authority, scheme+"://"+authority) {
		err = fmt.Errorf("invalid trusted host or scheme")
		return
	}
	ip, err = netip.ParseAddr(rawIP)
	if err != nil || ip.Zone() != "" {
		err = fmt.Errorf("invalid trusted client IP")
		return
	}
	ip = ip.Unmap()
	rawReturn := r.Header.Get("X-AntiDDoS-URI")
	returnURL, err = ValidateReturnURL(rawReturn)
	if err != nil {
		return
	}
	snapshot, ok := service.state.Current()
	if !ok {
		err = errFeedUnavailable
		return
	}
	for _, site := range snapshot.Sites {
		for _, candidate := range site.Hosts {
			if candidate == host {
				siteID = site.ID
				break
			}
		}
		if siteID != "" {
			break
		}
	}
	if siteID == "" {
		err = fmt.Errorf("host not configured")
		return
	}
	return
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("Pragma", "no-cache")
}
func setChallengeSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:; connect-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (service *Service) ValidPassCookie(token, host string, now time.Time) bool {
	snapshot, ok := service.state.Current()
	if !ok || !softfeed.SnapshotUsesSoftBlock(*snapshot) {
		return false
	}
	ttl, err := time.ParseDuration(snapshot.CookieTTL)
	if err != nil {
		return false
	}
	siteID := ""
	for _, site := range snapshot.Sites {
		for _, candidate := range site.Hosts {
			if candidate == host {
				siteID = site.ID
				break
			}
		}
		if siteID != "" {
			break
		}
	}
	if siteID == "" {
		return false
	}
	return VerifyPassCookie(service.cookieKeys, token, siteID, host, ttl, now) == nil
}
