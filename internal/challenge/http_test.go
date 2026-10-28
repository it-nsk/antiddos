package challenge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var inputValue = regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`)

func setTrustedHeaders(request *http.Request, uri string) {
	request.Host = "example.test"
	request.Header.Set("X-AntiDDoS-Host", "example.test")
	request.Header.Set("X-AntiDDoS-Authority", "example.test")
	request.Header.Set("X-AntiDDoS-Scheme", "https")
	request.Header.Set("X-AntiDDoS-IP", "192.0.2.25")
	request.Header.Set("X-AntiDDoS-URI", uri)
}

func TestHTTPSHandlerIssuesSingleUsePassCookieAndSelfHostedAsset(t *testing.T) {
	now := time.Now()
	service := testService(t, now)
	var err error
	service.metrics, err = openMetrics(filepath.Join(t.TempDir(), "metrics.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer service.metrics.close()
	server := httptest.NewTLSServer(service.PublicHandler())
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/__antiddos/challenge", nil)
	setTrustedHeaders(request, "/protected?q=1")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, _ := io.ReadAll(response.Body)
	body := string(bodyBytes)
	response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Cache-Control") != "no-store, private" || response.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("challenge response status=%d headers=%v", response.StatusCode, response.Header)
	}
	var form map[string]string
	form = map[string]string{}
	for _, match := range inputValue.FindAllStringSubmatch(body, -1) {
		form[match[1]] = match[2]
	}
	if form["task_id"] == "" || form["csrf"] == "" || !strings.Contains(body, "<altcha-widget") || !strings.Contains(body, "challenge=") {
		t.Fatalf("challenge page omitted widget/task: %s", body)
	}
	var session *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == SessionCookieName {
			session = cookie
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.Path != "/" || session.Domain != "" {
		t.Fatalf("unsafe browser session cookie: %+v", session)
	}
	service.mu.Lock()
	task := service.tasks[form["task_id"]].Task
	service.mu.Unlock()
	payload := solveTask(t, task)
	values := url.Values{"task_id": {task.ID}, "csrf": {task.CSRF}, "altcha": {payload}}
	request, _ = http.NewRequest(http.MethodPost, server.URL+"/__antiddos/verify", strings.NewReader(values.Encode()))
	setTrustedHeaders(request, "/__antiddos/verify")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://example.test")
	request.AddCookie(session)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	verifyBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/protected?q=1" {
		t.Fatalf("verify response status=%d location=%q body=%q", response.StatusCode, response.Header.Get("Location"), verifyBody)
	}
	var pass *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == PassCookieName {
			pass = cookie
		}
	}
	if pass == nil || !pass.Secure || !pass.HttpOnly || pass.Path != "/" || pass.Domain != "" || pass.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe pass cookie: %+v", pass)
	}
	if !service.ValidPassCookie(pass.Value, "example.test", time.Now()) {
		t.Fatal("issued pass cookie did not validate")
	}
	if err := service.metrics.flush(time.Now()); err != nil {
		t.Fatal(err)
	}
	rows, err := service.metrics.query(now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil || len(rows) != 2 || rows[0].Reason != metricIssued || rows[0].Count != 1 || rows[1].Reason != metricSolved || rows[1].Count != 1 {
		t.Fatalf("challenge metrics rows=%+v err=%v", rows, err)
	}
	assetRequest, _ := http.NewRequest(http.MethodGet, server.URL+"/__antiddos/assets/altcha.min.js", nil)
	setTrustedHeaders(assetRequest, "/__antiddos/assets/altcha.min.js")
	asset, err := client.Do(assetRequest)
	if err != nil {
		t.Fatal(err)
	}
	assetBytes, _ := io.ReadAll(asset.Body)
	asset.Body.Close()
	if asset.StatusCode != 200 || asset.Header.Get("Cache-Control") != "no-cache" || !strings.Contains(asset.Header.Get("Content-Type"), "javascript") || !strings.Contains(string(assetBytes), "customElements") {
		t.Fatalf("self-hosted asset status=%d content-type=%q", asset.StatusCode, asset.Header.Get("Content-Type"))
	}
	clientScript, err := client.Get(server.URL + "/__antiddos/assets/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, clientScript.Body)
	clientScript.Body.Close()
	if clientScript.StatusCode != http.StatusOK || clientScript.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("challenge script status=%d cache-control=%q", clientScript.StatusCode, clientScript.Header.Get("Cache-Control"))
	}
}

func TestHTTPVerifyRejectsMissingOriginAndWrongMethod(t *testing.T) {
	service := testService(t, time.Now())
	server := httptest.NewTLSServer(service.PublicHandler())
	defer server.Close()
	client := server.Client()
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/__antiddos/verify", strings.NewReader("task_id=x"))
	setTrustedHeaders(request, "/protected")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing session status=%d", response.StatusCode)
	}
	request, _ = http.NewRequest(http.MethodGet, server.URL+"/__antiddos/verify", nil)
	setTrustedHeaders(request, "/protected")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status=%d", response.StatusCode)
	}
	_ = context.Background()
}

func TestVerificationMetricsIncludeEarlyFormRejection(t *testing.T) {
	now := time.Now()
	service := testService(t, now)
	var err error
	service.metrics, err = openMetrics(filepath.Join(t.TempDir(), "metrics.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer service.metrics.close()
	r := httptest.NewRequest(http.MethodPost, "https://example.test/__antiddos/verify", strings.NewReader("task_id=x"))
	setTrustedHeaders(r, "/__antiddos/verify")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	service.PublicHandler().ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", w.Code)
	}
	if err := service.metrics.flush(now); err != nil {
		t.Fatal(err)
	}
	rows, err := service.metrics.query(now.Add(-time.Minute), now.Add(time.Minute), 10)
	if err != nil || len(rows) != 1 || rows[0].Site != "main" || rows[0].Reason != metricRejected || rows[0].Count != 1 {
		t.Fatalf("metrics=%+v err=%v", rows, err)
	}
}
