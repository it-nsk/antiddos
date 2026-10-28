// Package webui serves the embedded React app and its authenticated local API.
package webui

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/it-nsk/antiddos/internal/challengeadmin"
	"github.com/it-nsk/antiddos/internal/configservice"
	"github.com/it-nsk/antiddos/internal/storage"
	"github.com/it-nsk/antiddos/internal/webauth"
	"github.com/it-nsk/antiddos/internal/webcontrol"
)

//go:embed assets/*
var assets embed.FS

const cookieName = "antiddos_session"

type Options struct{ Listen, Origin, UsersDB, DaemonSocket string }

type Backend interface {
	Dashboard(context.Context, time.Time, time.Time, int64, int) (storage.Dashboard, error)
	Config(context.Context) (webcontrol.ConfigState, error)
	SaveRules(context.Context, configservice.Update) (webcontrol.ConfigState, error)
	ChallengeStatus(context.Context) (challengeadmin.Status, error)
	ChallengeMetrics(context.Context, time.Time, time.Time, int) ([]challengeadmin.Metric, error)
	SoftBlocks(context.Context, int) ([]storage.SoftBlockLease, error)
}

type Server struct {
	auth       *webauth.Store
	backend    Backend
	logger     *slog.Logger
	origin     *url.URL
	mux        http.Handler
	loginSlots chan struct{}
	mu         sync.Mutex
	attempts   map[string]attempt
}
type attempt struct {
	count int
	until time.Time
}

func ValidateOptions(o Options) error {
	host, port, err := net.SplitHostPort(o.Listen)
	if err != nil {
		return fmt.Errorf("listen must be a loopback IP:port")
	}
	ip := net.ParseIP(host)
	n, e := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || e != nil || n < 1 || n > 65535 {
		return fmt.Errorf("web must listen on a loopback IP and valid port; use an HTTPS reverse proxy for remote access")
	}
	u, err := url.Parse(o.Origin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return fmt.Errorf("origin must be a scheme and host, without a path")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || (net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()))) {
		return fmt.Errorf("origin must use HTTPS, except for loopback access")
	}
	return nil
}
func New(o Options, auth *webauth.Store, backend Backend, logger *slog.Logger) (*Server, error) {
	if err := ValidateOptions(o); err != nil {
		return nil, err
	}
	origin, _ := url.Parse(o.Origin)
	s := &Server{auth: auth, backend: backend, logger: logger, origin: origin, loginSlots: make(chan struct{}, 2), attempts: map[string]attempt{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", s.login)
	mux.HandleFunc("GET /api/session", s.protected(false, func(w http.ResponseWriter, r *http.Request, v webauth.Session) { writeJSON(w, 200, v) }))
	mux.HandleFunc("POST /api/logout", s.protected(false, s.logout))
	mux.HandleFunc("GET /api/dashboard", s.protected(false, s.dashboard))
	mux.HandleFunc("GET /api/challenge/status", s.protected(false, s.challengeStatus))
	mux.HandleFunc("GET /api/challenge/metrics", s.protected(false, s.challengeMetrics))
	mux.HandleFunc("GET /api/soft-blocks", s.protected(false, s.softBlocks))
	mux.HandleFunc("GET /api/config", s.protected(false, s.getConfig))
	mux.HandleFunc("PUT /api/config/rules", s.protected(true, s.saveConfig))
	mux.HandleFunc("GET /api/users", s.protected(true, s.users))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "Endpoint not found") })
	sub, _ := fs.Sub(assets, "assets")
	files := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			fail(w, 405, "Method not allowed")
			return
		}
		if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/assets/") {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
	s.mux = mux
	return s, nil
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-store")
	if r.Host != s.origin.Host {
		fail(w, 403, "Unexpected host")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.origin.String() {
		fail(w, 403, "Unexpected origin")
		return
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		fail(w, 403, "Cross-site request denied")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("Origin") != s.origin.String() {
		fail(w, 403, "Origin required")
		return
	}
	s.mux.ServeHTTP(w, r)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
func body(w http.ResponseWriter, r *http.Request, dst any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return fmt.Errorf("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON body")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("one JSON object required")
	}
	return nil
}
func (s *Server) protected(admin bool, next func(http.ResponseWriter, *http.Request, webauth.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			fail(w, 401, "Sign in required")
			return
		}
		v, err := s.auth.Authenticate(r.Context(), c.Value, time.Now())
		if err != nil {
			if !errors.Is(err, webauth.ErrSession) {
				s.internal(w, err)
				return
			}
			fail(w, 401, "Session expired")
			return
		}
		if admin && v.User.Role != "admin" {
			fail(w, 403, "Administrator role required")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(v.CSRF)) != 1 {
			fail(w, 403, "Invalid CSRF token")
			return
		}
		next(w, r, v)
	}
}
func (s *Server) throttle(key string, limit int, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.attempts {
		if !v.until.After(now) {
			delete(s.attempts, k)
		}
	}
	v, ok := s.attempts[key]
	if !ok {
		if len(s.attempts) >= 1024 {
			return false
		}
		v.until = now.Add(time.Minute)
	}
	if v.count >= limit {
		return false
	}
	v.count++
	s.attempts[key] = v
	return true
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := body(w, r, &in); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(in.Username) > 64 || len(in.Password) > 72 {
		fail(w, 401, "Invalid username or password")
		return
	}
	// Never trust forwarded client addresses. Apply a global budget as well as per-account limits.
	now := time.Now()
	if !s.throttle("all", 60, now) || !s.throttle("user:"+in.Username, 10, now) {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "Too many login attempts; wait one minute")
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		fail(w, 429, "Login busy; try again shortly")
		return
	}
	token, session, err := s.auth.Login(r.Context(), in.Username, in.Password, time.Now())
	if err != nil {
		if errors.Is(err, webauth.ErrCredentials) {
			fail(w, 401, "Invalid username or password")
			return
		}
		s.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.origin.Scheme == "https", SameSite: http.SameSiteStrictMode, MaxAge: int(webauth.SessionTTL.Seconds())})
	s.logger.Info("web login", "user", session.User.Username)
	writeJSON(w, 200, session)
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request, v webauth.Session) {
	c, _ := r.Cookie(cookieName)
	if err := s.auth.Logout(r.Context(), c.Value); err != nil {
		s.internal(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", HttpOnly: true, Secure: s.origin.Scheme == "https", SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) internal(w http.ResponseWriter, err error) {
	s.logger.Error("web request failed", "error", err)
	fail(w, 503, "Service unavailable; check server logs")
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, v webauth.Session) {
	now := time.Now().Unix()
	from, to, before := now-3600, now, int64(0)
	for key, dst := range map[string]*int64{"from": &from, "to": &to, "before": &before} {
		if value := r.URL.Query().Get(key); value != "" {
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				fail(w, 400, "Invalid time range or cursor")
				return
			}
			*dst = n
		}
	}
	if from < 0 || to <= from || to-from > 31*86400 || to > now+60 || before < 0 {
		fail(w, 400, "Select a past period of at most 31 days")
		return
	}
	// Stored traffic resolution is 15 seconds; return the actual aligned bounds.
	from = from / 15 * 15
	to = (to + 14) / 15 * 15
	if to-from > 31*86400 {
		fail(w, 400, "Range exceeds 31 days")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	data, err := s.backend.Dashboard(ctx, time.Unix(from, 0), time.Unix(to, 0), before, 100)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, data)
}
func (s *Server) softBlocks(w http.ResponseWriter, r *http.Request, _ webauth.Session) {
	if r.URL.RawQuery != "" {
		fail(w, 400, "Invalid query")
		return
	}
	rows, err := s.backend.SoftBlocks(r.Context(), 1000)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, rows)
}

func (s *Server) challengeStatus(w http.ResponseWriter, r *http.Request, _ webauth.Session) {
	if r.URL.RawQuery != "" {
		fail(w, 400, "Invalid query")
		return
	}
	status, err := s.backend.ChallengeStatus(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, status)
}

func (s *Server) challengeMetrics(w http.ResponseWriter, r *http.Request, _ webauth.Session) {
	now := time.Now().Unix()
	from, to, limit := now-3600, now, 1000
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 400, "Invalid query")
		return
	}
	for key, values := range q {
		if len(values) != 1 {
			fail(w, 400, "Invalid query")
			return
		}
		switch key {
		case "from":
			from, err = strconv.ParseInt(values[0], 10, 64)
		case "to":
			to, err = strconv.ParseInt(values[0], 10, 64)
		case "limit":
			limit, err = strconv.Atoi(values[0])
		default:
			fail(w, 400, "Invalid query")
			return
		}
		if err != nil {
			fail(w, 400, "Invalid query")
			return
		}
	}
	start, end := time.Unix(from, 0), time.Unix(to, 0)
	if from < 0 || !end.After(start) || end.Sub(start) > 7*24*time.Hour || to > now+60 || limit < 1 || limit > 1000 {
		fail(w, 400, "Invalid metrics range or limit")
		return
	}
	rows, err := s.backend.ChallengeMetrics(r.Context(), start, end, limit)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, rows)
}
func (s *Server) getConfig(w http.ResponseWriter, r *http.Request, v webauth.Session) {
	state, err := s.backend.Config(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, state)
}
func (s *Server) saveConfig(w http.ResponseWriter, r *http.Request, v webauth.Session) {
	var in configservice.Update
	if err := body(w, r, &in); err != nil {
		fail(w, 400, err.Error())
		return
	}
	state, err := s.backend.SaveRules(r.Context(), in)
	if err != nil {
		var remote *webcontrol.RemoteError
		if errors.As(err, &remote) && (remote.Status == http.StatusConflict || remote.Status == http.StatusBadRequest) {
			fail(w, remote.Status, remote.Message)
			return
		}
		s.logger.Warn("web rule configuration save rejected", "user", v.User.Username, "error", err)
		s.internal(w, err)
		return
	}
	s.logger.Info("web rule configuration saved", "user", v.User.Username, "revision", state.Config.Revision)
	writeJSON(w, 200, state)
}
func (s *Server) users(w http.ResponseWriter, r *http.Request, v webauth.Session) {
	users, err := s.auth.Users(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, users)
}
func Serve(ctx context.Context, o Options, logger *slog.Logger) error {
	if err := ValidateOptions(o); err != nil {
		return err
	}
	auth, err := webauth.Open(o.UsersDB)
	if err != nil {
		return err
	}
	defer auth.Close()
	backend := webcontrol.NewClient(o.DaemonSocket)
	handler, err := New(o, auth, backend, logger)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", o.Listen)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	logger.Info("web interface started", "listen", o.Listen, "origin", o.Origin)
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		err := server.Shutdown(shutdown)
		if err != nil {
			_ = server.Close()
		}
		<-done
		return err
	}
}
