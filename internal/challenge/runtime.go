package challenge

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/it-nsk/antiddos/internal/softfeed"
	"github.com/it-nsk/antiddos/internal/unixsocket"
)

const (
	DefaultCheckSocketPath = "/run/antiddos-challenge-check/check.sock"
	DefaultAdminSocketPath = "/run/antiddos-challenge-admin/admin.sock"
	DefaultCredentialName  = "keys.json"
	DefaultMetricsPath     = "/var/lib/antiddos-challenge/metrics.sqlite"
	MaxPublicConnections   = 256
)

type RuntimeOptions struct {
	FeedSocketPath     string
	CheckSocketPath    string
	AdminSocketPath    string
	CredentialPath     string
	MetricsPath        string
	CheckSocketGroupID int
	AdminSocketGroupID int
}

// Run starts the read-only feed client and public check/challenge HTTP socket.
// It never opens the daemon's SQLite database or firewall control socket.
func Run(ctx context.Context, options RuntimeOptions, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	if options.FeedSocketPath == "" {
		options.FeedSocketPath = softfeed.DefaultSocketPath
	}
	if options.CheckSocketPath == "" {
		options.CheckSocketPath = DefaultCheckSocketPath
	}
	if options.CredentialPath == "" {
		return fmt.Errorf("LoadCredential path is required")
	}
	provider, keys, err := LoadCredentials(options.CredentialPath)
	if err != nil {
		return err
	}
	state := softfeed.NewState()
	service, err := NewService(state, Options{ProviderSecret: provider, CookieKeys: keys})
	if err != nil {
		return err
	}
	if options.MetricsPath != "" {
		service.metrics, err = openMetrics(options.MetricsPath)
		if err != nil {
			logger.Error("checker metrics unavailable", "error", err)
		} else {
			defer service.metrics.close()
		}
	}
	listener, cleanup, err := unixsocket.Listen(options.CheckSocketPath, 0750, 0660, options.CheckSocketGroupID)
	if err != nil {
		return fmt.Errorf("create challenge check socket: %w", err)
	}
	defer func() { _ = listener.Close(); _ = cleanup() }()
	server := &http.Server{Handler: service.PublicHandler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	connections := &connectionLimiter{active: make(map[net.Conn]struct{})}
	server.ConnState = connections.transition
	type serveResult struct {
		name string
		err  error
	}
	serveDone := make(chan serveResult, 2)
	servers := []*http.Server{server}
	serverCount := 1
	go func() { serveDone <- serveResult{name: "public", err: server.Serve(listener)} }()
	if options.AdminSocketPath != "" {
		adminListener, adminCleanup, listenErr := unixsocket.Listen(options.AdminSocketPath, 0750, 0660, options.AdminSocketGroupID)
		if listenErr != nil {
			return fmt.Errorf("create challenge admin socket: %w", listenErr)
		}
		defer func() { _ = adminListener.Close(); _ = adminCleanup() }()
		adminServer := &http.Server{Handler: service.AdminHandler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
		servers = append(servers, adminServer)
		serverCount++
		go func() { serveDone <- serveResult{name: "admin", err: adminServer.Serve(adminListener)} }()
	}
	feedCtx, stopFeed := context.WithCancel(ctx)
	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		(&softfeed.Client{SocketPath: options.FeedSocketPath, State: state}).Run(feedCtx, func(err error) {
			logger.Warn("soft-block feed unavailable; checker fails open", "error", err)
		})
	}()
	maintenanceCtx, stopMaintenance := context.WithCancel(ctx)
	maintenanceDone := make(chan struct{})
	go func() { defer close(maintenanceDone); service.RunMaintenance(maintenanceCtx) }()
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		if service.metrics == nil {
			return
		}
		ticker := time.NewTicker(metricBucket)
		defer ticker.Stop()
		for {
			select {
			case now := <-ticker.C:
				if err := service.metrics.flush(now); err != nil {
					logger.Error("checker metrics flush failed", "error", err)
				}
			case <-maintenanceCtx.Done():
				return
			}
		}
	}()
	var serveErr error
	finishedServers := 0
	select {
	case <-ctx.Done():
	case result := <-serveDone:
		finishedServers++
		if result.err != http.ErrServerClosed {
			serveErr = fmt.Errorf("serve challenge %s socket: %w", result.name, result.err)
		}
	}
	stopFeed()
	stopMaintenance()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
	var shutdownErr error
	for _, current := range servers {
		if err := current.Shutdown(shutdownCtx); err != nil && shutdownErr == nil {
			shutdownErr = err
			_ = current.Close()
		}
	}
	cancelShutdown()
	for finishedServers < serverCount {
		result := <-serveDone
		finishedServers++
		if result.err != nil && result.err != http.ErrServerClosed && serveErr == nil {
			serveErr = fmt.Errorf("serve challenge %s socket: %w", result.name, result.err)
		}
	}
	<-feedDone
	<-maintenanceDone
	<-metricsDone
	if service.metrics != nil {
		if err := service.metrics.flush(time.Now()); err != nil {
			logger.Error("checker metrics final flush failed", "error", err)
		}
	}
	if serveErr != nil {
		return serveErr
	}
	if shutdownErr != nil {
		return fmt.Errorf("shutdown challenge HTTP server: %w", shutdownErr)
	}
	if ctx.Err() != nil {
		return nil
	}
	return nil
}

type connectionLimiter struct {
	mu     sync.Mutex
	active map[net.Conn]struct{}
}

func (limiter *connectionLimiter) transition(conn net.Conn, state http.ConnState) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	switch state {
	case http.StateNew:
		if len(limiter.active) >= MaxPublicConnections {
			_ = conn.Close()
			return
		}
		limiter.active[conn] = struct{}{}
	case http.StateClosed, http.StateHijacked:
		delete(limiter.active, conn)
	}
}
