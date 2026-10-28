// Package softfeed serves the daemon's versioned, read-only decision snapshot
// over a private Unix socket.
package softfeed

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/it-nsk/antiddos/internal/unixsocket"
)

const DefaultSocketPath = "/run/antiddos-soft-feed/feed.sock"

const FeedHeartbeat = 2 * time.Second

type Snapshot struct {
	Protocol       int        `json:"protocol"`
	Epoch          string     `json:"epoch"`
	Revision       uint64     `json:"revision"`
	Mode           string     `json:"mode"`
	ConfigRevision string     `json:"config_revision"`
	Sites          []Site     `json:"sites"`
	CookieTTL      string     `json:"cookie_ttl"`
	Decisions      []Decision `json:"decisions"`
}
type Site struct {
	ID    string   `json:"id"`
	Hosts []string `json:"hosts"`
}
type Decision struct {
	SiteID    string    `json:"site_id"`
	RuleID    string    `json:"rule_id"`
	SourceID  string    `json:"source_id"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
type Response struct {
	Protocol       int         `json:"protocol"`
	Epoch          string      `json:"epoch"`
	Revision       uint64      `json:"revision"`
	Unchanged      bool        `json:"unchanged,omitempty"`
	Mode           string      `json:"mode,omitempty"`
	ConfigRevision string      `json:"config_revision,omitempty"`
	Sites          *[]Site     `json:"sites,omitempty"`
	CookieTTL      string      `json:"cookie_ttl,omitempty"`
	Decisions      *[]Decision `json:"decisions,omitempty"`
}

type Source interface {
	FeedSnapshot(epoch string, now time.Time) Snapshot
}

type RevisionWaiter interface {
	WaitForRevision(ctx context.Context, revision uint64)
}

type Server struct {
	Source Source
	Epoch  string
}

func NewEpoch() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("create feed epoch: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}

func (server Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/soft-decisions", func(w http.ResponseWriter, r *http.Request) {
		if server.Source == nil || server.Epoch == "" {
			http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
			return
		}
		query, err := parseQuery(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		snapshot := server.Source.FeedSnapshot(server.Epoch, time.Now())
		if query.wait && query.epoch == snapshot.Epoch && query.revision == snapshot.Revision {
			if waiter, ok := server.Source.(RevisionWaiter); ok {
				waitCtx, cancel := context.WithTimeout(r.Context(), FeedHeartbeat)
				waiter.WaitForRevision(waitCtx, query.revision)
				cancel()
				snapshot = server.Source.FeedSnapshot(server.Epoch, time.Now())
			}
		}
		response := Response{Protocol: snapshot.Protocol, Epoch: snapshot.Epoch, Revision: snapshot.Revision}
		if query.epoch == snapshot.Epoch && query.revision == snapshot.Revision {
			response.Unchanged = true
		} else {
			if snapshot.Sites == nil {
				snapshot.Sites = []Site{}
			}
			if snapshot.Decisions == nil {
				snapshot.Decisions = []Decision{}
			}
			response.Mode = snapshot.Mode
			response.ConfigRevision = snapshot.ConfigRevision
			response.Sites = &snapshot.Sites
			response.CookieTTL = snapshot.CookieTTL
			response.Decisions = &snapshot.Decisions
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(response)
	})
	return mux
}

type clientQuery struct {
	epoch    string
	revision uint64
	wait     bool
}

func parseQuery(values url.Values) (clientQuery, error) {
	if len(values) > 3 {
		return clientQuery{}, fmt.Errorf("unexpected query parameters")
	}
	for key, items := range values {
		if key != "epoch" && key != "revision" && key != "wait" || len(items) != 1 {
			return clientQuery{}, fmt.Errorf("invalid query parameters")
		}
	}
	q := clientQuery{epoch: values.Get("epoch")}
	if raw := values.Get("wait"); raw != "" {
		if raw != "1" {
			return clientQuery{}, fmt.Errorf("invalid wait parameter")
		}
		q.wait = true
	}
	if len(q.epoch) > 128 {
		return clientQuery{}, fmt.Errorf("epoch is too long")
	}
	if raw := values.Get("revision"); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			return clientQuery{}, fmt.Errorf("invalid revision")
		}
		q.revision = value
	}
	if (q.epoch == "") != (values.Get("revision") == "") {
		return clientQuery{}, fmt.Errorf("epoch and revision must be provided together")
	}
	if q.wait && q.epoch == "" {
		return clientQuery{}, fmt.Errorf("wait requires epoch and revision")
	}
	return q, nil
}

// Serve owns only the configured test/production feed socket and removes it
// when its own listener shuts down. It refuses to replace regular files.
func Serve(ctx context.Context, path string, source Source, epoch string) error {
	return ServeWithGroup(ctx, path, source, epoch, -1)
}

func ServeWithGroup(ctx context.Context, path string, source Source, epoch string, groupID int) error {
	if path == "" || source == nil || epoch == "" {
		return fmt.Errorf("feed socket path, source, and epoch are required")
	}
	listener, cleanup, err := unixsocket.Listen(path, 0750, 0660, groupID)
	if err != nil {
		return fmt.Errorf("listen on feed socket: %w", err)
	}
	defer func() { _ = listener.Close(); _ = cleanup() }()
	server := &http.Server{Handler: (Server{Source: source, Epoch: epoch}).Handler(), ReadHeaderTimeout: 2 * time.Second, MaxHeaderBytes: 16 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		err := <-done
		if err != nil && err != http.ErrServerClosed {
			return err
		}
		return nil
	case err := <-done:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
