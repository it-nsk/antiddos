package challenge

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type adminStatus struct {
	Health         string `json:"health"`
	Mode           string `json:"mode,omitempty"`
	ConfigRevision string `json:"config_revision,omitempty"`
	Epoch          string `json:"epoch,omitempty"`
	Revision       uint64 `json:"revision,omitempty"`
	Sites          int    `json:"sites"`
	MetricsHealth  string `json:"metrics_health"`
	MetricsDropped uint64 `json:"metrics_dropped"`
}

// AdminHandler exposes only bounded, read-only checker state. It is served on
// a separate Unix socket and is never mounted on the Nginx-facing mux.
func (service *Service) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "" {
			http.Error(w, "unexpected query parameters", http.StatusBadRequest)
			return
		}
		status := adminStatus{Health: service.state.Health(service.clock())}
		status.MetricsHealth = "unavailable"
		if service.metrics != nil {
			service.metrics.mu.Lock()
			status.MetricsHealth = "ready"
			if service.metrics.degraded {
				status.MetricsHealth = "degraded"
			}
			status.MetricsDropped = service.metrics.lost
			service.metrics.mu.Unlock()
		}
		if snapshot, ok := service.state.Current(); ok {
			status.Mode = snapshot.Mode
			status.ConfigRevision = snapshot.ConfigRevision
			status.Epoch = snapshot.Epoch
			status.Revision = snapshot.Revision
			status.Sites = len(snapshot.Sites)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(w).Encode(status)
	})
	mux.HandleFunc("GET /v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		q, parseErr := url.ParseQuery(r.URL.RawQuery)
		if parseErr != nil || len(q) != 3 || len(q["from"]) != 1 || len(q["to"]) != 1 || len(q["limit"]) != 1 {
			http.Error(w, "invalid query", http.StatusBadRequest)
			return
		}
		from, e1 := time.Parse(time.RFC3339, q.Get("from"))
		to, e2 := time.Parse(time.RFC3339, q.Get("to"))
		limit, e3 := strconv.Atoi(q.Get("limit"))
		if e1 != nil || e2 != nil || e3 != nil || !to.After(from) || to.Sub(from) > metricRetention || limit < 1 || limit > 1000 {
			http.Error(w, "invalid range or limit", http.StatusBadRequest)
			return
		}
		if service.metrics == nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		rows, err := service.metrics.query(from, to, limit)
		if err != nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_ = json.NewEncoder(w).Encode(rows)
	})
	return mux
}
