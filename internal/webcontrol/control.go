// Package webcontrol exposes the small, authenticated GUI data surface over a
// local Unix socket. It deliberately has no firewall or arbitrary config API.
package webcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/it-nsk/antiddos/internal/configservice"
	"github.com/it-nsk/antiddos/internal/storage"
)

const DefaultSocketPath = "/run/antiddos/web.sock"

type Status struct {
	ConfigRevision string    `json:"config_revision"`
	StartedAt      time.Time `json:"started_at"`
	BlockMode      string    `json:"block_mode"`
}

type ConfigState struct {
	Config          configservice.Document `json:"config"`
	Daemon          Status                 `json:"daemon"`
	DaemonAvailable bool                   `json:"daemon_available"`
	RestartRequired *bool                  `json:"restart_required"`
}

type Service struct {
	Config *configservice.Service
	Stats  *storage.Reader
	Status Status
}

func (s *Service) state() (ConfigState, error) {
	document, err := s.Config.Read()
	if err != nil {
		return ConfigState{}, err
	}
	restart := document.Revision != s.Status.ConfigRevision
	return ConfigState{Config: document, Daemon: s.Status, DaemonAvailable: true, RestartRequired: &restart}, nil
}

func (s *Service) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/config", func(w http.ResponseWriter, r *http.Request) {
		state, err := s.state()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, state)
	})
	mux.HandleFunc("PUT /v1/config/rules", func(w http.ResponseWriter, r *http.Request) {
		var update configservice.Update
		if err := decodeBody(w, r, &update); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		document, err := s.Config.Save(update)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, configservice.ErrConflict) {
				status = http.StatusConflict
			}
			writeError(w, status, err)
			return
		}
		restart := true
		writeJSON(w, http.StatusOK, ConfigState{Config: document, Daemon: s.Status, DaemonAvailable: true, RestartRequired: &restart})
	})
	mux.HandleFunc("GET /v1/dashboard", func(w http.ResponseWriter, r *http.Request) {
		from, err1 := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
		to, err2 := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
		before, err3 := strconv.ParseInt(defaultValue(r.URL.Query().Get("before"), "0"), 10, 64)
		limit, err4 := strconv.Atoi(defaultValue(r.URL.Query().Get("limit"), "100"))
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("invalid dashboard query"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		data, err := s.Stats.Dashboard(ctx, time.Unix(from, 0), time.Unix(to, 0), before, limit)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, data)
	})
	return mux
}

func Serve(ctx context.Context, path string, service *Service) error {
	listener, err := listen(path)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(path) }()
	server := &http.Server{Handler: service.handler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			return err
		}
		err := <-done
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func listen(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("web socket path is empty")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket web path %q", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return nil, fmt.Errorf("web socket %q is already active", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0660); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}

type Client struct {
	path   string
	client *http.Client
}

func NewClient(path string) *Client {
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
	}}
	return &Client{path: path, client: &http.Client{Transport: transport, Timeout: 8 * time.Second}}
}

type RemoteError struct {
	Status  int
	Message string
}

func (e *RemoteError) Error() string { return e.Message }

func (c *Client) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://antiddos"+path, body)
	if err != nil {
		return err
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("contact antiddos daemon through %s: %w", c.path, err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var failure struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&failure)
		if failure.Error == "" {
			failure.Error = res.Status
		}
		return &RemoteError{Status: res.StatusCode, Message: failure.Error}
	}
	return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(output)
}

func (c *Client) Dashboard(ctx context.Context, from, to time.Time, before int64, limit int) (storage.Dashboard, error) {
	path := fmt.Sprintf("/v1/dashboard?from=%d&to=%d&before=%d&limit=%d", from.Unix(), to.Unix(), before, limit)
	var result storage.Dashboard
	err := c.request(ctx, http.MethodGet, path, nil, &result)
	return result, err
}

func (c *Client) Config(ctx context.Context) (ConfigState, error) {
	var result ConfigState
	err := c.request(ctx, http.MethodGet, "/v1/config", nil, &result)
	return result, err
}

func (c *Client) SaveRules(ctx context.Context, update configservice.Update) (ConfigState, error) {
	var result ConfigState
	err := c.request(ctx, http.MethodPut, "/v1/config/rules", update, &result)
	return result, err
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func decodeBody(w http.ResponseWriter, r *http.Request, target any) error {
	if r.Header.Get("Content-Type") != "application/json" {
		return fmt.Errorf("Content-Type must be application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON body")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("one JSON object required")
	}
	return nil
}

func defaultValue(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
