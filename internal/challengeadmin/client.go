package challengeadmin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"
)

const DefaultSocketPath = "/run/antiddos-challenge-admin/admin.sock"

type Status struct {
	Health         string `json:"health"`
	Mode           string `json:"mode,omitempty"`
	ConfigRevision string `json:"config_revision,omitempty"`
	Epoch          string `json:"epoch,omitempty"`
	Revision       uint64 `json:"revision,omitempty"`
	Sites          int    `json:"sites"`
	MetricsHealth  string `json:"metrics_health,omitempty"`
	MetricsDropped uint64 `json:"metrics_dropped"`
}

type Metric struct {
	Bucket int64  `json:"bucket"`
	Site   string `json:"site"`
	Reason string `json:"reason"`
	Count  uint64 `json:"count"`
}

type Client struct {
	SocketPath string
	Timeout    time.Duration
}

func (client *Client) Status(ctx context.Context) (Status, error) {
	var status Status
	if err := client.read(ctx, "/v1/status", 16<<10, &status); err != nil {
		return Status{}, err
	}
	if status.Health != "starting" && status.Health != "ready" && status.Health != "degraded" || status.Sites < 0 || status.Sites > 32 || status.MetricsHealth != "" && status.MetricsHealth != "ready" && status.MetricsHealth != "degraded" && status.MetricsHealth != "unavailable" {
		return Status{}, fmt.Errorf("challenge status contains invalid values")
	}
	return status, nil
}

func (client *Client) Metrics(ctx context.Context, from, to time.Time, limit int) ([]Metric, error) {
	if !to.After(from) || to.Sub(from) > 7*24*time.Hour || limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("invalid metrics range or limit")
	}
	params := url.Values{"from": {from.UTC().Format(time.RFC3339)}, "to": {to.UTC().Format(time.RFC3339)}, "limit": {strconv.Itoa(limit)}}
	var rows []Metric
	if err := client.read(ctx, "/v1/metrics?"+params.Encode(), 256<<10, &rows); err != nil {
		return nil, err
	}
	if rows == nil || len(rows) > limit {
		return nil, fmt.Errorf("invalid metrics response")
	}
	for _, row := range rows {
		switch row.Reason {
		case "issued", "solved", "rejected", "immunity", "fail_open":
		default:
			return nil, fmt.Errorf("invalid metrics reason")
		}
		if len(row.Site) == 0 || len(row.Site) > 64 {
			return nil, fmt.Errorf("invalid metrics site")
		}
		for _, c := range row.Site {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return nil, fmt.Errorf("invalid metrics site")
			}
		}
	}
	return rows, nil
}

func (client *Client) read(ctx context.Context, endpoint string, maxBytes int64, result any) error {
	path := client.SocketPath
	if path == "" {
		path = DefaultSocketPath
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("challenge admin socket path must be absolute")
	}
	timeout := client.Timeout
	if timeout == 0 {
		timeout = 500 * time.Millisecond
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", path)
	}}
	httpClient := &http.Client{Transport: transport, Timeout: timeout}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://checker"+endpoint, nil)
	if err != nil {
		return err
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("read challenge admin: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("challenge admin returned %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("read challenge admin body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return fmt.Errorf("challenge admin response is too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(result); err != nil {
		return fmt.Errorf("decode challenge admin: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("challenge admin must contain one JSON value")
	}
	return nil
}
