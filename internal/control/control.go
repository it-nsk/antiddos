// Package control exposes narrowly-scoped local requests to the daemon.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/it-nsk/antiddos/internal/action"
)

const DefaultSocketPath = "/run/antiddos/control.sock"

type Unblocker interface {
	Unblock(context.Context, netip.Addr) action.Result
}

type unblockRequest struct {
	IP string `json:"ip"`
}
type unblockResponse struct {
	Status string `json:"status"`
	IP     string `json:"ip"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Serve listens on a protected Unix socket until ctx is canceled.
func Serve(ctx context.Context, path string, manager Unblocker) error {
	listener, err := listen(path)
	if err != nil {
		return err
	}
	defer func() { listener.Close(); _ = os.Remove(path) }()
	server := &http.Server{Handler: handler(manager), ReadHeaderTimeout: 3 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-done; err != nil && err != http.ErrServerClosed {
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

func handler(manager Unblocker) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/unblock", func(writer http.ResponseWriter, request *http.Request) {
		request.Body = http.MaxBytesReader(writer, request.Body, 1024)
		decoder := json.NewDecoder(request.Body)
		decoder.DisallowUnknownFields()
		var input unblockRequest
		if err := decoder.Decode(&input); err != nil {
			http.Error(writer, "invalid request body", http.StatusBadRequest)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			http.Error(writer, "request must contain one JSON object", http.StatusBadRequest)
			return
		}
		ip, err := netip.ParseAddr(input.IP)
		if err != nil {
			http.Error(writer, "ip must be one IPv4 or IPv6 address", http.StatusBadRequest)
			return
		}
		ip = ip.Unmap()
		result := manager.Unblock(request.Context(), ip)
		status := http.StatusOK
		if result.Status != action.StatusRemoved && result.Status != action.StatusAlreadyAbsent && result.Status != action.StatusWouldRemove {
			status = http.StatusInternalServerError
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(status)
		response := unblockResponse{Status: string(result.Status), IP: ip.Unmap().String(), Reason: result.Reason}
		if result.Err != nil {
			response.Error = result.Err.Error()
		}
		_ = json.NewEncoder(writer).Encode(response)
	})
	return mux
}

func listen(path string) (net.Listener, error) {
	if path == "" {
		return nil, fmt.Errorf("control socket path is empty")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket control path %q", path)
		}
		conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("control socket %q is already active", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale control socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect control socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on control socket %q: %w", path, err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		listener.Close()
		os.Remove(path)
		return nil, fmt.Errorf("set control socket permissions: %w", err)
	}
	return listener, nil
}

// RequestUnblock asks the daemon to remove an exact IP from its firewall set.
func RequestUnblock(ctx context.Context, path string, ip netip.Addr) (action.Result, error) {
	if !ip.IsValid() {
		return action.Result{}, fmt.Errorf("invalid IP address")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	body, _ := json.Marshal(unblockRequest{IP: ip.Unmap().String()})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://antiddos/v1/unblock", bytes.NewReader(body))
	if err != nil {
		return action.Result{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return action.Result{}, fmt.Errorf("contact antiddos daemon: %w", err)
	}
	defer response.Body.Close()
	var decoded unblockResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 2048)).Decode(&decoded); err != nil {
		return action.Result{}, fmt.Errorf("decode daemon response: %w", err)
	}
	result := action.Result{Status: action.Status(decoded.Status), IP: ip.Unmap(), Reason: decoded.Reason}
	if response.StatusCode >= 500 {
		if decoded.Error == "" {
			decoded.Error = response.Status
		}
		result.Status, result.Err = action.StatusFailed, fmt.Errorf("%s", decoded.Error)
		return result, nil
	}
	if response.StatusCode != http.StatusOK {
		return action.Result{}, fmt.Errorf("daemon rejected unblock request: %s", decoded.Error)
	}
	if decoded.IP != ip.Unmap().String() {
		return action.Result{}, fmt.Errorf("daemon response IP %q does not match request %q", decoded.IP, ip.Unmap())
	}
	if result.Status != action.StatusRemoved && result.Status != action.StatusAlreadyAbsent && result.Status != action.StatusWouldRemove {
		return action.Result{}, fmt.Errorf("daemon returned unexpected unblock status %q", result.Status)
	}
	return result, nil
}
