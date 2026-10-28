// Command uds-probe checks access to the checker Unix socket.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: uds-probe SOCKET")
		os.Exit(2)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", os.Args[1])
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	request, _ := http.NewRequest(http.MethodPost, "http://checker/__antiddos_check", nil)
	response, err := client.Do(request)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		fmt.Fprintf(os.Stderr, "unexpected status %d\n", response.StatusCode)
		os.Exit(1)
	}
}
