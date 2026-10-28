// Command challenge-fixture runs the browser acceptance fixture.
package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/it-nsk/antiddos/internal/challenge"
	"github.com/it-nsk/antiddos/internal/softfeed"
)

func main() {
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	snapshot := softfeed.Snapshot{Protocol: 1, Epoch: "browser-e2e", Revision: 1, Mode: "soft_block", ConfigRevision: "fixture", CookieTTL: "30m", Sites: []softfeed.Site{{ID: "main", Hosts: []string{"example.test"}}}, Decisions: []softfeed.Decision{}}
	raw, _ := json.Marshal(snapshot)
	state := softfeed.NewState()
	if err := state.ApplyJSON(raw, now); err != nil {
		log.Fatal(err)
	}
	service, err := challenge.NewService(state, challenge.Options{ProviderSecret: []byte("fixture-provider-secret-at-least-32-bytes"), CookieKeys: challenge.Keyring{Current: challenge.Key{ID: "fixture", Secret: []byte("fixture-cookie-secret-at-least-32-bytes")}}})
	if err != nil {
		log.Fatal(err)
	}
	var challenges atomic.Uint32
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__antiddos/challenge" {
			if err := state.ApplyJSON(raw, time.Now()); err != nil {
				http.Error(w, "fixture feed failed", http.StatusInternalServerError)
				return
			}
		}
		if r.URL.Path == "/protected" {
			if _, err := r.Cookie(challenge.PassCookieName); err != nil {
				http.Error(w, "pass cookie missing", http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("protected fixture"))
			return
		}
		host := r.Host
		if name, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = name
		}
		if strings.HasPrefix(host, "[") {
			host = strings.Trim(host, "[]")
		}
		r.Header.Set("X-AntiDDoS-Host", strings.ToLower(host))
		r.Header.Set("X-AntiDDoS-Authority", strings.ToLower(r.Host))
		r.Header.Set("X-AntiDDoS-Scheme", "https")
		clientID := challenges.Load()
		if r.URL.Path == "/__antiddos/challenge" {
			clientID = challenges.Add(1)
		}
		r.Header.Set("X-AntiDDoS-IP", "192.0.2."+strconv.Itoa(int(clientID%240)+10))
		r.Header.Set("X-AntiDDoS-URI", "/protected?q=browser-e2e")
		service.PublicHandler().ServeHTTP(w, r)
	})
	listener, err := net.Listen("tcp", "127.0.0.1:"+os.Getenv("PORT"))
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, ReadHeaderTimeout: 2 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("READY %s", listener.Addr())
	log.Fatal(server.ServeTLS(listener, "", ""))
}
