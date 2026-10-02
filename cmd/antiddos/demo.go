package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

const (
	demoInitialBurstDelay = 4 * time.Second
	demoBurstSize         = 8
)

type demoRequest struct {
	ip, path, userAgent string
	status              int
	responseBytes       int
}

func demo(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 0 {
		return fmt.Errorf("usage: antiddos demo")
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("locate working directory: %w", err)
	}
	runDirectory := filepath.Join(workingDirectory, "runtime", "demo", time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(runDirectory, 0o700); err != nil {
		return fmt.Errorf("create demo directory: %w", err)
	}
	logPath := filepath.Join(runDirectory, "access.log")
	databasePath := filepath.Join(runDirectory, "antiddos.sqlite")
	configPath := filepath.Join(runDirectory, "config.json")
	serviceLogPath := filepath.Join(runDirectory, "service.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		return fmt.Errorf("create demo access log: %w", err)
	}
	if err := writeDemoConfig(configPath, logPath, databasePath); err != nil {
		return err
	}
	serviceLog, err := os.OpenFile(serviceLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open demo service log: %w", err)
	}
	defer serviceLog.Close()

	demoCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	componentErrors := make(chan error, 2)
	runDone := make(chan struct{})
	demoLogger := slog.New(slog.NewTextHandler(serviceLog, nil))
	go func() {
		defer close(runDone)
		err := run(demoCtx, []string{"run", "--config", configPath, "--log-file", logPath}, demoLogger)
		if demoCtx.Err() == nil {
			if err == nil {
				err = fmt.Errorf("stopped unexpectedly")
			}
			componentErrors <- fmt.Errorf("demo analyzer: %w", err)
			cancel()
		}
	}()

	if err := waitForDemoDatabase(demoCtx, databasePath, componentErrors); err != nil {
		cancel()
		<-runDone
		return err
	}

	generatorDone := make(chan struct{})
	go func() {
		defer close(generatorDone)
		err := generateDemoTraffic(demoCtx, logPath)
		if demoCtx.Err() == nil {
			if err == nil {
				err = fmt.Errorf("stopped unexpectedly")
			}
			componentErrors <- fmt.Errorf("demo traffic generator: %w", err)
			cancel()
		}
	}()

	fmt.Fprintf(out, "Demo directory: %s\nFirst burst in %s; later bursts every 10-15 seconds. Press Ctrl+C to stop.\n\n", runDirectory, demoInitialBurstDelay)
	monitorErr := monitor(demoCtx, []string{"--config", configPath}, out)
	cancel()
	<-generatorDone
	<-runDone
	select {
	case componentErr := <-componentErrors:
		return componentErr
	default:
	}
	return monitorErr
}

func writeDemoConfig(path, logPath, databasePath string) error {
	contents := map[string]any{
		"log_file":       logPath,
		"database_path":  databasePath,
		"start_position": "end",
		"engine": map[string]any{
			"live_event_lateness": "30s",
			"rules": []any{map[string]any{
				"id":                   "homepage",
				"window":               "5s",
				"threshold":            5,
				"suspicious_threshold": 0,
				"groupings": []any{
					map[string]any{"id": "by_ip", "fields": []string{"ip"}},
					map[string]any{"id": "by_user_agent", "fields": []string{"user_agent"}},
					map[string]any{"id": "by_ip_user_agent", "fields": []string{"ip", "user_agent"}},
				},
			}},
		},
	}
	data, err := json.MarshalIndent(contents, "", "  ")
	if err != nil {
		return fmt.Errorf("encode demo config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write demo config: %w", err)
	}
	return nil
}

func waitForDemoDatabase(ctx context.Context, path string, componentErrors <-chan error) error {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-componentErrors:
			return err
		case <-timeout.C:
			return fmt.Errorf("demo analyzer did not create SQLite within 5 seconds")
		case <-ticker.C:
			if _, err := os.Stat(path); err == nil {
				// The database is created before the follower starts its read loop.
				// This short wait prevents the first generated line from racing startup.
				timer := time.NewTimer(100 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
					return nil
				}
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
}

func generateDemoTraffic(ctx context.Context, path string) error {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	nextBurst := time.Now().Add(demoInitialBurstDelay)
	burstNumber := 0
	for {
		if !time.Now().Before(nextBurst) {
			if err := writeDemoBurst(ctx, file, random, burstNumber); err != nil {
				return err
			}
			burstNumber++
			nextBurst = time.Now().Add(time.Duration(10+random.Intn(6)) * time.Second)
			continue
		}

		request := randomDemoRequest(random)
		if err := writeDemoLine(file, time.Now(), request); err != nil {
			return err
		}
		wait := time.Duration(300+random.Intn(601)) * time.Millisecond
		if remaining := time.Until(nextBurst); wait > remaining {
			wait = remaining
		}
		if err := waitDemo(ctx, wait); err != nil {
			return err
		}
	}
}

func randomDemoRequest(random *rand.Rand) demoRequest {
	ips := []string{"192.0.2.10", "192.0.2.11", "192.0.2.12", "198.51.100.10", "198.51.100.11", "198.51.100.12", "203.0.113.10", "203.0.113.11", "203.0.113.12"}
	paths := []string{"/", "/path1", "/path1", "/path2", "/path2", "/assets/demo.css"}
	userAgents := []string{"UserAgent1", "UserAgent2", "UserAgent3", "UserAgent4", "UserAgent5"}
	path := paths[random.Intn(len(paths))]
	status := 200
	if path == "/path2" && random.Intn(4) == 0 {
		status = 404
	}
	return demoRequest{
		ip:            ips[random.Intn(len(ips))],
		path:          path,
		userAgent:     userAgents[random.Intn(len(userAgents))],
		status:        status,
		responseBytes: 300 + random.Intn(24_701),
	}
}

func writeDemoBurst(ctx context.Context, file *os.File, random *rand.Rand, burstNumber int) error {
	for index := 0; index < demoBurstSize; index++ {
		request := demoRequest{path: "/", status: 200, responseBytes: 700 + random.Intn(1801)}
		switch burstNumber % 3 {
		case 0:
			request.ip = "203.0.113.200"
			request.userAgent = "UserAgentBurst1"
		case 1:
			request.ip = "198.51.100.200"
			request.userAgent = fmt.Sprintf("UserAgentBurst%d", 2+index%2)
		case 2:
			request.ip = fmt.Sprintf("192.0.2.%d", 200+index%2)
			request.userAgent = "UserAgentBurst4"
		}
		if err := writeDemoLine(file, time.Now(), request); err != nil {
			return err
		}
		if err := waitDemo(ctx, time.Duration(70+random.Intn(61))*time.Millisecond); err != nil {
			return err
		}
	}
	return nil
}

func writeDemoLine(file *os.File, timestamp time.Time, request demoRequest) error {
	_, err := fmt.Fprintf(file, "%s - - [%s] \"GET %s HTTP/1.1\" %d %d \"-\" \"%s\"\n",
		request.ip,
		timestamp.Format("02/Jan/2006:15:04:05 -0700"),
		request.path,
		request.status,
		request.responseBytes,
		request.userAgent,
	)
	return err
}

func waitDemo(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
