package challenge

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"github.com/it-nsk/antiddos/internal/softfeed"
)

const (
	TaskTTL           = 2 * time.Minute
	MaxTasks          = 10000
	MaxTasksPerSiteIP = 3
	MaxLimiterKeys    = 20000
	LimiterIdleTTL    = 5 * time.Minute
	MaxFormBytes      = 16 << 10
	ChallengeCost     = 1000
	MaxChallengeWork  = 4
)

type Options struct {
	ProviderSecret []byte
	CookieKeys     Keyring
	MaxTasks       int
	MaxInFlight    int
	Clock          func() time.Time
}
type Task struct {
	ID        string
	CSRF      string
	SiteID    string
	Host      string
	ReturnURL string
	ExpiresAt time.Time
	Challenge altcha.Challenge
	reused    bool
}
type taskSessionKey struct{ site, ip, session, host, returnURL, revision string }
type VerifyRequest struct {
	TaskID    string
	SessionID string
	SiteID    string
	Host      string
	Authority string
	Scheme    string
	Origin    string
	CSRF      string
	Payload   string
}
type VerifyResult struct {
	PassCookie string
	ReturnURL  string
	SiteID     string
	Host       string
}
type storedTask struct {
	Task
	sessionID      string
	clientIP       netip.Addr
	configRevision string
	inFlight       bool
	sessionKey     taskSessionKey
}
type rateEntry struct {
	window   time.Time
	creates  int
	verifies int
	lastSeen time.Time
}

type Service struct {
	metrics        *metrics
	mu             sync.Mutex
	state          *softfeed.State
	providerSecret []byte
	cookieKeys     Keyring
	maxTasks       int
	tasks          map[string]*storedTask
	taskCounts     map[string]int
	sessionTasks   map[taskSessionKey]string
	limiters       map[string]*rateEntry
	overflow       rateEntry
	verifySlots    chan struct{}
	clock          func() time.Time
}

func NewService(state *softfeed.State, options Options) (*Service, error) {
	if state == nil {
		return nil, fmt.Errorf("challenge service requires feed state")
	}
	if len(options.ProviderSecret) < 32 {
		return nil, fmt.Errorf("provider secret must contain at least 32 bytes")
	}
	if err := validateKeyring(options.CookieKeys); err != nil {
		return nil, err
	}
	maxTasks := options.MaxTasks
	if maxTasks == 0 {
		maxTasks = MaxTasks
	}
	if maxTasks < 1 || maxTasks > MaxTasks {
		return nil, fmt.Errorf("task capacity must be between 1 and %d", MaxTasks)
	}
	maxWork := min(2*runtime.GOMAXPROCS(0), 8, MaxChallengeWork)
	if options.MaxInFlight > 0 {
		if options.MaxInFlight > maxWork {
			return nil, fmt.Errorf("in-flight limit cannot exceed %d", maxWork)
		}
		maxWork = options.MaxInFlight
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return &Service{state: state, providerSecret: append([]byte(nil), options.ProviderSecret...), cookieKeys: cloneKeyring(options.CookieKeys), maxTasks: maxTasks, tasks: map[string]*storedTask{}, taskCounts: map[string]int{}, sessionTasks: map[taskSessionKey]string{}, limiters: map[string]*rateEntry{}, verifySlots: make(chan struct{}, maxWork), clock: clock}, nil
}

func cloneKeyring(source Keyring) Keyring {
	result := Keyring{Current: source.Current, Previous: make([]Key, len(source.Previous))}
	result.Current.Secret = append([]byte(nil), source.Current.Secret...)
	for i, key := range source.Previous {
		result.Previous[i] = key
		result.Previous[i].Secret = append([]byte(nil), key.Secret...)
	}
	return result
}

func (service *Service) NewSession() (string, error) { return NewBrowserSession() }

func (service *Service) CreateTask(host string, ip netip.Addr, sessionID, returnURL string, now time.Time) (Task, error) {
	if !validHost(host) || !ip.IsValid() || ip.Zone() != "" || !validSession(sessionID) {
		return Task{}, fmt.Errorf("invalid challenge request metadata")
	}
	returnURL, err := ValidateReturnURL(returnURL)
	if err != nil {
		return Task{}, err
	}
	if service.state.Health(now) != "ready" {
		return Task{}, fmt.Errorf("challenge service feed is not ready")
	}
	snapshot, ok := service.state.Current()
	if !ok || !softfeed.SnapshotUsesSoftBlock(*snapshot) {
		return Task{}, fmt.Errorf("soft-block mode is not ready")
	}
	siteID := ""
	for _, site := range snapshot.Sites {
		for _, candidate := range site.Hosts {
			if candidate == host {
				siteID = site.ID
				break
			}
		}
		if siteID != "" {
			break
		}
	}
	if siteID == "" {
		return Task{}, fmt.Errorf("host is not configured for soft-block")
	}
	ttl, err := time.ParseDuration(snapshot.CookieTTL)
	if err != nil || ttl < time.Minute || ttl > 24*time.Hour {
		return Task{}, fmt.Errorf("feed cookie TTL is invalid")
	}
	ip = ip.Unmap()
	limiterKey := siteID + "\x00" + ip.String()
	sessionTaskKey := limiterKey
	service.mu.Lock()
	defer service.mu.Unlock()
	service.pruneLocked(now)
	entry := service.limiterLocked(limiterKey, now)
	if !allowRate(entry, now, true) {
		return Task{}, fmt.Errorf("challenge creation rate limit exceeded")
	}
	sessionKey := taskSessionKey{siteID, ip.String(), sessionID, host, returnURL, snapshot.ConfigRevision}
	if id, ok := service.sessionTasks[sessionKey]; ok {
		if existing, found := service.tasks[id]; found {
			result := existing.Task
			result.reused = true
			return result, nil
		}
	}
	if len(service.tasks) >= service.maxTasks {
		return Task{}, fmt.Errorf("challenge task capacity reached")
	}
	if service.taskCounts[sessionTaskKey] >= MaxTasksPerSiteIP {
		return Task{}, fmt.Errorf("too many active challenge tasks for site and IP")
	}
	id, err := randomToken(32)
	if err != nil {
		return Task{}, err
	}
	csrf, err := randomToken(32)
	if err != nil {
		return Task{}, err
	}
	expires := time.Unix(now.Add(TaskTTL).Unix(), 0).UTC()
	challenge, err := altcha.CreateChallenge(altcha.CreateChallengeOptions{Algorithm: "PBKDF2/SHA-256", Cost: ChallengeCost, DeriveKey: altcha.DeriveKeyPBKDF2(), HMACSignatureSecret: string(service.providerSecret), KeyLength: 32, KeyPrefixLength: 1, ExpiresAt: &expires, Data: map[string]interface{}{"task_id": id, "site_id": siteID, "host": host}})
	if err != nil {
		return Task{}, fmt.Errorf("create ALTCHA challenge: %w", err)
	}
	task := Task{ID: id, CSRF: csrf, SiteID: siteID, Host: host, ReturnURL: returnURL, ExpiresAt: expires, Challenge: challenge}
	service.tasks[id] = &storedTask{Task: task, sessionID: sessionID, clientIP: ip, configRevision: snapshot.ConfigRevision, sessionKey: sessionKey}
	service.sessionTasks[sessionKey] = id
	service.taskCounts[sessionTaskKey]++
	return task, nil
}

func (service *Service) Verify(ctx context.Context, request VerifyRequest, now time.Time) (VerifyResult, error) {
	if err := ctx.Err(); err != nil {
		return VerifyResult{}, err
	}
	if len(request.Payload) > MaxFormBytes {
		return VerifyResult{}, fmt.Errorf("verification payload exceeds %d bytes", MaxFormBytes)
	}
	if !validIdentifier(request.TaskID) || !validSession(request.SessionID) || !validHost(request.Host) || !validIdentifier(request.SiteID) || len(request.Origin) > 512 {
		return VerifyResult{}, fmt.Errorf("invalid verification metadata")
	}
	if !verifyOrigin(request.Scheme, request.Authority, request.Origin) {
		return VerifyResult{}, fmt.Errorf("verification Origin mismatch")
	}
	service.mu.Lock()
	task, ok := service.tasks[request.TaskID]
	if !ok {
		service.mu.Unlock()
		return VerifyResult{}, fmt.Errorf("challenge task expired or was consumed")
	}
	if task.inFlight || !task.ExpiresAt.After(now) || task.sessionID != request.SessionID || task.SiteID != request.SiteID || task.Host != request.Host || subtle.ConstantTimeCompare([]byte(task.CSRF), []byte(request.CSRF)) != 1 {
		service.mu.Unlock()
		return VerifyResult{}, fmt.Errorf("challenge task binding failed")
	}
	snapshot, hasSnapshot := service.state.Current()
	if !hasSnapshot || !softfeed.SnapshotUsesSoftBlock(*snapshot) || snapshot.ConfigRevision != task.configRevision || snapshot.CookieTTL == "" {
		service.mu.Unlock()
		return VerifyResult{}, fmt.Errorf("challenge configuration changed")
	}
	entry := service.limiterLocked(task.SiteID+"\x00"+task.clientIP.String(), now)
	if !allowRate(entry, now, false) {
		service.mu.Unlock()
		return VerifyResult{}, fmt.Errorf("verification rate limit exceeded")
	}
	select {
	case service.verifySlots <- struct{}{}:
	default:
		service.mu.Unlock()
		return VerifyResult{}, fmt.Errorf("verification capacity is busy")
	}
	task.inFlight = true
	service.mu.Unlock()
	defer func() { <-service.verifySlots }()
	started := time.Now()
	verified, err := service.verifyPayload(task.Task, request.Payload, now)
	if err != nil {
		service.clearInFlight(task.ID)
		return VerifyResult{}, err
	}
	if !verified {
		service.clearInFlight(task.ID)
		return VerifyResult{}, fmt.Errorf("ALTCHA proof was rejected")
	}
	currentSnapshot, ok := service.state.Current()
	if !ok || !softfeed.SnapshotUsesSoftBlock(*currentSnapshot) || currentSnapshot.ConfigRevision != task.configRevision {
		service.clearInFlight(task.ID)
		return VerifyResult{}, fmt.Errorf("challenge configuration changed")
	}
	ttl, err := time.ParseDuration(currentSnapshot.CookieTTL)
	if err != nil || ttl < time.Minute || ttl > 24*time.Hour {
		service.clearInFlight(task.ID)
		return VerifyResult{}, fmt.Errorf("invalid current cookie TTL")
	}
	completedAt := now.Add(time.Since(started))
	passCookie, err := IssuePassCookie(service.cookieKeys, task.SiteID, task.Host, ttl, completedAt)
	if err != nil {
		service.clearInFlight(task.ID)
		return VerifyResult{}, err
	}
	service.mu.Lock()
	current, exists := service.tasks[task.ID]
	if !exists || current != task || !task.inFlight || !task.ExpiresAt.After(completedAt) {
		service.mu.Unlock()
		return VerifyResult{}, fmt.Errorf("challenge task expired during verification")
	}
	delete(service.tasks, task.ID)
	delete(service.sessionTasks, task.sessionKey)
	service.taskCounts[task.SiteID+"\x00"+task.clientIP.String()]--
	task.inFlight = false
	service.mu.Unlock()
	return VerifyResult{PassCookie: passCookie, ReturnURL: task.ReturnURL, SiteID: task.SiteID, Host: task.Host}, nil
}

func (service *Service) verifyPayload(task Task, encoded string, now time.Time) (bool, error) {
	if encoded == "" || len(encoded) > MaxFormBytes {
		return false, fmt.Errorf("invalid ALTCHA payload size")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		raw, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(raw) > MaxFormBytes {
		return false, fmt.Errorf("invalid ALTCHA payload encoding")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var payload altcha.Payload
	if err := decoder.Decode(&payload); err != nil {
		return false, fmt.Errorf("invalid ALTCHA payload: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, fmt.Errorf("ALTCHA payload must contain one object")
	}
	if !sameChallenge(task.Challenge, payload.Challenge) {
		return false, fmt.Errorf("submitted ALTCHA challenge differs from the stored task")
	}
	if payload.Challenge.Parameters.Algorithm != "PBKDF2/SHA-256" || payload.Challenge.Parameters.Cost != ChallengeCost || payload.Challenge.Parameters.KeyLength != 32 || payload.Solution.Counter < 0 || uint64(payload.Solution.Counter) > math.MaxUint32 {
		return false, fmt.Errorf("ALTCHA work parameters are invalid")
	}
	key, err := hex.DecodeString(payload.Solution.DerivedKey)
	if err != nil || len(key) != 32 {
		return false, fmt.Errorf("ALTCHA solution key is invalid")
	}
	if !task.ExpiresAt.After(now) {
		return false, fmt.Errorf("challenge task expired")
	}
	result, err := altcha.VerifySolution(altcha.VerifySolutionOptions{Challenge: task.Challenge, Solution: payload.Solution, DeriveKey: altcha.DeriveKeyPBKDF2(), HMACSignatureSecret: string(service.providerSecret)})
	if err != nil {
		return false, fmt.Errorf("verify ALTCHA proof: %w", err)
	}
	return result.Verified, nil
}

func sameChallenge(expected, submitted altcha.Challenge) bool {
	a, b := expected.Parameters, submitted.Parameters
	if expected.Signature != submitted.Signature || a.Algorithm != b.Algorithm || a.Nonce != b.Nonce || a.Salt != b.Salt || a.Cost != b.Cost || a.KeyLength != b.KeyLength || a.KeyPrefix != b.KeyPrefix || a.KeySignature != b.KeySignature || a.MemoryCost != b.MemoryCost || a.Parallelism != b.Parallelism || a.ExpiresAt != b.ExpiresAt {
		return false
	}
	left, _ := json.Marshal(a.Data)
	right, _ := json.Marshal(b.Data)
	return string(left) == string(right)
}

func (service *Service) clearInFlight(id string) {
	service.mu.Lock()
	if task, ok := service.tasks[id]; ok {
		task.inFlight = false
	}
	service.mu.Unlock()
}
func (service *Service) limiterLocked(key string, now time.Time) *rateEntry {
	if entry, ok := service.limiters[key]; ok {
		entry.lastSeen = now
		return entry
	}
	if len(service.limiters) >= MaxLimiterKeys {
		return &service.overflow
	}
	entry := &rateEntry{window: now, lastSeen: now}
	service.limiters[key] = entry
	return entry
}
func allowRate(entry *rateEntry, now time.Time, create bool) bool {
	if now.Sub(entry.window) >= time.Minute || now.Before(entry.window) {
		entry.window = now
		entry.creates = 0
		entry.verifies = 0
	}
	entry.lastSeen = now
	if create {
		if entry.creates >= 5 {
			return false
		}
		entry.creates++
		return true
	}
	if entry.verifies >= 10 {
		return false
	}
	entry.verifies++
	return true
}
func (service *Service) pruneLocked(now time.Time) {
	for id, task := range service.tasks {
		if !task.ExpiresAt.After(now) && !task.inFlight {
			delete(service.tasks, id)
			delete(service.sessionTasks, task.sessionKey)
			key := task.SiteID + "\x00" + task.clientIP.String()
			if service.taskCounts[key] > 1 {
				service.taskCounts[key]--
			} else {
				delete(service.taskCounts, key)
			}
		}
	}
	if len(service.limiters) >= MaxLimiterKeys/2 {
		for key, entry := range service.limiters {
			if now.Sub(entry.lastSeen) > LimiterIdleTTL {
				delete(service.limiters, key)
			}
		}
	}
}
func (service *Service) Cleanup(now time.Time) {
	service.mu.Lock()
	defer service.mu.Unlock()
	service.pruneLocked(now)
}
func (service *Service) RunMaintenance(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			service.Cleanup(now)
		}
	}
}
func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("create random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
