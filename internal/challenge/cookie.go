package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	PassCookieName    = "__Host-antiddos_pass"
	SessionCookieName = "__Host-antiddos_challenge"
	MaxCookieBytes    = 4096
)

type Key struct {
	ID          string
	Secret      []byte
	AcceptUntil time.Time
}
type Keyring struct {
	Current  Key
	Previous []Key
}
type passClaims struct {
	Version   int    `json:"version"`
	KeyID     string `json:"key_id"`
	SiteID    string `json:"site_id"`
	Host      string `json:"host"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	RandomID  string `json:"random_id"`
}

func validateKeyring(ring Keyring) error {
	if !validIdentifier(ring.Current.ID) || len(ring.Current.Secret) < 32 {
		return fmt.Errorf("current cookie key requires a valid ID and at least 32 secret bytes")
	}
	seen := map[string]bool{ring.Current.ID: true}
	for _, key := range ring.Previous {
		if !validIdentifier(key.ID) || len(key.Secret) < 32 || key.AcceptUntil.IsZero() || seen[key.ID] {
			return fmt.Errorf("invalid previous cookie key")
		}
		seen[key.ID] = true
	}
	return nil
}

func IssuePassCookie(ring Keyring, site, host string, ttl time.Duration, now time.Time) (string, error) {
	if err := validateKeyring(ring); err != nil {
		return "", err
	}
	if !validIdentifier(site) || !validHost(host) || ttl < time.Minute || ttl > 24*time.Hour {
		return "", fmt.Errorf("invalid pass cookie claims")
	}
	var randomID [16]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return "", fmt.Errorf("create pass cookie nonce: %w", err)
	}
	claims := passClaims{Version: 1, KeyID: ring.Current.ID, SiteID: site, Host: host, IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), RandomID: hex.EncodeToString(randomID[:])}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	message := "v1." + encoded
	mac := hmac.New(sha256.New, ring.Current.Secret)
	_, _ = mac.Write([]byte(message))
	token := message + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if len(token) > MaxCookieBytes {
		return "", fmt.Errorf("pass cookie exceeds %d bytes", MaxCookieBytes)
	}
	return token, nil
}

func VerifyPassCookie(ring Keyring, token, site, host string, currentTTL time.Duration, now time.Time) error {
	if len(token) == 0 || len(token) > MaxCookieBytes {
		return fmt.Errorf("invalid pass cookie size")
	}
	if err := validateKeyring(ring); err != nil {
		return err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return fmt.Errorf("invalid pass cookie format")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) > 2048 {
		return fmt.Errorf("invalid pass cookie payload")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var claims passClaims
	if err := decoder.Decode(&claims); err != nil {
		return fmt.Errorf("invalid pass cookie claims: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("invalid pass cookie claims")
	}
	var key *Key
	if ring.Current.ID == claims.KeyID {
		key = &ring.Current
	} else {
		for i := range ring.Previous {
			candidate := &ring.Previous[i]
			if candidate.ID == claims.KeyID && now.Before(candidate.AcceptUntil) {
				key = candidate
				break
			}
		}
	}
	if key == nil {
		return fmt.Errorf("unknown or retired pass cookie key")
	}
	provided, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(provided) != sha256.Size {
		return fmt.Errorf("invalid pass cookie signature")
	}
	mac := hmac.New(sha256.New, key.Secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(provided, expected) != 1 {
		return fmt.Errorf("invalid pass cookie signature")
	}
	if claims.Version != 1 || !validIdentifier(claims.SiteID) || !validHost(claims.Host) || claims.SiteID != site || claims.Host != host || len(claims.RandomID) != 32 {
		return fmt.Errorf("pass cookie audience mismatch")
	}
	issued := time.Unix(claims.IssuedAt, 0)
	expires := time.Unix(claims.ExpiresAt, 0)
	if issued.After(now.Add(30*time.Second)) || !expires.After(now) || !expires.After(issued) || expires.Sub(issued) > 24*time.Hour {
		return fmt.Errorf("pass cookie is expired or has invalid time claims")
	}
	if currentTTL < time.Minute || currentTTL > 24*time.Hour || now.Sub(issued) > currentTTL {
		return fmt.Errorf("pass cookie exceeds current cookie TTL")
	}
	return nil
}

func NewBrowserSession() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("create browser session: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}
func validSession(value string) bool {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(decoded) == 32
}

func ValidateReturnURL(value string) (string, error) {
	if value == "" || len(value) > 4096 || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\\\r\n\x00") {
		return "", fmt.Errorf("return URL must be a local path")
	}
	current := value
	for i := 0; i < 5; i++ {
		parsed, err := url.ParseRequestURI(current)
		if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" || !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
			return "", fmt.Errorf("invalid local return URL")
		}
		if strings.ContainsAny(current, "\\\r\n\x00") || strings.HasPrefix(parsed.Path, "//") {
			return "", fmt.Errorf("invalid local return URL")
		}
		decoded, err := url.PathUnescape(current)
		if err != nil {
			return "", fmt.Errorf("invalid return URL encoding")
		}
		if decoded == current {
			return current, nil
		}
		current = decoded
	}
	return "", fmt.Errorf("return URL has excessive encoding")
}

func trustedOrigin(scheme, host string) (string, error) {
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("invalid trusted scheme")
	}
	if host == "" || len(host) > 260 || strings.ContainsAny(host, "/\\\r\n\x00") {
		return "", fmt.Errorf("invalid trusted host")
	}
	_, ok := parseAuthority(host)
	if !ok {
		return "", fmt.Errorf("invalid trusted host")
	}
	return scheme + "://" + strings.ToLower(host), nil
}

func parseAuthority(authority string) (string, bool) {
	if authority == "" || len(authority) > 260 || strings.ContainsAny(authority, "/\\\r\n\x00@") {
		return "", false
	}
	name, port := authority, ""
	if strings.Contains(authority, ":") {
		var err error
		name, port, err = net.SplitHostPort(authority)
		if err != nil {
			return "", false
		}
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", false
		}
	}
	name = strings.ToLower(name)
	if !validHost(name) {
		return "", false
	}
	return name, true
}

func verifyOrigin(scheme, trustedAuthority, origin string) bool {
	if scheme != "https" && scheme != "http" {
		return false
	}
	if _, ok := parseAuthority(trustedAuthority); !ok {
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.Scheme != scheme || parsed.Host == "" {
		return false
	}
	if _, ok := parseAuthority(parsed.Host); !ok {
		return false
	}
	return strings.EqualFold(parsed.Host, trustedAuthority)
}

func validIdentifier(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}
func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ToLower(host) != host || strings.HasSuffix(host, ".") || strings.ContainsAny(host, ":/%") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
