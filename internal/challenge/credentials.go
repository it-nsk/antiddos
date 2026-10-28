package challenge

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const MaxCredentialBytes = 16 << 10

type credentialFile struct {
	ProviderSecret string          `json:"provider_secret"`
	Current        credentialKey   `json:"current"`
	Previous       []credentialKey `json:"previous"`
}
type credentialKey struct {
	ID          string `json:"id"`
	Secret      string `json:"secret"`
	AcceptUntil string `json:"accept_until,omitempty"`
}

// LoadCredentials decodes secret material from a systemd LoadCredential file.
// Secrets are never included in returned errors.
func LoadCredentials(path string) ([]byte, Keyring, error) {
	if path == "" {
		return nil, Keyring{}, fmt.Errorf("credential file path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, Keyring{}, fmt.Errorf("stat credential file: %w", err)
	}
	mode := info.Mode().Perm()
	private := mode&0077 == 0
	// systemd exposes LoadCredential files as root:root 0440 on some
	// distributions while granting the unit access through its credential
	// mount. Accept that exact mode only inside systemd's credential directory.
	systemdCredential := mode == 0440 && os.Getenv("CREDENTIALS_DIRECTORY") != "" &&
		filepath.Clean(filepath.Dir(path)) == filepath.Clean(os.Getenv("CREDENTIALS_DIRECTORY"))
	if !info.Mode().IsRegular() || info.Size() > MaxCredentialBytes || (!private && !systemdCredential) {
		return nil, Keyring{}, fmt.Errorf("credential file must be private, regular, and at most %d bytes", MaxCredentialBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, Keyring{}, fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, MaxCredentialBytes+1))
	decoder.DisallowUnknownFields()
	var raw credentialFile
	if err := decoder.Decode(&raw); err != nil {
		return nil, Keyring{}, fmt.Errorf("decode credential file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, Keyring{}, fmt.Errorf("credential file must contain one JSON object")
	}
	provider, err := decodeSecret(raw.ProviderSecret)
	if err != nil || len(provider) < 32 {
		return nil, Keyring{}, fmt.Errorf("provider secret must contain at least 32 bytes")
	}
	ring := Keyring{Current: Key{ID: raw.Current.ID}}
	ring.Current.Secret, err = decodeSecret(raw.Current.Secret)
	if err != nil {
		return nil, Keyring{}, fmt.Errorf("invalid current cookie key")
	}
	for _, item := range raw.Previous {
		key := Key{ID: item.ID}
		key.Secret, err = decodeSecret(item.Secret)
		if err != nil {
			return nil, Keyring{}, fmt.Errorf("invalid previous cookie key")
		}
		key.AcceptUntil, err = time.Parse(time.RFC3339, item.AcceptUntil)
		if err != nil {
			return nil, Keyring{}, fmt.Errorf("invalid previous cookie key expiry")
		}
		ring.Previous = append(ring.Previous, key)
	}
	if err := validateKeyring(ring); err != nil {
		return nil, Keyring{}, err
	}
	return provider, ring, nil
}

func decodeSecret(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("empty secret")
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict()} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("secret is not valid base64")
}

// RotateCredentials atomically replaces the current cookie signing key while
// preserving the provider secret. Normal rotation accepts the former key for
// one hour; revokeExisting immediately retires every former cookie key.
func RotateCredentials(path string, revokeExisting bool, now time.Time) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect credential file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("credential file must be a regular non-symlink file")
	}
	provider, ring, err := LoadCredentials(path)
	if err != nil {
		return err
	}
	var secret [32]byte
	var idBytes [8]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return fmt.Errorf("generate cookie key: %w", err)
	}
	if _, err := rand.Read(idBytes[:]); err != nil {
		return fmt.Errorf("generate cookie key ID: %w", err)
	}
	raw := credentialFile{
		ProviderSecret: base64.StdEncoding.EncodeToString(provider),
		Current: credentialKey{
			ID:     "k" + hex.EncodeToString(idBytes[:]),
			Secret: base64.StdEncoding.EncodeToString(secret[:]),
		},
		Previous: []credentialKey{},
	}
	if !revokeExisting {
		raw.Previous = append(raw.Previous, credentialKey{
			ID:          ring.Current.ID,
			Secret:      base64.StdEncoding.EncodeToString(ring.Current.Secret),
			AcceptUntil: now.Add(time.Hour).UTC().Format(time.RFC3339),
		})
		for _, key := range ring.Previous {
			if key.AcceptUntil.After(now) {
				raw.Previous = append(raw.Previous, credentialKey{
					ID: key.ID, Secret: base64.StdEncoding.EncodeToString(key.Secret),
					AcceptUntil: key.AcceptUntil.UTC().Format(time.RFC3339),
				})
			}
		}
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("encode rotated credentials: %w", err)
	}
	encoded = append(encoded, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".keys.rotate-*")
	if err != nil {
		return fmt.Errorf("create rotated credential file: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect rotated credential file: %w", err)
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write rotated credential file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync rotated credential file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close rotated credential file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace credential file: %w", err)
	}
	removeTemporary = false
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open credential directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync credential directory: %w", err)
	}
	return nil
}
