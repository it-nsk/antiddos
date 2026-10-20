package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
)

// Decode validates a document without reading or writing any configuration file.
func Decode(r io.Reader) (Config, error) { return decode(r, "document", "") }

// WhitelistRevision identifies the effective global and rule-level allow lists.
func WhitelistRevision(cfg Config) string {
	lists := map[string][]string{"": cfg.Engine.IgnoreIPs}
	for _, rule := range cfg.Engine.Rules {
		lists[rule.ID] = rule.IgnoreIPs
	}
	b, _ := json.Marshal(lists)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}
