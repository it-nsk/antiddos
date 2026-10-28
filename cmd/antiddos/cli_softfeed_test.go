package main

import (
	"io"
	"testing"
)

func TestParseRunFlagsAcceptsIsolatedSoftFeedOverrides(t *testing.T) {
	options, err := parseRunFlags([]string{"--config", "/tmp/config.json", "--soft-feed-socket", "/tmp/feed.sock", "--soft-feed-group", "fixture-group"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if options.SoftFeedSocket != "/tmp/feed.sock" || options.SoftFeedGroup != "fixture-group" {
		t.Fatalf("soft feed overrides were not retained: %+v", options)
	}
}
