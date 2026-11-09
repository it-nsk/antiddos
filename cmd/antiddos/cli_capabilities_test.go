package main

import (
	"reflect"
	"testing"
)

func TestSetprivDropArgsUsesLegacyBoundingSetWithoutAmbientCapabilities(t *testing.T) {
	t.Setenv("ANTIDDOS_LEGACY_SYSTEMD", "1")
	got := setprivDropArgs("setpriv", []string{"net_admin", "net_raw"})
	want := []string{"setpriv", "--no-new-privs", "--inh-caps=-net_admin,-net_raw", "--bounding-set=-net_admin,-net_raw"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("setpriv args = %#v, want %#v", got, want)
	}
}

func TestSetprivDropArgsUsesAmbientSetOnModernSystemd(t *testing.T) {
	t.Setenv("ANTIDDOS_LEGACY_SYSTEMD", "")
	got := setprivDropArgs("setpriv", []string{"net_raw"})
	want := []string{"setpriv", "--no-new-privs", "--inh-caps=-net_raw", "--ambient-caps=-net_raw"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("setpriv args = %#v, want %#v", got, want)
	}
}
