package parser

import (
	"strings"
	"testing"
	"time"
)

func TestNginxErrorParser(t *testing.T) {
	p, err := New(FormatNginxError, "")
	if err != nil {
		t.Fatal(err)
	}
	event, err := p.Parse("2026/10/26 13:20:01 [error] 123#1: *7 user \"admin\": password mismatch, client: 203.0.113.7, server: bgt.my, request: \"GET /admin HTTP/1.1\"")
	if err != nil {
		t.Fatal(err)
	}
	if event.IP.String() != "203.0.113.7" || event.Status != 500 || event.Path != "/auth/basic/failure" {
		t.Fatalf("event=%+v", event)
	}
}

func TestSyslogSSHDParser(t *testing.T) {
	p, err := New(FormatSyslogSSHD, "")
	if err != nil {
		t.Fatal(err)
	}
	event, err := p.Parse("Oct 26 13:20:01 host sshd[123]: Failed password for invalid user root from 198.51.100.8 port 42122 ssh2")
	if err != nil {
		t.Fatal(err)
	}
	if event.IP.String() != "198.51.100.8" || event.Path != "/ssh/invalid-user" || event.Method != "SSH" {
		t.Fatalf("event=%+v", event)
	}
}

func TestSyslogSSHDParserAcceptsISOTime(t *testing.T) {
	p, _ := New(FormatSyslogSSHD, "")
	event, err := p.Parse("2026-10-25T00:08:42.695344+00:00 bgt-web sshd[96647]: Failed password for root from 45.198.224.51 port 12284 ssh2")
	if err != nil {
		t.Fatal(err)
	}
	if event.IP.String() != "45.198.224.51" || event.Path != "/ssh/failed" {
		t.Fatalf("event=%+v", event)
	}
}

func TestSyslogSSHDParserDoesNotMisclassifySuccessfulLogin(t *testing.T) {
	p, err := New(FormatSyslogSSHD, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Parse("2026-10-25T00:08:42.695344+00:00 example-host sshd[96647]: Accepted publickey for deploy from 45.198.224.51 port 12284 ssh2")
	if err == nil || !IsIgnored(err) {
		t.Fatalf("successful SSH login error = %v, want ignored record", err)
	}
}

func TestSyslogSSHDParserTreatsBrokenFailureAsMalformed(t *testing.T) {
	p, _ := New(FormatSyslogSSHD, "")
	_, err := p.Parse("Oct 26 13:20:01 host sshd[123]: Failed password without a remote address")
	if err == nil || IsIgnored(err) {
		t.Fatalf("broken SSH failure error = %v, want malformed record", err)
	}
}

func TestSyslogSSHDParserAcceptsPAMRhostAndIgnoresDuplicateInvalidUser(t *testing.T) {
	p, _ := New(FormatSyslogSSHD, "")
	event, err := p.Parse("Oct 26 13:20:01 host sshd[123]: pam_unix(sshd:auth): authentication failure; rhost=198.51.100.8")
	if err != nil {
		t.Fatal(err)
	}
	if event.IP.String() != "198.51.100.8" || event.Path != "/ssh/failed" {
		t.Fatalf("event = %+v", event)
	}
	if _, err := p.Parse("Oct 26 13:20:02 host sshd[123]: input_userauth_request: invalid user root [preauth]"); err == nil || !IsIgnored(err) {
		t.Fatalf("duplicate invalid-user error = %v, want ignored record", err)
	}
}

func TestNetfilterLogParser(t *testing.T) {
	p, err := New(FormatNetfilterLog, "")
	if err != nil {
		t.Fatal(err)
	}
	event, err := p.Parse("Oct 26 13:20:01 host kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.9 DST=192.0.2.10 PROTO=TCP SPT=42122 DPT=22")
	if err != nil {
		t.Fatal(err)
	}
	if event.IP.String() != "198.51.100.9" || event.Path != "/port/tcp/22" || event.Method != "NETFILTER" {
		t.Fatalf("event=%+v", event)
	}
}

func TestNetfilterScanPrefixIPv4IPv6TCPUDP(t *testing.T) {
	p, err := New(FormatNetfilterLog, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ source, proto, port string }{{"198.51.100.9", "TCP", "22"}, {"198.51.100.9", "UDP", "53"}, {"2001:db8::9", "TCP", "443"}, {"2001:db8::9", "UDP", "5353"}} {
		line := "Nov 17 12:00:00 host kernel: ANTIDDOS_SCAN IN=eth0 OUT= SRC=" + test.source + " DST=2001:db8::1 PROTO=" + test.proto + " SPT=42122 DPT=" + test.port
		event, err := p.Parse(line)
		if err != nil {
			t.Fatal(err)
		}
		if event.IP.String() != test.source || event.Path != "/port/"+strings.ToLower(test.proto)+"/"+test.port {
			t.Fatalf("scan event: %+v", event)
		}
	}
}

func TestNetfilterLogParserSeparatesIgnoredAndMalformedRecords(t *testing.T) {
	p, _ := New(FormatNetfilterLog, "")
	if _, err := p.Parse("Oct 26 13:20:01 host kernel: device initialized"); err == nil || !IsIgnored(err) {
		t.Fatalf("unrelated kernel error = %v, want ignored record", err)
	}
	if _, err := p.Parse("Oct 26 13:20:01 host kernel: SRC=198.51.100.9 PROTO=TCP"); err == nil || IsIgnored(err) {
		t.Fatalf("partial netfilter error = %v, want malformed record", err)
	}
}

func TestHistoricalSecurityParserUsesExplicitTimeContext(t *testing.T) {
	location := time.FixedZone("archive", 7*60*60)
	p, err := NewHistorical(FormatSyslogSSHD, "", HistoricalOptions{Location: location, SyslogYear: 2024})
	if err != nil {
		t.Fatal(err)
	}
	event, err := p.Parse("Dec 31 23:59:58 host sshd[123]: Failed password for root from 198.51.100.8 port 42122 ssh2")
	if err != nil {
		t.Fatal(err)
	}
	if event.Timestamp.Year() != 2024 || event.Timestamp.Location() != location {
		t.Fatalf("timestamp = %v, want explicit 2024 archive timezone", event.Timestamp)
	}
}

func TestHistoricalSecurityParserRejectsImplicitTimeContext(t *testing.T) {
	if _, err := NewHistorical(FormatSyslogSSHD, "", HistoricalOptions{}); err == nil {
		t.Fatal("historical syslog parser accepted implicit year and timezone")
	}
	if _, err := NewHistorical(FormatNginxError, "", HistoricalOptions{}); err == nil {
		t.Fatal("historical Nginx error parser accepted implicit timezone")
	}
}
