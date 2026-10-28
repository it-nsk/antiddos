package parser

import "testing"

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
	_, err = p.Parse("2026-10-25T00:08:42.695344+00:00 bgt-web sshd[96647]: Accepted publickey for deploy from 45.198.224.51 port 12284 ssh2")
	if err == nil {
		t.Fatal("successful SSH login must not be parsed as a failed login")
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
