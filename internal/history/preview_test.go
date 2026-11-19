package history

import (
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/parser"
)

func TestPreviewStreamsGzipAndUsesNaturalRotationOrder(t *testing.T) {
	directory := t.TempDir()
	lines := map[string]string{
		"access.log.10.gz": nginxLine("01/Jan/2024:00:00:00 +0000", "/old"),
		"access.log.2.gz":  nginxLine("02/Jan/2024:00:00:00 +0000", "/middle"),
		"access.log.1":     nginxLine("03/Jan/2024:00:00:00 +0000", "/newer"),
		"access.log":       nginxLine("04/Jan/2024:00:00:00 +0000", "/current"),
	}
	for name, contents := range lines {
		path := filepath.Join(directory, name)
		if strings.HasSuffix(name, ".gz") {
			writeGzip(t, path, contents+"\n")
		} else if err := os.WriteFile(path, []byte(contents+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := Preview(context.Background(), defaultOptions(directory))
	if err != nil {
		t.Fatal(err)
	}
	wantNames := []string{"access.log.10.gz", "access.log.2.gz", "access.log.1", "access.log"}
	if len(report.Files) != len(wantNames) {
		t.Fatalf("files = %d, want %d", len(report.Files), len(wantNames))
	}
	for index, want := range wantNames {
		if got := filepath.Base(report.Files[index].Path); got != want {
			t.Errorf("file[%d] = %q, want %q", index, got, want)
		}
		if report.Files[index].Err != nil {
			t.Errorf("file[%d] error: %v", index, report.Files[index].Err)
		}
	}
	if report.Parsed != 4 || report.Unparsed != 0 || report.Overlapping != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestPreviewReportsUnparsedOutOfOrderAndOverlap(t *testing.T) {
	directory := t.TempDir()
	older := nginxLine("02/Jan/2024:00:00:00 +0000", "/two") + "\n" + nginxLine("01/Jan/2024:00:00:00 +0000", "/one") + "\ninvalid\n"
	newer := nginxLine("01/Jan/2024:12:00:00 +0000", "/overlap") + "\n"
	if err := os.WriteFile(filepath.Join(directory, "access.log.1"), []byte(older), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "access.log"), []byte(newer), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := Preview(context.Background(), defaultOptions(directory))
	if err != nil {
		t.Fatal(err)
	}
	if report.Parsed != 3 || report.Unparsed != 1 || report.Malformed != 1 || report.Ignored != 0 || report.Files[0].OutOfOrderLines != 1 || report.Overlapping != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestPreviewCanOrderReportsByFirstRecognizedEvent(t *testing.T) {
	directory := t.TempDir()
	for name, timestamp := range map[string]string{
		"access.log.a": "03/Jan/2024:00:00:00 +0000",
		"access.log.b": "01/Jan/2024:00:00:00 +0000",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(nginxLine(timestamp, "/")+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	options := defaultOptions(directory)
	options.NameRegex = `^access\.log\.[ab]$`
	options.Order = OrderFirstEvent
	report, err := Preview(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(report.Files[0].Path); got != "access.log.b" {
		t.Fatalf("first report file = %q, want access.log.b", got)
	}
}

func TestPreviewCanOrderByExplicitFilenameTimestamp(t *testing.T) {
	directory := t.TempDir()
	for name := range map[string]struct{}{"access-2024-01-10.log": {}, "access-2024-01-02.log": {}} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(nginxLine("01/Jan/2024:00:00:00 +0000", "/")+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	options := defaultOptions(directory)
	options.NameRegex = `^access-[0-9]{4}-[0-9]{2}-[0-9]{2}\.log$`
	options.Order = OrderFilenameTime
	options.FilenameTimeRegex = `^access-([0-9]{4}-[0-9]{2}-[0-9]{2})\.log$`
	options.FilenameTimeLayout = "2006-01-02"
	report, err := Preview(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(report.Files[0].Path); got != "access-2024-01-02.log" {
		t.Fatalf("first report file = %q, want dated oldest file", got)
	}
}

func TestPreviewRejectsMatchedSymlinkAndUnsupportedArchive(t *testing.T) {
	for _, name := range []string{"access.log", "access.zip"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, name)
			if name == "access.log" {
				target := filepath.Join(directory, "target")
				if err := os.WriteFile(target, []byte("line"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, []byte("zip"), 0600); err != nil {
				t.Fatal(err)
			}
			options := defaultOptions(directory)
			options.NameRegex = `^access\.(?:log|zip)$`
			if _, err := Preview(context.Background(), options); err == nil {
				t.Fatal("unsafe matched file was accepted")
			}
		})
	}
}

func TestPreviewHistoricalSyslogUsesExplicitYearAndTimezone(t *testing.T) {
	directory := t.TempDir()
	line := "Dec 31 23:59:58 host sshd[123]: Failed password for root from 198.51.100.8 port 42122 ssh2\n"
	if err := os.WriteFile(filepath.Join(directory, "auth.log"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	options := defaultOptions(directory)
	options.NameRegex = `^auth\.log$`
	options.Format = parser.FormatSyslogSSHD
	options.Location = time.FixedZone("archive", 7*60*60)
	options.SyslogYear = 2024
	report, err := Preview(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Files[0].FirstEvent; got.Year() != 2024 || got.Location() != options.Location {
		t.Fatalf("first event = %v", got)
	}
}

func TestPreviewSeparatesIgnoredAndMalformedSecurityRecords(t *testing.T) {
	directory := t.TempDir()
	lines := strings.Join([]string{
		"Oct 26 13:20:01 host sshd[1]: Accepted publickey for deploy from 198.51.100.8 port 22 ssh2",
		"Oct 26 13:20:02 host sshd[1]: Failed password without a remote address",
		"Oct 26 13:20:03 host sshd[1]: Failed password for root from 198.51.100.8 port 22 ssh2",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(directory, "auth.log"), []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	options := defaultOptions(directory)
	options.NameRegex = `^auth\.log$`
	options.Format = parser.FormatSyslogSSHD
	options.Location = time.UTC
	options.SyslogYear = 2026
	report, err := Preview(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if report.Parsed != 1 || report.Ignored != 1 || report.Malformed != 1 || report.Unparsed != 2 {
		t.Fatalf("report = %+v", report)
	}
}

func TestPreviewReportsCorruptGzipAndTotalExpansionLimit(t *testing.T) {
	t.Run("corrupt gzip", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.WriteFile(filepath.Join(directory, "access.log.1.gz"), []byte("not gzip"), 0600); err != nil {
			t.Fatal(err)
		}
		report, err := Preview(context.Background(), defaultOptions(directory))
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Files) != 1 || report.Files[0].Err == nil {
			t.Fatalf("report = %+v, want corrupt gzip error", report)
		}
	})

	t.Run("total expanded bytes", func(t *testing.T) {
		directory := t.TempDir()
		line := nginxLine("01/Jan/2024:00:00:00 +0000", "/") + "\n"
		for _, name := range []string{"access.log.1", "access.log"} {
			if err := os.WriteFile(filepath.Join(directory, name), []byte(line), 0600); err != nil {
				t.Fatal(err)
			}
		}
		options := defaultOptions(directory)
		options.MaxExpandedBytes = int64(len(line) + 10)
		report, err := Preview(context.Background(), options)
		if err != nil {
			t.Fatal(err)
		}
		if report.Files[0].Err != nil || report.Files[1].Err == nil {
			t.Fatalf("file errors = [%v, %v], want total limit on second file", report.Files[0].Err, report.Files[1].Err)
		}
	})
}

func defaultOptions(directory string) PreviewOptions {
	return PreviewOptions{
		Directory: directory, NameRegex: `^access\.log(?:\.[0-9]+(?:\.gz)?)?$`, Format: parser.FormatNginxCombined,
		Order: OrderNatural, MaxFiles: 100, MaxInputBytes: 1 << 20, MaxExpandedBytes: 1 << 20, MaxLineBytes: 64 << 10,
	}
}

func nginxLine(timestamp, path string) string {
	return `192.0.2.1 - - [` + timestamp + `] "GET ` + path + ` HTTP/1.1" 200 12 "-" "test"`
}

func writeGzip(t *testing.T, path, contents string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
