package history

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/it-nsk/antiddos/internal/storage"
)

func TestCatalogPublishesAdjacentCoverageAndRejectsOverlap(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	var lines []string
	for _, offset := range []time.Duration{0, 5 * time.Second, 10 * time.Second, 15 * time.Second, 20 * time.Second} {
		lines = append(lines, nginxLine(base.Add(offset).Format("02/Jan/2006:15:04:05 -0700"), "/login"))
	}
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	makeResult := func(name string, from, to time.Time) string {
		output := filepath.Join(root, name)
		options := importTestOptions(logs, output)
		options.From = from
		options.To = to
		if _, err := Import(context.Background(), options); err != nil {
			t.Fatal(err)
		}
		return output
	}
	first := makeResult("first.sqlite", base.Add(15*time.Second), base.Add(45*time.Second))
	replacement := makeResult("replacement.sqlite", base.Add(15*time.Second), base.Add(30*time.Second))
	second := makeResult("second.sqlite", base.Add(45*time.Second), base.Add(60*time.Second))
	overlap := makeResult("overlap.sqlite", base.Add(30*time.Second), base.Add(60*time.Second))
	catalog := filepath.Join(root, "catalog.sqlite")
	if result, err := PublishToCatalog(context.Background(), catalog, first); err != nil || result.AlreadyPublished {
		t.Fatalf("first = %#v, %v", result, err)
	}
	if result, err := PublishToCatalog(context.Background(), catalog, first); err != nil || !result.AlreadyPublished {
		t.Fatalf("idempotent = %#v, %v", result, err)
	}
	firstEntry, err := catalogCandidate(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplaceCatalog(context.Background(), catalog, replacement, firstEntry.ImportID); err != nil {
		t.Fatalf("replace = %v", err)
	}
	if _, err := PublishToCatalog(context.Background(), catalog, second); err != nil {
		t.Fatalf("adjacent = %v", err)
	}
	entries, err := CatalogEntries(context.Background(), catalog)
	if err != nil || len(entries) != 2 {
		t.Fatalf("catalog entries=%#v, err=%v", entries, err)
	}
	traffic, err := ReadCatalogTraffic(context.Background(), catalog, base.Add(15*time.Second), base.Add(60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var requests int64
	for _, sample := range traffic.Samples {
		requests += sample.Requests
	}
	if traffic.Entries != 2 || requests != 2 {
		t.Fatalf("traffic=%#v requests=%d", traffic, requests)
	}
	coverage, err := ReadCatalogCoverage(context.Background(), catalog, "web", base, base.Add(75*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(coverage.Covered) != 2 || len(coverage.Gaps) != 3 || !coverage.Gaps[0].From.Equal(base) || !coverage.Gaps[0].To.Equal(base.Add(15*time.Second)) || !coverage.Gaps[1].From.Equal(base.Add(30*time.Second)) || !coverage.Gaps[1].To.Equal(base.Add(45*time.Second)) || !coverage.Gaps[2].From.Equal(base.Add(60*time.Second)) || !coverage.Gaps[2].To.Equal(base.Add(75*time.Second)) {
		t.Fatalf("coverage=%#v", coverage)
	}
	detections, err := ReadCatalogDetections(context.Background(), catalog, base.Add(15*time.Second), base.Add(60*time.Second), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(detections) != 2 || detections[0].ImportID == "" || detections[0].RuleID != "login" {
		t.Fatalf("detections=%#v", detections)
	}
	if _, err := PublishToCatalog(context.Background(), catalog, overlap); err == nil || !strings.Contains(err.Error(), "overlaps") {
		t.Fatalf("overlap error = %v", err)
	}
}

func TestCatalogRestrictsDatabasePermissions(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 5, 0, time.UTC)
	contents := nginxLine(base.Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n" +
		nginxLine(base.Add(5*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n" +
		nginxLine(base.Add(10*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	result := filepath.Join(root, "result.sqlite")
	options := importTestOptions(logs, result)
	options.From, options.To = base.Add(10*time.Second), base.Add(25*time.Second)
	if _, err := Import(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(root, "catalog.sqlite")
	if _, err := PublishToCatalog(context.Background(), catalog, result); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("catalog permissions=%#o, want 0600", info.Mode().Perm())
	}
}

func TestInferredRangePublishesWithWarmupWarning(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 5, 0, time.UTC)
	line := nginxLine(base.Format("02/Jan/2006:15:04:05 -0700"), "/login")
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "result.sqlite")
	result, err := Import(context.Background(), importTestOptions(logs, output))
	if err != nil {
		t.Fatal(err)
	}
	if result.WarmupComplete {
		t.Fatal("first event incorrectly claims warmup")
	}
	entry, err := PublishToDatabase(context.Background(), output, filepath.Join(root, "dashboard.sqlite"), result.ImportID)
	if err != nil {
		t.Fatal(err)
	}
	if !entry.Entry.From.Equal(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)) || !entry.Entry.To.Equal(time.Date(2024, 1, 1, 0, 0, 15, 0, time.UTC)) {
		t.Fatalf("coverage: %#v", entry.Entry)
	}
}

func TestComparisonResultCannotPublish(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	line := nginxLine("01/Jan/2024:00:00:05 +0000", "/login")
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "comparison.sqlite")
	options := importTestOptions(logs, output)
	options.ComparisonRule, options.ParentImportID = "login", "parent-import"
	result, err := Import(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := storage.OpenReader(output)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := reader.HistoryImportManifest(context.Background(), result.ImportID)
	reader.Close()
	if err != nil || !strings.Contains(string(manifest), `"parent_import_id":"parent-import"`) {
		t.Fatalf("comparison provenance: %s, %v", manifest, err)
	}
	if _, err := PublishToDatabase(context.Background(), output, filepath.Join(root, "live.sqlite"), result.ImportID); err == nil || !strings.Contains(err.Error(), "comparison result") {
		t.Fatalf("comparison published: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "live.sqlite")); !os.IsNotExist(err) {
		t.Fatalf("live database created: %v", err)
	}
}

func TestCatalogRejectsSymlinkResult(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.sqlite")
	if err := os.WriteFile(target, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "result.sqlite")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishToCatalog(context.Background(), filepath.Join(root, "catalog.sqlite"), link); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestCatalogRejectsSymlinkCatalog(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.sqlite")
	if err := os.WriteFile(target, []byte("not a catalog"), 0o600); err != nil {
		t.Fatal(err)
	}
	catalog := filepath.Join(root, "catalog.sqlite")
	if err := os.Symlink(target, catalog); err != nil {
		t.Fatal(err)
	}
	if _, err := CatalogEntries(context.Background(), catalog); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("read symlink catalog error = %v", err)
	}
	if _, err := PublishToCatalog(context.Background(), catalog, target); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("write symlink catalog error = %v", err)
	}
}

func TestPublishToDatabaseAppendsOnceAndRequiresExactConfirmation(t *testing.T) {
	root := t.TempDir()
	logs := filepath.Join(root, "logs")
	if err := os.Mkdir(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2024, 1, 1, 0, 0, 5, 0, time.UTC)
	contents := nginxLine(base.Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n" +
		nginxLine(base.Add(5*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n" +
		nginxLine(base.Add(10*time.Second).Format("02/Jan/2006:15:04:05 -0700"), "/login") + "\n"
	if err := os.WriteFile(filepath.Join(logs, "access.log"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	isolated := filepath.Join(root, "isolated.sqlite")
	options := importTestOptions(logs, isolated)
	options.From, options.To = base.Add(10*time.Second), base.Add(25*time.Second)
	imported, err := Import(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.sqlite")
	if _, err := PublishToDatabase(context.Background(), isolated, target, "wrong"); err == nil {
		t.Fatal("wrong confirmation was accepted")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("wrong confirmation created target: %v", err)
	}
	published, err := PublishToDatabase(context.Background(), isolated, target, imported.ImportID)
	if err != nil {
		t.Fatal(err)
	}
	if published.AlreadyPublished || published.Detections != 1 || published.TrafficSamples != 1 {
		t.Fatalf("published=%+v", published)
	}
	reader, err := storage.OpenReader(target)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	detections, err := reader.Detections(context.Background(), 10)
	if err != nil || len(detections) != 1 {
		t.Fatalf("detections=%#v, err=%v", detections, err)
	}
	traffic, err := reader.Traffic(context.Background(), 10)
	if err != nil || len(traffic) != 1 || traffic[0].Requests != 1 {
		t.Fatalf("traffic=%#v, err=%v", traffic, err)
	}
	again, err := PublishToDatabase(context.Background(), isolated, target, imported.ImportID)
	if err != nil || !again.AlreadyPublished {
		t.Fatalf("idempotent publish=%+v, err=%v", again, err)
	}
}
