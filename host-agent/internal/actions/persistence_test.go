package actions

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScanModifiedSinceFindsOnlyNewerFiles(t *testing.T) {
	root := t.TempDir()
	cutoff := time.Now()
	time.Sleep(10 * time.Millisecond)

	oldFile := filepath.Join(root, "old.txt")
	_ = os.WriteFile(oldFile, []byte("x"), 0o644)
	old := cutoff.Add(-time.Hour)
	_ = os.Chtimes(oldFile, old, old)

	newFile := filepath.Join(root, "new.txt")
	_ = os.WriteFile(newFile, []byte("x"), 0o644)
	_ = os.Chtimes(newFile, time.Now(), time.Now())

	findings := ScanModifiedSince([]string{root}, cutoff)

	foundNew, foundOld := false, false
	for _, f := range findings {
		if f == newFile {
			foundNew = true
		}
		if f == oldFile {
			foundOld = true
		}
	}
	if !foundNew {
		t.Error("expected the newer file to be reported")
	}
	if foundOld {
		t.Error("did not expect the older file to be reported")
	}
}

func TestScanModifiedSinceReturnsEmptyNotNilForNoMatches(t *testing.T) {
	root := t.TempDir()
	findings := ScanModifiedSince([]string{root}, time.Now())
	if findings == nil {
		t.Error("expected a non-nil empty slice, got nil")
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings, got %v", findings)
	}
}

func TestScanModifiedSinceIgnoresMissingPaths(t *testing.T) {
	findings := ScanModifiedSince([]string{"/definitely/does/not/exist"}, time.Now())
	if len(findings) != 0 {
		t.Errorf("expected no findings for a missing path, got %v", findings)
	}
}

func TestScanModifiedSinceRespectsDepthLimit(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c", "d", "e", "too-deep.txt")
	if err := os.MkdirAll(filepath.Dir(deep), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(deep, []byte("x"), 0o644)

	cutoff := time.Now().Add(-time.Hour)
	findings := ScanModifiedSince([]string{root}, cutoff)

	for _, f := range findings {
		if f == deep {
			t.Error("expected the depth limit to exclude a file this deep")
		}
	}
}

func TestScanModifiedSinceRootReturnsLogicalPaths(t *testing.T) {
	hostRoot := t.TempDir()
	actualDir := filepath.Join(hostRoot, "etc", "sentinelmesh-test")
	if err := os.MkdirAll(actualDir, 0o755); err != nil {
		t.Fatal(err)
	}
	actual := filepath.Join(actualDir, "changed.conf")
	if err := os.WriteFile(actual, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-time.Hour)
	findings := ScanModifiedSinceRoot([]string{"/etc/sentinelmesh-test"}, cutoff, hostRoot)
	for _, got := range findings {
		if got == "/etc/sentinelmesh-test/changed.conf" {
			return
		}
	}
	t.Fatalf("expected logical host path in findings, got %v", findings)
}
