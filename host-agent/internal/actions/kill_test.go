package actions

import (
	"errors"
	"os"
	"testing"
)

func TestSameBinary(t *testing.T) {
	cases := []struct {
		actual, expected string
		want             bool
	}{
		{"/usr/bin/python3.11", "/usr/bin/python3", true},
		{"/usr/bin/bash", "/bin/bash", true},
		{"/tmp/payload (deleted)", "/tmp/payload", true},
		{"/usr/bin/nginx", "/usr/bin/bash", false},
		{"", "/usr/bin/bash", false},
		{"/usr/bin/bash", "", false},
	}
	for _, c := range cases {
		if got := sameBinary(c.actual, c.expected); got != c.want {
			t.Errorf("sameBinary(%q,%q) = %v, want %v", c.actual, c.expected, got, c.want)
		}
	}
}

func TestKillSkipsWhenExeDoesNotMatch(t *testing.T) {
	orig := readExe
	defer func() { readExe = orig }()
	readExe = func(pid int) (string, error) { return "/usr/bin/some-other-binary", nil }

	r := Kill([]KillTarget{{PID: 4242, Exe: "/tmp/malware"}})
	if r.Killed != 0 || r.Attempted != 0 || r.Skipped != 1 {
		t.Errorf("expected a pure skip on exe mismatch, got %+v", r)
	}
}

func TestKillSkipsOnProcLookupFailure(t *testing.T) {
	orig := readExe
	defer func() { readExe = orig }()
	readExe = func(pid int) (string, error) { return "", errors.New("no such process") }

	r := Kill([]KillTarget{{PID: 4242, Exe: "/tmp/malware"}})
	if r.Skipped != 1 || r.Attempted != 0 {
		t.Errorf("expected skip on lookup failure, got %+v", r)
	}
}

func TestKillRejectsSelfAndInit(t *testing.T) {
	orig := readExe
	defer func() { readExe = orig }()
	readExe = func(pid int) (string, error) { return "/tmp/malware", nil }

	r := Kill([]KillTarget{{PID: 1, Exe: "/tmp/malware"}, {PID: os.Getpid(), Exe: "/tmp/malware"}})
	if r.Attempted != 0 || r.Skipped != 2 {
		t.Errorf("expected both pid<=1 and self-pid rejected, got %+v", r)
	}
}

func TestKillDedupesRepeatedPIDs(t *testing.T) {
	orig := readExe
	defer func() { readExe = orig }()
	calls := 0
	readExe = func(pid int) (string, error) { calls++; return "", errors.New("nope") }

	Kill([]KillTarget{{PID: 999, Exe: "/tmp/x"}, {PID: 999, Exe: "/tmp/x"}})
	if calls != 1 {
		t.Errorf("expected one /proc lookup for a repeated pid, got %d", calls)
	}
}
