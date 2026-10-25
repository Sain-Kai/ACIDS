package actions

import (
	"errors"
	"strings"
	"testing"
)

func withFakeRunCmd(t *testing.T, fn func(name string, args ...string) error) *[][]string {
	t.Helper()
	var calls [][]string
	orig := runCmd
	runCmd = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		if fn != nil {
			return fn(name, args...)
		}
		return nil
	}
	t.Cleanup(func() { runCmd = orig })
	return &calls
}

func TestLockAccountRejectsProtectedUsersWithoutRunningAnyCommand(t *testing.T) {
	calls := withFakeRunCmd(t, nil)

	for _, u := range []string{"root", "daemon", "", "Root", "-rf"} {
		if err := LockAccount(u); err == nil {
			t.Errorf("expected LockAccount(%q) to be rejected", u)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("expected zero commands run for rejected usernames, got %v", *calls)
	}
}

func TestLockAccountRunsUsermodThenPkill(t *testing.T) {
	calls := withFakeRunCmd(t, nil)

	if err := LockAccount("www-data"); err != nil {
		t.Fatalf("LockAccount: %v", err)
	}

	if len(*calls) != 2 {
		t.Fatalf("expected exactly 2 commands, got %v", *calls)
	}
	if (*calls)[0][0] != "usermod" || !contains((*calls)[0], "www-data") || !contains((*calls)[0], "-L") {
		t.Errorf("expected a usermod -L call for www-data, got %v", (*calls)[0])
	}
	if (*calls)[1][0] != "pkill" || !contains((*calls)[1], "www-data") {
		t.Errorf("expected a pkill call for www-data, got %v", (*calls)[1])
	}
}

func TestLockAccountPropagatesUsermodFailureButIgnoresPkillFailure(t *testing.T) {
	withFakeRunCmd(t, func(name string, args ...string) error {
		if name == "usermod" {
			return errors.New("usermod: boom")
		}
		return errors.New("pkill: no processes matched") // expected, should be swallowed
	})

	if err := LockAccount("www-data"); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("expected usermod failure to propagate, got %v", err)
	}
}

func contains(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
