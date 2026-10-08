package actions

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"sentinelmesh/host-agent/internal/validate"
)

// KillTarget identifies a process to kill. Exe is required: control-plane
// learns about PIDs from *historical* events, and by the time reclaim runs
// a PID may have exited and been reused by an unrelated process. Killing
// blind by number would eventually kill something innocent, so the agent
// only signals a PID whose current /proc/<pid>/exe still matches the
// binary the event recorded.
type KillTarget struct {
	PID int    `json:"pid"`
	Exe string `json:"exe"`
}

type KillResult struct {
	Attempted int `json:"attempted"`
	Killed    int `json:"killed"`
	Skipped   int `json:"skipped"`
}

// readExe is a variable so tests can fake /proc.
var readExe = func(pid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
}

// sameBinary compares base names, tolerating the two ways an event's
// recorded exe and /proc/<pid>/exe legitimately differ: a "(deleted)"
// suffix on a removed binary, and versioned interpreters (event says
// "python3", /proc says "python3.11").
func sameBinary(actual, expected string) bool {
	actual = strings.TrimSuffix(actual, " (deleted)")
	if actual == "" || expected == "" {
		return false
	}
	a, e := filepath.Base(actual), filepath.Base(expected)
	return a == e || strings.HasPrefix(a, e) || strings.HasPrefix(e, a)
}

func Kill(targets []KillTarget) KillResult {
	self := os.Getpid()
	seen := make(map[int]bool)
	var r KillResult
	for _, t := range targets {
		if seen[t.PID] {
			continue
		}
		seen[t.PID] = true
		if validate.PID(t.PID, self) != nil || t.Exe == "" {
			r.Skipped++
			continue
		}
		actual, err := readExe(t.PID)
		if err != nil || !sameBinary(actual, t.Exe) {
			r.Skipped++
			continue
		}
		r.Attempted++
		if syscall.Kill(t.PID, syscall.SIGKILL) == nil {
			r.Killed++
		}
	}
	return r
}
