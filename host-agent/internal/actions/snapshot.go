package actions

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sentinelmesh/host-agent/internal/validate"
)

// tsLayout names snapshot directories. UTC, sortable, no timezone suffix.
const tsLayout = "20060102T150405.000000000"

// Snapshotter takes periodic copies of a configured set of paths on THIS
// host and restores individual files from them. Each host's agent
// snapshots its own filesystem, which is what makes restore work across a
// fleet (control-plane no longer needs to share a filesystem with anything).
//
// Paths may contain glob patterns (e.g. /home/*/.ssh). A snapshot mirrors
// the real layout under its own directory, so /etc/cron.d/x lives at
// <Root>/<ts>/etc/cron.d/x and a restore can map any covered path back
// without extra bookkeeping.
//
// Snapshots contain whatever the watched paths contain -- including
// /etc/shadow if /etc is watched -- so Root must stay root-only (0700).
type Snapshotter struct {
	Root     string
	Paths    []string
	Keep     int    // retain the newest Keep snapshots; <=0 keeps everything
	HostRoot string // logical "/" is mapped into this root when set (e.g. /hostfs)
}

func toRelative(abs string) string { return strings.TrimLeft(filepath.Clean(abs), "/") }

func normalizeHostRoot(root string) string {
	if root == "" {
		return "/"
	}
	root = filepath.Clean(root)
	if root == "" {
		return "/"
	}
	return root
}

func resolveHostPath(logical, hostRoot string) string {
	logical = filepath.Clean(logical)
	root := normalizeHostRoot(hostRoot)
	if root == "/" {
		return logical
	}
	return filepath.Join(root, strings.TrimPrefix(logical, string(filepath.Separator)))
}

func logicalHostPath(actual, hostRoot string) string {
	actual = filepath.Clean(actual)
	root := normalizeHostRoot(hostRoot)
	if root == "/" {
		return actual
	}
	rel, err := filepath.Rel(root, actual)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return actual
	}
	return string(filepath.Separator) + rel
}

func (s *Snapshotter) expand() []string {
	var out []string
	root := normalizeHostRoot(s.HostRoot)
	for _, logical := range s.Paths {
		actualPattern := resolveHostPath(logical, root)
		matches, err := filepath.Glob(actualPattern)
		if err != nil {
			continue
		}
		for _, actual := range matches {
			out = append(out, actual)
		}
	}
	return out
}

// covered reports whether abs, or any ancestor of it, matches one of the
// configured patterns. Matching against the *patterns* (not the currently
// existing paths) matters: an attacker who deletes /root/.ssh must still
// leave it restorable.
func (s *Snapshotter) covered(abs string) bool {
	logical := logicalHostPath(abs, s.HostRoot)
	for _, pat := range s.Paths {
		for cur := logical; ; cur = filepath.Dir(cur) {
			if ok, err := filepath.Match(pat, cur); err == nil && ok {
				return true
			}
			if cur == "/" || cur == "." {
				break
			}
		}
	}
	return false
}

func (s *Snapshotter) list() []string {
	entries, err := os.ReadDir(s.Root)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := time.Parse(tsLayout, e.Name()); err != nil {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// Create snapshots every watched path that currently exists. Best effort
// per path: it returns the snapshot id plus the first error, so a single
// unreadable path doesn't discard the rest of the snapshot.
func (s *Snapshotter) Create(now time.Time) (string, error) {
	id := now.UTC().Format(tsLayout)
	dest := filepath.Join(s.Root, id)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return "", err
	}
	var firstErr error
	for _, actual := range s.expand() {
		logical := logicalHostPath(actual, s.HostRoot)
		target := filepath.Join(dest, toRelative(logical))
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err := runCmd("cp", "-a", actual, target); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	s.prune()
	return id, firstErr
}

func (s *Snapshotter) prune() {
	if s.Keep <= 0 {
		return
	}
	names := s.list()
	for len(names) > s.Keep {
		_ = os.RemoveAll(filepath.Join(s.Root, names[0]))
		names = names[1:]
	}
}

// latestBefore returns the newest snapshot strictly older than `before`.
func (s *Snapshotter) latestBefore(before time.Time) (string, bool) {
	names := s.list()
	for i := len(names) - 1; i >= 0; i-- {
		t, err := time.Parse(tsLayout, names[i])
		if err == nil && t.Before(before) {
			return filepath.Join(s.Root, names[i]), true
		}
	}
	return "", false
}

// Restore copies path back from the newest snapshot older than `before`.
// It returns (false, nil) when there's simply nothing to restore -- no
// snapshot that old, or the path wasn't captured -- and an error only when
// the request itself is invalid or the copy fails.
//
// Caveat worth knowing: a snapshot taken *before* the incident can still
// contain earlier attacker persistence if the compromise predates it.
func (s *Snapshotter) Restore(path string, before time.Time) (bool, error) {
	abs, err := validate.AbsPath(path)
	if err != nil {
		return false, err
	}
	if !s.covered(abs) {
		return false, errors.New("path is not covered by any snapshot root")
	}
	snap, ok := s.latestBefore(before)
	if !ok {
		return false, nil
	}
	src := filepath.Join(snap, toRelative(abs))
	dst := resolveHostPath(abs, s.HostRoot)
	fi, err := os.Lstat(src)
	if err != nil {
		return false, nil
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("refusing to restore a symlink from snapshot")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	if fi.IsDir() {
		if _, statErr := os.Stat(dst); os.IsNotExist(statErr) {
			return true, runCmd("cp", "-a", src, dst)
		}
		// Existing directory: copy the *contents* over it. Plain
		// `cp -a src abs` would nest a second copy inside abs.
		return true, runCmd("cp", "-a", src+"/.", dst+"/")
	}
	return true, runCmd("cp", "-a", src, dst)
}
