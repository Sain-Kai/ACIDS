package actions

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxScanDepth = 4
	maxFindings  = 500
)

// ScanModifiedSince is the compatibility wrapper used by tests and local
// development. In production, ScanModifiedSinceRoot maps logical host paths
// into a mounted host root (for example /hostfs).
func ScanModifiedSince(patterns []string, since time.Time) []string {
	return ScanModifiedSinceRoot(patterns, since, "/")
}

// ScanModifiedSinceRoot walks configured logical host paths (glob patterns
// allowed) and returns regular files whose mtime is after since. Findings are
// returned as logical host paths regardless of whether HostRoot is / or a
// mounted path such as /hostfs.
func ScanModifiedSinceRoot(patterns []string, since time.Time, hostRoot string) []string {
	findings := []string{}
	add := func(p string) bool {
		if len(findings) >= maxFindings {
			return false
		}
		findings = append(findings, logicalHostPath(p, hostRoot))
		return true
	}

	root := normalizeHostRoot(hostRoot)
	for _, pat := range patterns {
		roots, err := filepath.Glob(resolveHostPath(pat, root))
		if err != nil {
			continue
		}
		for _, scanRoot := range roots {
			fi, err := os.Lstat(scanRoot)
			if err != nil {
				continue
			}
			if fi.Mode().IsRegular() {
				if fi.ModTime().After(since) && !add(scanRoot) {
					return findings
				}
				continue
			}
			if !fi.IsDir() {
				continue
			}
			_ = filepath.WalkDir(scanRoot, func(path string, d fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				if d.IsDir() {
					rel, relErr := filepath.Rel(scanRoot, path)
					if relErr == nil && rel != "." && strings.Count(rel, string(filepath.Separator)) >= maxScanDepth-1 {
						return fs.SkipDir
					}
					return nil
				}
				if !d.Type().IsRegular() {
					return nil
				}
				info, infoErr := d.Info()
				if infoErr != nil {
					return nil
				}
				if info.ModTime().After(since) && !add(path) {
					return fs.SkipAll
				}
				return nil
			})
		}
	}
	return findings
}
