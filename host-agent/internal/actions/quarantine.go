package actions

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"sentinelmesh/host-agent/internal/validate"
)

// Quarantine moves a regular file into dir and strips all permissions, so
// nothing but root can read or execute it. The name is <eventID>_<base>,
// matching detection-engine's QuarantineDestPath so both sides agree on
// where an artifact lives. Returns the destination path.
//
// Symlinks and directories are refused: chmod on a moved symlink would
// follow it and strip permissions from the *target*.
func Quarantine(dir, path, eventID string) (string, error) {
	return QuarantineOnHost("/", dir, path, eventID)
}

func QuarantineOnHost(hostRoot, dir, path, eventID string) (string, error) {
	p, err := validate.AbsPath(path)
	if err != nil {
		return "", err
	}
	if err := validate.QuarantineAllowed(p, dir); err != nil {
		return "", err
	}
	if hostRoot == "" {
		hostRoot = "/"
	}
	actual := p
	if hostRoot != "/" {
		root, rootErr := validate.AbsPath(hostRoot)
		if rootErr != nil {
			return "", rootErr
		}
		actual = filepath.Join(root, strings.TrimPrefix(p, string(filepath.Separator)))
		if !validate.Within(actual, root) {
			return "", errors.New("path escapes host root")
		}
	}
	if err := validate.Token(eventID); err != nil {
		return "", err
	}
	dest := filepath.Join(dir, eventID+"_"+filepath.Base(p))
	fi, err := os.Lstat(actual)
	if os.IsNotExist(err) {
		if existing, statErr := os.Stat(dest); statErr == nil && existing.Mode().IsRegular() {
			return dest, nil
		}
		return "", err
	}
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", errors.New("only regular files can be quarantined")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := moveFile(actual, dest); err != nil {
		return "", err
	}
	if err := os.Chmod(dest, 0o000); err != nil {
		return "", err
	}
	return dest, nil
}

// moveFile renames, falling back to copy+remove when src and dst are on
// different filesystems (rename fails with EXDEV there -- common when the
// quarantine directory lives on its own volume).
func moveFile(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

func copyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(dst)
		}
	}()
	_, err = io.Copy(out, in)
	return err
}
