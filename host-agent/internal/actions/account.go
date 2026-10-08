package actions

import "sentinelmesh/host-agent/internal/validate"

// LockAccount disables a local account and kills its processes.
//
// `usermod -L` alone only blocks *password* login -- SSH key auth would
// still work. `-e 1` also sets the account expiry to 1970-01-02, which PAM's
// account stage rejects for every auth method, key-based included.
//
// Protected/system accounts are refused by validate.Username. This is
// containment, not credential rotation: it leaves the account recoverable
// by an administrator (`usermod -U -e ""`) once the incident is closed.
func LockAccount(username string) error {
	return LockAccountOnHost("/", username)
}

func LockAccountOnHost(hostRoot, username string) error {
	u, err := validate.Username(username)
	if err != nil {
		return err
	}
	root := hostRoot
	if root == "" {
		root = "/"
	}
	if root == "/" {
		if err := runCmd("usermod", "-L", "-e", "1", u); err != nil {
			return err
		}
	} else {
		if err := runCmd("chroot", root, "/usr/sbin/usermod", "-L", "-e", "1", u); err != nil {
			return err
		}
	}
	// pkill exits 1 when nothing matched, which is fine here.
	_ = runCmd("pkill", "-KILL", "-u", u)
	return nil
}
