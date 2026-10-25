package validate

import "testing"

func TestIPv4(t *testing.T) {
	good := map[string]string{"10.0.0.5": "10.0.0.5", " 192.168.1.9 ": "192.168.1.9"}
	for in, want := range good {
		got, err := IPv4(in)
		if err != nil || got != want {
			t.Errorf("IPv4(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", "abc", "10.0.0.5; rm -rf /", "-s", "127.0.0.1", "0.0.0.0", "::1", "2001:db8::1", "10.0.0.256"}
	for _, in := range bad {
		if _, err := IPv4(in); err == nil {
			t.Errorf("IPv4(%q) should have been rejected", in)
		}
	}
}

func TestUsername(t *testing.T) {
	for _, ok := range []string{"alice", "www-data", "_svc", "a1_b-2"} {
		if _, err := Username(ok); err != nil {
			t.Errorf("Username(%q) rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "Root", "root", "daemon", "nobody", "-rf", "a b", "a;b", "1abc", "toolongtoolongtoolongtoolongtoolong1"} {
		if _, err := Username(bad); err == nil {
			t.Errorf("Username(%q) should have been rejected", bad)
		}
	}
}

func TestPID(t *testing.T) {
	if PID(1, 500) == nil || PID(0, 500) == nil || PID(-3, 500) == nil {
		t.Error("pid <= 1 must be rejected")
	}
	if PID(500, 500) == nil {
		t.Error("the agent's own pid must be rejected")
	}
	if PID(4242, 500) != nil {
		t.Error("an ordinary pid must be accepted")
	}
}

func TestToken(t *testing.T) {
	if Token("evt-123_ab") != nil {
		t.Error("valid token rejected")
	}
	for _, bad := range []string{"", "../x", "a/b", "a b", "a.b"} {
		if Token(bad) == nil {
			t.Errorf("Token(%q) should have been rejected", bad)
		}
	}
}

func TestAbsPath(t *testing.T) {
	got, err := AbsPath("/etc/../tmp//x")
	if err != nil || got != "/tmp/x" {
		t.Errorf("AbsPath cleaned to %q, %v", got, err)
	}
	for _, bad := range []string{"", "relative/path", "x\x00y"} {
		if _, err := AbsPath(bad); err == nil {
			t.Errorf("AbsPath(%q) should have been rejected", bad)
		}
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		path, root string
		within, orEq bool
	}{
		{"/var/q/file", "/var/q", true, true},
		{"/var/q", "/var/q", false, true},
		{"/var/qq/file", "/var/q", false, false},
		{"/var/q/../x", "/var/q", false, false},
		{"/other", "/var/q", false, false},
	}
	for _, c := range cases {
		if got := Within(c.path, c.root); got != c.within {
			t.Errorf("Within(%q,%q)=%v want %v", c.path, c.root, got, c.within)
		}
		if got := WithinOrEqual(c.path, c.root); got != c.orEq {
			t.Errorf("WithinOrEqual(%q,%q)=%v want %v", c.path, c.root, got, c.orEq)
		}
	}
}

func TestQuarantineAllowed(t *testing.T) {
	const qdir = "/var/lib/sentinelmesh/quarantine"
	for _, bad := range []string{"/", "/etc", "/etc/passwd", "/etc/shadow", "/proc/1/mem", "/dev/sda", "/boot/vmlinuz", qdir, qdir + "/x"} {
		if QuarantineAllowed(bad, qdir) == nil {
			t.Errorf("QuarantineAllowed(%q) should have been rejected", bad)
		}
	}
	for _, ok := range []string{"/tmp/dropper", "/var/www/shell.php", "/etc/cron.d/evil"} {
		if err := QuarantineAllowed(ok, qdir); err != nil {
			t.Errorf("QuarantineAllowed(%q) rejected: %v", ok, err)
		}
	}
}
