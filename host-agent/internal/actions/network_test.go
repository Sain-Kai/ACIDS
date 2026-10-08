package actions

import "testing"

func TestIsolateRejectsInvalidIPWithoutRunningAnyCommand(t *testing.T) {
	calls := withFakeRunCmd(t, nil)

	for _, ip := range []string{"", "not-an-ip", "127.0.0.1", "0.0.0.0", "10.0.0.5; rm -rf /"} {
		if err := Isolate(ip); err == nil {
			t.Errorf("expected Isolate(%q) to be rejected", ip)
		}
	}
	if len(*calls) != 0 {
		t.Errorf("expected zero iptables calls for rejected input, got %v", *calls)
	}
}

func TestIsolateInsertsAcceptBeforeDrop(t *testing.T) {
	calls := withFakeRunCmd(t, nil)

	if err := Isolate("10.0.0.5"); err != nil {
		t.Fatalf("Isolate: %v", err)
	}

	var sawAccept, sawDrop bool
	for _, c := range *calls {
		if contains(c, "ACCEPT") {
			sawAccept = true
			if sawDrop {
				t.Errorf("an ACCEPT rule was inserted after a DROP rule: %v", *calls)
			}
		}
		if contains(c, "DROP") {
			sawDrop = true
		}
	}
	if !sawAccept || !sawDrop {
		t.Errorf("expected both accept and drop rules, got %v", *calls)
	}
}

func TestIsolateUsesDedicatedChain(t *testing.T) {
	calls := withFakeRunCmd(t, nil)
	_ = Isolate("10.0.0.5")

	for _, c := range *calls {
		if c[0] != "iptables" {
			t.Errorf("expected only iptables calls, got %v", c)
		}
	}
	if len(*calls) == 0 {
		t.Fatal("expected at least one iptables call")
	}
}

// Filtering by the IP itself (rather than by -I/-A/-D flags) is
// deliberate: ensureChain's one-time bootstrap calls don't mention the
// IP at all, so this stays correct regardless of how many of those run.
func rulesReferencingIP(calls [][]string, ip string) int {
	n := 0
	for _, c := range calls {
		if contains(c, ip) {
			n++
		}
	}
	return n
}

func TestLiftDeletesEverythingIsolateInserted(t *testing.T) {
	const ip = "10.0.0.5"

	insertCalls := withFakeRunCmd(t, nil)
	if err := Isolate(ip); err != nil {
		t.Fatalf("Isolate: %v", err)
	}
	nInsert := rulesReferencingIP(*insertCalls, ip)
	if nInsert != len(acceptSpecs(ip))+len(dropSpecs(ip)) {
		t.Fatalf("expected one iptables call per accept+drop spec, got %d in %v", nInsert, *insertCalls)
	}

	deleteCalls := withFakeRunCmd(t, func(name string, args ...string) error {
		return nil
	})
	if err := Lift(ip); err != nil {
		t.Fatalf("Lift: %v", err)
	}
	nDelete := 0
	for _, c := range *deleteCalls {
		if contains(c, ip) && contains(c, "-D") {
			nDelete++
		}
	}

	if nInsert != nDelete {
		t.Errorf("Isolate inserted %d rules but Lift deleted %d", nInsert, nDelete)
	}
}

func TestLiftRejectsInvalidIP(t *testing.T) {
	calls := withFakeRunCmd(t, nil)
	if err := Lift("not-an-ip"); err == nil {
		t.Error("expected Lift to reject an invalid IP")
	}
	if len(*calls) != 0 {
		t.Errorf("expected zero commands for rejected input, got %v", *calls)
	}
}

func TestLiftIsIdempotentWhenRulesAreAlreadyAbsent(t *testing.T) {
	const ip = "10.0.0.5"
	calls := withFakeRunCmd(t, func(name string, args ...string) error {
		if contains(args, "-C") {
			return &fakeRuleMissingError{}
		}
		return nil
	})
	if err := Lift(ip); err != nil {
		t.Fatalf("Lift should succeed when rules are already absent: %v", err)
	}
	for _, c := range *calls {
		if contains(c, "-D") {
			t.Fatalf("Lift should not issue delete for an absent rule: %v", c)
		}
	}
}

type fakeRuleMissingError struct{}

func (*fakeRuleMissingError) Error() string { return "rule not present" }
