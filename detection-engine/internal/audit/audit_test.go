package audit

import (
	"encoding/json"
	"os"
	"testing"

	"sentinelmesh/detection-engine/internal/types"
)

func TestLoggerWritesHashChain(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.log"
	logger, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ev := types.Event{EventID: "e1"}
	verdict := types.Verdict{Action: types.ActionKillProcess, Score: 0.99, MatchedRules: []string{"rule-a"}}
	if err := logger.Record(ev, verdict, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := logger.Record(types.Event{EventID: "e2"}, types.Verdict{Action: types.ActionBlockNetwork, Score: 0.88}, false, os.ErrPermission); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := splitLines(b)
	if len(lines) != 2 {
		t.Fatalf("got %d records", len(lines))
	}
	var a, c Record
	if err := json.Unmarshal(lines[0], &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(lines[1], &c); err != nil {
		t.Fatal(err)
	}
	if c.PreviousHash != a.Hash || a.Hash == "" || c.Hash == "" {
		t.Fatal("hash chain not linked")
	}
	if c.Success || c.Error == "" {
		t.Fatal("failed action record missing outcome")
	}
}

func TestLoggerRejectsCorruptTail(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.log"
	if err := os.WriteFile(path, []byte("{\"not\":\"a valid audit record\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path); err == nil {
		t.Fatal("expected corrupt tail rejection")
	}
}
