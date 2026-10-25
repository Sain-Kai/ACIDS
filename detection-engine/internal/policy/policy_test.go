package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSignVerifyAndWrite(t *testing.T) {
	key := "test-key"
	signed, err := Sign(Document{Version: 7}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(signed, key); err != nil {
		t.Fatal(err)
	}
	signed.Signature = "00"
	if _, err := Verify(signed, key); err == nil {
		t.Fatal("expected invalid signature")
	}
	signed, _ = Sign(Document{Version: 8}, key)
	path := filepath.Join(t.TempDir(), "policy", "current.json")
	if err := WriteAtomically(path, signed, key); err != nil {
		t.Fatal(err)
	}
	d, _, err := Read(path, key)
	if err != nil || d.Version != 8 {
		t.Fatalf("read failed: %v %#v", err, d)
	}
	_ = os.Remove(path)
}
