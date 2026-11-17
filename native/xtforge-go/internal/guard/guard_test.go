package guard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRootsAndDenyGlobs(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XT_ROOTS", tmp)
	t.Setenv("XT_HOME", filepath.Join(tmp, ".xt"))

	good := filepath.Join(tmp, "hello.txt")
	if err := os.WriteFile(good, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGuard(good); err != nil {
		t.Fatalf("expected good path allowed, got %v", err)
	}

	envFile := filepath.Join(tmp, ".env")
	if err := os.WriteFile(envFile, []byte("SECRET=1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGuard(envFile); err == nil {
		t.Fatal("expected .env to be denied")
	}

	if _, err := ReadGuard("/etc/passwd"); err == nil {
		t.Fatal("expected /etc/passwd outside roots to be denied")
	}
}

func TestPermissionModesAndTokens(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XT_ROOTS", tmp)
	t.Setenv("XT_HOME", filepath.Join(tmp, ".xt"))

	target := filepath.Join(tmp, "out.bin")
	t.Setenv("XT_PERM_MODE", "explore")
	if _, err := WriteGuard(target, true, "", false); err == nil {
		t.Fatal("expected explore mode to reject write")
	}

	t.Setenv("XT_PERM_MODE", "ask")
	tokInfo, err := IssueToken("patch", target, "re")
	if err != nil {
		t.Fatal(err)
	}
	tok := tokInfo["confirm_token"].(string)
	res, err := WriteGuard(target, true, tok, false)
	if err != nil {
		t.Fatalf("expected valid token to pass, got %v", err)
	}
	if res["confirmed"] != true {
		t.Fatalf("expected confirmed=true, got %v", res)
	}
	if _, err := WriteGuard(target, true, tok, false); err == nil {
		t.Fatal("expected reused token to be rejected")
	}
}
