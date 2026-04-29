package caddymcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	token, err := generateToken()
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if len(token) < 20 {
		t.Errorf("token too short: %q", token)
	}
	if token[:4] != "mcp_" {
		t.Errorf("token should start with mcp_, got %q", token[:4])
	}
}

func TestHashToken(t *testing.T) {
	hash1 := hashToken("test-token")
	hash2 := hashToken("test-token")
	if hash1 != hash2 {
		t.Error("same token should produce same hash")
	}
	hash3 := hashToken("different-token")
	if hash1 == hash3 {
		t.Error("different tokens should produce different hashes")
	}
}

func TestCheckACL(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		tunnel   string
		want     bool
	}{
		{"no patterns allows all", nil, "anything", true},
		{"exact match", []string{"myapp"}, "myapp", true},
		{"exact no match", []string{"myapp"}, "other", false},
		{"glob wildcard", []string{"team-a-*"}, "team-a-frontend", true},
		{"glob no match", []string{"team-a-*"}, "team-b-frontend", false},
		{"multiple patterns", []string{"team-a-*", "shared-*"}, "shared-db", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &TokenInfo{AllowedTunnels: tt.patterns}
			if got := checkACL(info, tt.tunnel); got != tt.want {
				t.Errorf("checkACL(%v, %q) = %v, want %v", tt.patterns, tt.tunnel, got, tt.want)
			}
		})
	}
}

func TestJSONTokenStore_IssueAndValidate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens.json")
	ts, err := newJSONTokenStore(path)
	if err != nil {
		t.Fatalf("newJSONTokenStore: %v", err)
	}

	token, err := ts.Issue("test-token", 1*time.Hour, []string{"tunnel-*"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	info, ok := ts.Validate(context.Background(), token)
	if !ok {
		t.Fatal("Validate should return true for valid token")
	}
	if info.Name != "test-token" {
		t.Errorf("Name = %q, want %q", info.Name, "test-token")
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("token file should exist: %v", err)
	}
}

func TestJSONTokenStore_DuplicateName(t *testing.T) {
	ts, err := newJSONTokenStore("")
	if err != nil {
		t.Fatalf("newJSONTokenStore: %v", err)
	}

	_, err = ts.Issue("dup", 0, nil)
	if err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	_, err = ts.Issue("dup", 0, nil)
	if err == nil {
		t.Error("duplicate name should fail")
	}
}

func TestJSONTokenStore_Revoke(t *testing.T) {
	ts, err := newJSONTokenStore("")
	if err != nil {
		t.Fatalf("newJSONTokenStore: %v", err)
	}

	token, _ := ts.Issue("revoke-me", 0, nil)
	if err := ts.Revoke("revoke-me"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, ok := ts.Validate(context.Background(), token); ok {
		t.Error("revoked token should not validate")
	}
}

func TestJSONTokenStore_Expiry(t *testing.T) {
	ts, err := newJSONTokenStore("")
	if err != nil {
		t.Fatalf("newJSONTokenStore: %v", err)
	}

	token, _ := ts.Issue("expires", 1*time.Millisecond, nil)
	time.Sleep(5 * time.Millisecond)
	if _, ok := ts.Validate(context.Background(), token); ok {
		t.Error("expired token should not validate")
	}
}

func TestJSONTokenStore_CleanExpired(t *testing.T) {
	ts, err := newJSONTokenStore("")
	if err != nil {
		t.Fatalf("newJSONTokenStore: %v", err)
	}

	ts.Issue("expired1", 1*time.Millisecond, nil)
	ts.Issue("valid", 1*time.Hour, nil)
	time.Sleep(5 * time.Millisecond)

	cleaned := ts.CleanExpired()
	if cleaned != 1 {
		t.Errorf("CleanExpired = %d, want 1", cleaned)
	}

	list := ts.List()
	if len(list) != 1 {
		t.Errorf("List len = %d, want 1", len(list))
	}
}
