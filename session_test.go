package caddymcp

import (
	"testing"
	"time"
)

func TestSessionTable_CreateAndLookup(t *testing.T) {
	st := newSessionTable()
	st.create("sess-1", "code-server", nil)

	entry, ok := st.lookup("sess-1")
	if !ok {
		t.Fatal("session should exist")
	}
	if entry.TunnelName != "code-server" {
		t.Errorf("tunnel = %q, want %q", entry.TunnelName, "code-server")
	}
}

func TestSessionTable_LookupMissing(t *testing.T) {
	st := newSessionTable()
	_, ok := st.lookup("nonexistent")
	if ok {
		t.Error("missing session should not be found")
	}
}

func TestSessionTable_Remove(t *testing.T) {
	st := newSessionTable()
	st.create("sess-1", "code-server", nil)
	st.remove("sess-1")

	_, ok := st.lookup("sess-1")
	if ok {
		t.Error("removed session should not be found")
	}
}

func TestSessionTable_RemoveByTunnel(t *testing.T) {
	st := newSessionTable()
	st.create("sess-1", "code-server", nil)
	st.create("sess-2", "code-server", nil)
	st.create("sess-3", "db-tools", nil)

	removed := st.removeByTunnel("code-server")
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}

	if _, ok := st.lookup("sess-3"); !ok {
		t.Error("db-tools session should still exist")
	}
}

func TestSessionTable_Count(t *testing.T) {
	st := newSessionTable()
	st.create("sess-1", "code-server", nil)
	st.create("sess-2", "code-server", nil)

	if got := st.countForTunnel("code-server"); got != 2 {
		t.Errorf("count = %d, want 2", got)
	}
	if got := st.countForTunnel("unknown"); got != 0 {
		t.Errorf("count = %d, want 0", got)
	}
}

func TestSessionTable_List(t *testing.T) {
	st := newSessionTable()
	st.create("sess-1", "code-server", nil)

	list := st.list()
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
	if list[0].SessionID != "sess-1" {
		t.Errorf("session id = %q, want %q", list[0].SessionID, "sess-1")
	}
}

func TestSessionTable_CreatedAtIsSet(t *testing.T) {
	st := newSessionTable()
	before := time.Now()
	st.create("sess-1", "code-server", nil)

	entry, _ := st.lookup("sess-1")
	if entry.CreatedAt.Before(before) {
		t.Error("CreatedAt should be after test start")
	}
}

func TestSessionTable_MaxSize(t *testing.T) {
	st := newSessionTable()
	st.maxSessions = 2

	if !st.create("sess-1", "a", nil) {
		t.Error("first create should succeed")
	}
	if !st.create("sess-2", "a", nil) {
		t.Error("second create should succeed")
	}
	if st.create("sess-3", "a", nil) {
		t.Error("third create should fail — at capacity")
	}
	if _, ok := st.lookup("sess-3"); ok {
		t.Error("sess-3 should not exist")
	}
}

func TestSessionTable_TTLExpiry(t *testing.T) {
	st := newSessionTable()
	st.sessionTTL = 1 * time.Millisecond

	st.create("sess-1", "code-server", nil)
	time.Sleep(5 * time.Millisecond)

	_, ok := st.lookup("sess-1")
	if ok {
		t.Error("expired session should not be found")
	}
}

func TestSessionTable_ReapExpired(t *testing.T) {
	st := newSessionTable()
	st.sessionTTL = 1 * time.Millisecond

	st.create("sess-1", "code-server", nil)
	st.create("sess-2", "code-server", nil)
	time.Sleep(5 * time.Millisecond)
	st.create("sess-3", "code-server", nil) // fresh, should survive

	reaped := st.reapExpired()
	if reaped != 2 {
		t.Errorf("reapExpired = %d, want 2", reaped)
	}
	if _, ok := st.lookup("sess-3"); !ok {
		t.Error("fresh session should survive reap")
	}
}
