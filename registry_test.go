package caddymcp

import (
	"testing"
)

func TestRegistry_DeclareAndStatus(t *testing.T) {
	r := newTunnelRegistry()
	r.declare("myapp")

	if s := r.status("myapp"); s != stateUnclaimed {
		t.Errorf("status = %v, want unclaimed", s)
	}
	if s := r.status("unknown"); s != stateUndeclared {
		t.Errorf("status = %v, want undeclared", s)
	}
}

func TestRegistry_ClaimAndRelease(t *testing.T) {
	r := newTunnelRegistry()
	r.declare("myapp")

	_, err := r.claim("myapp", nil)
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if s := r.status("myapp"); s != stateClaimed {
		t.Errorf("status = %v, want claimed", s)
	}

	r.release("myapp")
	if s := r.status("myapp"); s != stateUnclaimed {
		t.Errorf("status after release = %v, want unclaimed", s)
	}
}

func TestRegistry_DoubleClaimFails(t *testing.T) {
	r := newTunnelRegistry()
	r.declare("myapp")

	_, err := r.claim("myapp", nil)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	_, err = r.claim("myapp", nil)
	if err == nil {
		t.Error("second claim should fail")
	}
}

func TestRegistry_ClaimUndeclaredFails(t *testing.T) {
	r := newTunnelRegistry()
	_, err := r.claim("unknown", nil)
	if err == nil {
		t.Error("claim on undeclared should fail")
	}
}

func TestRegistry_SetCapabilities(t *testing.T) {
	r := newTunnelRegistry()
	r.declare("myapp")

	caps := &tunnelCapabilities{
		Tools:     []string{"read_file", "search"},
		Resources: []string{"file:///repo/*"},
	}
	r.setCapabilities("myapp", caps)

	got := r.getCapabilities("myapp")
	if got == nil {
		t.Fatal("capabilities should not be nil")
	}
	if len(got.Tools) != 2 {
		t.Errorf("tools len = %d, want 2", len(got.Tools))
	}
}

func TestRegistry_Reconcile(t *testing.T) {
	r := newTunnelRegistry()
	r.declare("keep")
	r.declare("remove")

	declared := map[string]struct{}{"keep": {}}
	r.reconcile(declared)

	if s := r.status("keep"); s != stateUnclaimed {
		t.Error("kept tunnel should remain unclaimed")
	}
	if s := r.status("remove"); s != stateUndeclared {
		t.Error("removed tunnel should be undeclared")
	}
}

func TestRegistry_DeclaredNames(t *testing.T) {
	r := newTunnelRegistry()
	r.declare("a")
	r.declare("b")

	names := r.declaredNames()
	if len(names) != 2 {
		t.Errorf("declaredNames len = %d, want 2", len(names))
	}
}
