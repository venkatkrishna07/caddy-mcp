package caddymcp

import "testing"

func TestValidateTunnelName(t *testing.T) {
	valid := []string{"myapp", "code-server", "db_tools", "a", "a1", "my-app-123"}
	for _, name := range valid {
		if err := validateTunnelName(name); err != nil {
			t.Errorf("validateTunnelName(%q) = %v, want nil", name, err)
		}
	}

	invalid := []string{
		"",
		"-starts-with-hyphen",
		"ends-with-hyphen-",
		"_starts_underscore",
		"HAS-CAPS",
		"has spaces",
		"has.dots",
		"has/slashes",
		string(make([]byte, 64)),
		"a@b",
	}
	for _, name := range invalid {
		if err := validateTunnelName(name); err == nil {
			t.Errorf("validateTunnelName(%q) = nil, want error", name)
		}
	}
}

func TestValidateSessionID(t *testing.T) {
	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	}
	for _, id := range valid {
		if err := validateSessionID(id); err != nil {
			t.Errorf("validateSessionID(%q) = %v, want nil", id, err)
		}
	}

	invalid := []string{
		"",
		"not-a-uuid",
		"550e8400e29b41d4a716446655440000",
		"550e8400-e29b-41d4-a716-44665544000g",
	}
	for _, id := range invalid {
		if err := validateSessionID(id); err == nil {
			t.Errorf("validateSessionID(%q) = nil, want error", id)
		}
	}
}
