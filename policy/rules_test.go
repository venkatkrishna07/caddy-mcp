package policy

import (
	"testing"
)

func TestRuleSet_AllowTool(t *testing.T) {
	tests := []struct {
		name      string
		rules     RuleSet
		tool      string
		wantAllow bool
	}{
		{"empty rules allow all", RuleSet{}, "anything", true},
		{"allow list match", RuleSet{AllowTools: []string{"read_file", "search"}}, "read_file", true},
		{"allow list no match", RuleSet{AllowTools: []string{"read_file"}}, "execute_command", false},
		{"deny list match", RuleSet{DenyTools: []string{"execute_command"}}, "execute_command", false},
		{"deny list no match", RuleSet{DenyTools: []string{"execute_command"}}, "read_file", true},
		{"deny overrides allow", RuleSet{AllowTools: []string{"*"}, DenyTools: []string{"execute_command"}}, "execute_command", false},
		{"glob pattern", RuleSet{AllowTools: []string{"read_*"}}, "read_file", true},
		{"glob no match", RuleSet{AllowTools: []string{"read_*"}}, "write_file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rules.AllowTool(tt.tool); got != tt.wantAllow {
				t.Errorf("AllowTool(%q) = %v, want %v", tt.tool, got, tt.wantAllow)
			}
		})
	}
}

func TestRuleSet_AllowResource(t *testing.T) {
	tests := []struct {
		name      string
		rules     RuleSet
		uri       string
		wantAllow bool
	}{
		{"empty allows all", RuleSet{}, "file:///anything", true},
		{"allow match", RuleSet{AllowResources: []string{"file:///repo/*"}}, "file:///repo/main.go", true},
		{"allow no match", RuleSet{AllowResources: []string{"file:///repo/*"}}, "file:///etc/passwd", false},
		{"deny match", RuleSet{DenyResources: []string{"file:///etc/*"}}, "file:///etc/passwd", false},
		{"deny no match", RuleSet{DenyResources: []string{"file:///etc/*"}}, "file:///repo/main.go", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rules.AllowResource(tt.uri); got != tt.wantAllow {
				t.Errorf("AllowResource(%q) = %v, want %v", tt.uri, got, tt.wantAllow)
			}
		})
	}
}

func TestIntersect(t *testing.T) {
	tunnel := RuleSet{AllowTools: []string{"read_file", "search", "execute_command"}}
	user := RuleSet{AllowTools: []string{"read_file", "search"}, DenyTools: []string{"execute_command"}}

	merged := Intersect(tunnel, user)

	if merged.AllowTool("read_file") != true {
		t.Error("read_file should be allowed")
	}
	if merged.AllowTool("execute_command") != false {
		t.Error("execute_command should be denied (user denies it)")
	}
}

func TestIntersect_AllowListIntersection(t *testing.T) {
	a := RuleSet{AllowTools: []string{"read_file", "search"}}
	b := RuleSet{AllowTools: []string{"search", "write_file"}}

	merged := Intersect(a, b)

	if !merged.AllowTool("search") {
		t.Error("search should be allowed (in both)")
	}
	if merged.AllowTool("read_file") {
		t.Error("read_file should be denied (only in a)")
	}
	if merged.AllowTool("write_file") {
		t.Error("write_file should be denied (only in b)")
	}
}

func TestIntersect_AllowListGlob(t *testing.T) {
	a := RuleSet{AllowTools: []string{"read_*"}}
	b := RuleSet{AllowTools: []string{"read_file", "read_dir", "write_file"}}

	merged := Intersect(a, b)

	if !merged.AllowTool("read_file") {
		t.Error("read_file should be allowed (matches read_* and in b)")
	}
	if !merged.AllowTool("read_dir") {
		t.Error("read_dir should be allowed (matches read_* and in b)")
	}
	if merged.AllowTool("write_file") {
		t.Error("write_file should be denied (not matched by read_*)")
	}
}

func TestIntersect_EmptyAllowMeansAll(t *testing.T) {
	a := RuleSet{}
	b := RuleSet{AllowTools: []string{"read_file"}}

	merged := Intersect(a, b)

	if !merged.AllowTool("read_file") {
		t.Error("read_file should be allowed")
	}
	if merged.AllowTool("write_file") {
		t.Error("write_file should be denied (b restricts)")
	}
}

func TestLoadPolicyFile(t *testing.T) {
	data := `{
		"policies": [
			{
				"users": ["alice", "team-a-*"],
				"allow_tools": ["read_file"],
				"deny_tools": ["execute_command"],
				"allow_resources": ["file:///repo/*"]
			}
		]
	}`

	pf, err := parsePolicyFile([]byte(data))
	if err != nil {
		t.Fatalf("parsePolicyFile: %v", err)
	}
	if len(pf.Policies) != 1 {
		t.Fatalf("policies len = %d, want 1", len(pf.Policies))
	}

	rules := pf.RulesForUser("alice")
	if !rules.AllowTool("read_file") {
		t.Error("alice should be allowed read_file")
	}
	if rules.AllowTool("execute_command") {
		t.Error("alice should not be allowed execute_command")
	}

	rules2 := pf.RulesForUser("bob")
	if rules2.AllowTool("anything") {
		t.Error("bob has no matching policy, should deny all")
	}
}
