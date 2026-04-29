package policy

import (
	"testing"
)

func TestEngine_Evaluate_TransparentMode(t *testing.T) {
	e := &Engine{Mode: ModeTransparent}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"execute_command"}}`)
	decision := e.Evaluate("alice", body)
	if decision.Action != ActionAllow {
		t.Errorf("transparent mode should always allow, got %v", decision.Action)
	}
}

func TestEngine_Evaluate_AwareMode_AllowTool(t *testing.T) {
	e := &Engine{
		Mode:        ModeAware,
		TunnelRules: RuleSet{AllowTools: []string{"read_file", "search"}},
	}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"read_file"}}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionAllow {
		t.Errorf("allowed tool should pass, got %v", decision.Action)
	}
}

func TestEngine_Evaluate_AwareMode_DenyTool(t *testing.T) {
	e := &Engine{
		Mode:        ModeAware,
		TunnelRules: RuleSet{DenyTools: []string{"execute_command"}},
	}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"execute_command"}}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionDeny {
		t.Errorf("denied tool should be blocked, got %v", decision.Action)
	}
}

func TestEngine_Evaluate_AwareMode_DenyResource(t *testing.T) {
	e := &Engine{
		Mode:        ModeAware,
		TunnelRules: RuleSet{DenyResources: []string{"file:///etc/*"}},
	}
	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","id":1,"params":{"uri":"file:///etc/passwd"}}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionDeny {
		t.Error("denied resource should be blocked")
	}
}

func TestEngine_Evaluate_NonMCPMethod_AlwaysAllows(t *testing.T) {
	e := &Engine{
		Mode:        ModeAware,
		TunnelRules: RuleSet{DenyTools: []string{"*"}},
	}
	body := []byte(`{"jsonrpc":"2.0","method":"initialize","id":1}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionAllow {
		t.Error("initialize should always be allowed")
	}
}

func TestEngine_Evaluate_MalformedJSON(t *testing.T) {
	e := &Engine{Mode: ModeAware}
	decision := e.Evaluate("", []byte("not json"))
	if decision.Action != ActionDeny {
		t.Error("malformed JSON should be denied in aware mode")
	}
}

func TestEngine_Evaluate_WithUserPolicy(t *testing.T) {
	pf := &PolicyFile{
		Policies: []PolicyEntry{
			{
				Users:     []string{"alice"},
				DenyTools: []string{"execute_command"},
			},
		},
	}
	e := &Engine{
		Mode:       ModeAware,
		UserPolicy: pf,
	}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"execute_command"}}`)
	decision := e.Evaluate("alice", body)
	if decision.Action != ActionDeny {
		t.Error("user policy should deny execute_command for alice")
	}
}

func TestEngine_Evaluate_MalformedToolParams(t *testing.T) {
	e := &Engine{Mode: ModeAware}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":"not an object"}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionDeny {
		t.Error("malformed tool params should be denied")
	}
}

func TestEngine_Evaluate_EmptyToolName(t *testing.T) {
	e := &Engine{Mode: ModeAware}
	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{}}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionDeny {
		t.Error("empty tool name should be denied")
	}
}

func TestEngine_Evaluate_MalformedResourceParams(t *testing.T) {
	e := &Engine{Mode: ModeAware}
	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","id":1,"params":"bad"}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionDeny {
		t.Error("malformed resource params should be denied")
	}
}

func TestEngine_Evaluate_EmptyResourceURI(t *testing.T) {
	e := &Engine{Mode: ModeAware}
	body := []byte(`{"jsonrpc":"2.0","method":"resources/read","id":1,"params":{}}`)
	decision := e.Evaluate("", body)
	if decision.Action != ActionDeny {
		t.Error("empty resource URI should be denied")
	}
}
