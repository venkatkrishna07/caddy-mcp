package policy

import (
	"encoding/json"
	"fmt"
)

const (
	ModeTransparent = "transparent"
	ModeAware       = "aware"
)

const (
	ActionAllow = "allow"
	ActionDeny  = "deny"
)

// Decision is the result of a policy evaluation.
type Decision struct {
	Action   string
	Reason   string
	Method   string
	Tool     string
	Resource string
}

// Engine evaluates MCP requests against tunnel and user policies.
type Engine struct {
	Mode        string
	TunnelRules RuleSet
	UserPolicy  *PolicyFile
}

// Evaluate checks a request body against policies.
func (e *Engine) Evaluate(user string, body []byte) Decision {
	if e.Mode != ModeAware {
		return Decision{Action: ActionAllow, Reason: "transparent"}
	}

	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		Method  string          `json:"method"`
		ID      json.RawMessage `json:"id,omitempty"`
		Params  json.RawMessage `json:"params,omitempty"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		return Decision{Action: ActionDeny, Reason: fmt.Sprintf("malformed JSON-RPC: %v", err)}
	}

	switch req.Method {
	case "tools/call":
		return e.evaluateToolCall(user, req.Method, req.Params)
	case "resources/read", "resources/subscribe":
		return e.evaluateResourceAccess(user, req.Method, req.Params)
	default:
		return Decision{Action: ActionAllow, Method: req.Method, Reason: "non-restricted method"}
	}
}

func (e *Engine) evaluateToolCall(user, method string, params json.RawMessage) Decision {
	var p struct {
		Name string `json:"name"`
	}
	if params != nil {
		if err := json.Unmarshal(params, &p); err != nil {
			return Decision{Action: ActionDeny, Method: method, Reason: "malformed tool params"}
		}
	}
	if p.Name == "" {
		return Decision{Action: ActionDeny, Method: method, Reason: "missing tool name"}
	}

	effectiveRules := e.effectiveRules(user)

	if !effectiveRules.AllowTool(p.Name) {
		return Decision{
			Action: ActionDeny,
			Method: method,
			Tool:   p.Name,
			Reason: "tool denied by policy",
		}
	}
	return Decision{
		Action: ActionAllow,
		Method: method,
		Tool:   p.Name,
		Reason: "tool allowed",
	}
}

func (e *Engine) evaluateResourceAccess(user, method string, params json.RawMessage) Decision {
	var p struct {
		URI string `json:"uri"`
	}
	if params != nil {
		if err := json.Unmarshal(params, &p); err != nil {
			return Decision{Action: ActionDeny, Method: method, Reason: "malformed resource params"}
		}
	}
	if p.URI == "" {
		return Decision{Action: ActionDeny, Method: method, Reason: "missing resource URI"}
	}

	effectiveRules := e.effectiveRules(user)

	if !effectiveRules.AllowResource(p.URI) {
		return Decision{
			Action:   ActionDeny,
			Method:   method,
			Resource: p.URI,
			Reason:   "resource denied by policy",
		}
	}
	return Decision{
		Action:   ActionAllow,
		Method:   method,
		Resource: p.URI,
		Reason:   "resource allowed",
	}
}

func (e *Engine) effectiveRules(user string) RuleSet {
	rules := e.TunnelRules
	if e.UserPolicy != nil && user != "" {
		userRules := e.UserPolicy.RulesForUser(user)
		rules = Intersect(rules, userRules)
	}
	return rules
}
