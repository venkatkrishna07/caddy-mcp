package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// RuleSet defines allow/deny lists for tools and resources.
type RuleSet struct {
	AllowTools     []string `json:"allow_tools,omitempty"`
	DenyTools      []string `json:"deny_tools,omitempty"`
	AllowResources []string `json:"allow_resources,omitempty"`
	DenyResources  []string `json:"deny_resources,omitempty"`
}

// AllowTool checks if a tool name is permitted. Deny takes precedence. Empty lists = allow all.
func (rs RuleSet) AllowTool(name string) bool {
	if matchAny(rs.DenyTools, name) {
		return false
	}
	if len(rs.AllowTools) == 0 {
		return true
	}
	return matchAny(rs.AllowTools, name)
}

// AllowResource checks if a resource URI is permitted.
func (rs RuleSet) AllowResource(uri string) bool {
	if matchAny(rs.DenyResources, uri) {
		return false
	}
	if len(rs.AllowResources) == 0 {
		return true
	}
	return matchAny(rs.AllowResources, uri)
}

func matchAny(patterns []string, value string) bool {
	for _, p := range patterns {
		if matched, err := filepath.Match(p, value); err == nil && matched {
			return true
		}
	}
	return false
}

// Intersect merges two rule sets with most-restrictive-wins semantics.
func Intersect(a, b RuleSet) RuleSet {
	return RuleSet{
		AllowTools:     mergeAllow(a.AllowTools, b.AllowTools),
		DenyTools:      mergeDeny(a.DenyTools, b.DenyTools),
		AllowResources: mergeAllow(a.AllowResources, b.AllowResources),
		DenyResources:  mergeDeny(a.DenyResources, b.DenyResources),
	}
}

func mergeAllow(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	// Real intersection: keep entries from a that match any pattern in b, and vice versa
	var result []string
	seen := make(map[string]struct{})
	for _, av := range a {
		for _, bv := range b {
			if av == bv {
				if _, ok := seen[av]; !ok {
					seen[av] = struct{}{}
					result = append(result, av)
				}
			}
		}
	}
	// Also check glob matches both directions
	for _, av := range a {
		if _, ok := seen[av]; ok {
			continue
		}
		if matchAny(b, av) {
			seen[av] = struct{}{}
			result = append(result, av)
		}
	}
	for _, bv := range b {
		if _, ok := seen[bv]; ok {
			continue
		}
		if matchAny(a, bv) {
			seen[bv] = struct{}{}
			result = append(result, bv)
		}
	}
	return result
}

func mergeDeny(a, b []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, v := range a {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	for _, v := range b {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			result = append(result, v)
		}
	}
	return result
}

// --- Policy file ---

type PolicyFile struct {
	Policies []PolicyEntry `json:"policies"`
}

type PolicyEntry struct {
	Users          []string `json:"users"`
	AllowTools     []string `json:"allow_tools,omitempty"`
	DenyTools      []string `json:"deny_tools,omitempty"`
	AllowResources []string `json:"allow_resources,omitempty"`
	DenyResources  []string `json:"deny_resources,omitempty"`
}

func parsePolicyFile(data []byte) (*PolicyFile, error) {
	var pf PolicyFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}
	return &pf, nil
}

// LoadPolicyFile parses policy JSON data.
func LoadPolicyFile(data []byte) (*PolicyFile, error) {
	return parsePolicyFile(data)
}

// RulesForUser returns the merged rule set for the given user identity.
// If no policy matches, denies everything — unknown users get no access.
func (pf *PolicyFile) RulesForUser(user string) RuleSet {
	var result RuleSet
	matched := false
	for _, entry := range pf.Policies {
		if matchAny(entry.Users, user) {
			entryRules := RuleSet{
				AllowTools:     entry.AllowTools,
				DenyTools:      entry.DenyTools,
				AllowResources: entry.AllowResources,
				DenyResources:  entry.DenyResources,
			}
			if matched {
				result = Intersect(result, entryRules)
			} else {
				result = entryRules
				matched = true
			}
		}
	}
	if !matched {
		// Unknown user — deny all tools and resources
		return RuleSet{
			DenyTools:     []string{"*"},
			DenyResources: []string{"*"},
		}
	}
	return result
}
