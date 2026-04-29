package caddymcp

import (
	"encoding/json"
	"fmt"
)

const (
	MCPMethodInitialize    = "initialize"
	MCPMethodToolsCall     = "tools/call"
	MCPMethodToolsList     = "tools/list"
	MCPMethodResourcesRead = "resources/read"
	MCPMethodResourcesList = "resources/list"
	MCPMethodResourcesSub  = "resources/subscribe"
	MCPMethodPromptsList   = "prompts/list"
	MCPMethodPromptsGet    = "prompts/get"
)

const MCPSessionHeader = "Mcp-Session-Id"

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func parseMCPRequest(body []byte) (*mcpRequest, error) {
	var req mcpRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("parse JSON-RPC: %w", err)
	}
	return &req, nil
}

func (r *mcpRequest) ToolName() string {
	if r.Params == nil {
		return ""
	}
	var params struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(r.Params, &params) != nil {
		return ""
	}
	return params.Name
}

func (r *mcpRequest) ResourceURI() string {
	if r.Params == nil {
		return ""
	}
	var params struct {
		URI string `json:"uri"`
	}
	if json.Unmarshal(r.Params, &params) != nil {
		return ""
	}
	return params.URI
}

func mcpErrorResponse(id json.RawMessage, code int, message string) []byte {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"internal error"}}`)
	}
	return data
}
