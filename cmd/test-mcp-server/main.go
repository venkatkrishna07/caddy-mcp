// Full MCP test server implementing Streamable HTTP transport.
// Supports: tools, resources, prompts, SSE notifications, logging, completion, ping.
// Usage: go run ./cmd/test-mcp-server/ --port 9090
package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SSE client tracking
type sseClient struct {
	events    chan []byte
	sessionID string
}

var (
	sessions    = map[string]bool{}
	sessionsMu  sync.Mutex
	sseClients  = map[string]*sseClient{}
	sseClientMu sync.Mutex
)

// Sample resources
var resources = map[string]string{
	"file:///readme.md":      "# Test MCP Server\n\nThis is a test README exposed as an MCP resource.",
	"file:///config.json":    `{"env": "test", "version": "0.1.0", "features": ["tools", "resources", "prompts"]}`,
	"file:///notes/todo.txt": "1. Test echo tool\n2. Test add tool\n3. Verify SSE streaming\n4. Check resource reads",
}

// Sample prompts
var prompts = map[string]map[string]any{
	"summarize": {
		"name":        "summarize",
		"description": "Summarize the given text concisely",
		"arguments": []map[string]any{
			{"name": "text", "description": "Text to summarize", "required": true},
			{"name": "style", "description": "Summary style: brief, detailed, or bullets", "required": false},
		},
	},
	"code-review": {
		"name":        "code-review",
		"description": "Review code for bugs, style, and improvements",
		"arguments": []map[string]any{
			{"name": "code", "description": "Code to review", "required": true},
			{"name": "language", "description": "Programming language", "required": false},
		},
	},
}

func main() {
	port := flag.Int("port", 9090, "listen port")
	flag.Parse()

	http.HandleFunc("/mcp", handleRequest)
	http.HandleFunc("/", handleRequest)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("test MCP server listening on %s (tools, resources, prompts, SSE)", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Authorization")
	w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Well-known endpoints Claude Code checks
	if r.URL.Path == "/.well-known/oauth-protected-resource" ||
		r.URL.Path == "/.well-known/oauth-authorization-server" {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	switch r.Method {
	case http.MethodPost:
		handleMCP(w, r)
	case http.MethodGet:
		handleSSE(w, r)
	default:
		http.Error(w, "POST or GET only", http.StatusMethodNotAllowed)
	}
}

func handleMCP(w http.ResponseWriter, r *http.Request) {
	var req jsonrpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nil, -32700, "parse error")
		return
	}

	log.Printf("MCP request: method=%s id=%s", req.Method, string(req.ID))

	switch req.Method {
	// --- Lifecycle ---
	case "initialize":
		handleInitialize(w, req)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "ping":
		writeResult(w, req.ID, map[string]any{})

	// --- Tools ---
	case "tools/list":
		handleToolsList(w, req)
	case "tools/call":
		handleToolCall(w, r, req)

	// --- Resources ---
	case "resources/list":
		handleResourcesList(w, req)
	case "resources/read":
		handleResourcesRead(w, req)
	case "resources/templates/list":
		handleResourceTemplates(w, req)
	case "resources/subscribe":
		handleResourceSubscribe(w, req)

	// --- Prompts ---
	case "prompts/list":
		handlePromptsList(w, req)
	case "prompts/get":
		handlePromptsGet(w, req)

	// --- Completion ---
	case "completion/complete":
		handleCompletion(w, req)

	// --- Logging ---
	case "logging/setLevel":
		handleSetLogLevel(w, req)

	default:
		writeError(w, req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
	}
}

// --- Lifecycle ---

func handleInitialize(w http.ResponseWriter, req jsonrpcRequest) {
	sessionID := newSession()
	w.Header().Set("Mcp-Session-Id", sessionID)
	writeResult(w, req.ID, map[string]any{
		"protocolVersion": "2025-03-26",
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": true},
			"resources": map[string]any{"subscribe": true, "listChanged": true},
			"prompts":   map[string]any{"listChanged": true},
			"logging":   map[string]any{},
		},
		"serverInfo": map[string]any{
			"name":    "test-mcp-server",
			"version": "0.1.0",
		},
	})
}

// --- Tools ---

func handleToolsList(w http.ResponseWriter, req jsonrpcRequest) {
	writeResult(w, req.ID, map[string]any{
		"tools": []map[string]any{
			{
				"name":        "echo",
				"description": "Echo back the input message",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"message": map[string]any{"type": "string", "description": "Message to echo"},
					},
					"required": []string{"message"},
				},
			},
			{
				"name":        "add",
				"description": "Add two numbers",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"a": map[string]any{"type": "number"},
						"b": map[string]any{"type": "number"},
					},
					"required": []string{"a", "b"},
				},
			},
			{
				"name":        "current_time",
				"description": "Get the current server time",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
			{
				"name":        "slow_task",
				"description": "Simulates a slow task with progress notifications (takes 3 seconds)",
				"inputSchema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"steps": map[string]any{"type": "number", "description": "Number of steps (default 3)"},
					},
				},
			},
			{
				"name":        "list_resources",
				"description": "List available resource URIs",
				"inputSchema": map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
		},
	})
}

func handleToolCall(w http.ResponseWriter, r *http.Request, req jsonrpcRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, -32602, "invalid params")
		return
	}

	switch params.Name {
	case "echo":
		var args struct {
			Message string `json:"message"`
		}
		json.Unmarshal(params.Arguments, &args)
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf("Echo: %s", args.Message)},
			},
		})

	case "add":
		var args struct {
			A float64 `json:"a"`
			B float64 `json:"b"`
		}
		json.Unmarshal(params.Arguments, &args)
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf("%g + %g = %g", args.A, args.B, args.A+args.B)},
			},
		})

	case "current_time":
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": time.Now().Format(time.RFC3339)},
			},
		})

	case "slow_task":
		var args struct {
			Steps float64 `json:"steps"`
		}
		json.Unmarshal(params.Arguments, &args)
		steps := int(args.Steps)
		if steps <= 0 {
			steps = 3
		}

		// Send progress notifications via SSE if session exists
		sessionID := r.Header.Get("Mcp-Session-Id")
		for i := 1; i <= steps; i++ {
			sendSSENotification(sessionID, map[string]any{
				"jsonrpc": "2.0",
				"method":  "notifications/progress",
				"params": map[string]any{
					"progressToken": req.ID,
					"progress":      i,
					"total":         steps,
					"message":       fmt.Sprintf("Step %d of %d", i, steps),
				},
			})
			// Also send a log notification
			sendSSENotification(sessionID, map[string]any{
				"jsonrpc": "2.0",
				"method":  "notifications/message",
				"params": map[string]any{
					"level":  "info",
					"logger": "slow_task",
					"data":   fmt.Sprintf("Processing step %d/%d", i, steps),
				},
			})
			time.Sleep(time.Second)
		}

		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf("Completed %d steps successfully", steps)},
			},
		})

	case "list_resources":
		var uris []string
		for uri := range resources {
			uris = append(uris, uri)
		}
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf("Available resources: %s", strings.Join(uris, ", "))},
			},
		})

	default:
		writeResult(w, req.ID, map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": fmt.Sprintf("Unknown tool: %s", params.Name)},
			},
			"isError": true,
		})
	}
}

// --- Resources ---

func handleResourcesList(w http.ResponseWriter, req jsonrpcRequest) {
	var list []map[string]any
	for uri, content := range resources {
		mimeType := "text/plain"
		if strings.HasSuffix(uri, ".json") {
			mimeType = "application/json"
		} else if strings.HasSuffix(uri, ".md") {
			mimeType = "text/markdown"
		}
		list = append(list, map[string]any{
			"uri":      uri,
			"name":     uri[strings.LastIndex(uri, "/")+1:],
			"mimeType": mimeType,
			"size":     len(content),
		})
	}
	writeResult(w, req.ID, map[string]any{"resources": list})
}

func handleResourcesRead(w http.ResponseWriter, req jsonrpcRequest) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, -32602, "invalid params")
		return
	}
	content, ok := resources[params.URI]
	if !ok {
		writeError(w, req.ID, -32602, fmt.Sprintf("resource not found: %s", params.URI))
		return
	}

	mimeType := "text/plain"
	if strings.HasSuffix(params.URI, ".json") {
		mimeType = "application/json"
	} else if strings.HasSuffix(params.URI, ".md") {
		mimeType = "text/markdown"
	}

	writeResult(w, req.ID, map[string]any{
		"contents": []map[string]any{
			{
				"uri":      params.URI,
				"mimeType": mimeType,
				"text":     content,
			},
		},
	})
}

func handleResourceTemplates(w http.ResponseWriter, req jsonrpcRequest) {
	writeResult(w, req.ID, map[string]any{
		"resourceTemplates": []map[string]any{
			{
				"uriTemplate": "file:///notes/{name}.txt",
				"name":        "Notes",
				"description": "Access notes by name",
			},
		},
	})
}

func handleResourceSubscribe(w http.ResponseWriter, req jsonrpcRequest) {
	var params struct {
		URI string `json:"uri"`
	}
	json.Unmarshal(req.Params, &params)
	log.Printf("resource subscription: %s", params.URI)
	writeResult(w, req.ID, map[string]any{})
}

// --- Prompts ---

func handlePromptsList(w http.ResponseWriter, req jsonrpcRequest) {
	var list []map[string]any
	for _, p := range prompts {
		list = append(list, p)
	}
	writeResult(w, req.ID, map[string]any{"prompts": list})
}

func handlePromptsGet(w http.ResponseWriter, req jsonrpcRequest) {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, -32602, "invalid params")
		return
	}

	switch params.Name {
	case "summarize":
		text := params.Arguments["text"]
		style := params.Arguments["style"]
		if style == "" {
			style = "brief"
		}
		writeResult(w, req.ID, map[string]any{
			"description": fmt.Sprintf("Summarize text (%s style)", style),
			"messages": []map[string]any{
				{
					"role": "user",
					"content": map[string]any{
						"type": "text",
						"text": fmt.Sprintf("Please provide a %s summary of the following text:\n\n%s", style, text),
					},
				},
			},
		})

	case "code-review":
		code := params.Arguments["code"]
		lang := params.Arguments["language"]
		if lang == "" {
			lang = "unknown"
		}
		writeResult(w, req.ID, map[string]any{
			"description": fmt.Sprintf("Code review (%s)", lang),
			"messages": []map[string]any{
				{
					"role": "user",
					"content": map[string]any{
						"type": "text",
						"text": fmt.Sprintf("Please review this %s code for bugs, style issues, and improvements:\n\n```%s\n%s\n```", lang, lang, code),
					},
				},
			},
		})

	default:
		writeError(w, req.ID, -32602, fmt.Sprintf("unknown prompt: %s", params.Name))
	}
}

// --- Completion ---

func handleCompletion(w http.ResponseWriter, req jsonrpcRequest) {
	var params struct {
		Ref struct {
			Type string `json:"type"`
			Name string `json:"name"`
		} `json:"ref"`
		Argument struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"argument"`
	}
	json.Unmarshal(req.Params, &params)

	var values []string
	switch {
	case params.Ref.Type == "ref/prompt" && params.Argument.Name == "style":
		all := []string{"brief", "detailed", "bullets"}
		for _, v := range all {
			if strings.HasPrefix(v, params.Argument.Value) {
				values = append(values, v)
			}
		}
	case params.Ref.Type == "ref/prompt" && params.Argument.Name == "language":
		all := []string{"go", "python", "javascript", "typescript", "rust", "java"}
		for _, v := range all {
			if strings.HasPrefix(v, params.Argument.Value) {
				values = append(values, v)
			}
		}
	case params.Ref.Type == "ref/resource":
		for uri := range resources {
			if strings.HasPrefix(uri, params.Argument.Value) {
				values = append(values, uri)
			}
		}
	}

	writeResult(w, req.ID, map[string]any{
		"completion": map[string]any{
			"values":  values,
			"hasMore": false,
		},
	})
}

// --- Logging ---

func handleSetLogLevel(w http.ResponseWriter, req jsonrpcRequest) {
	var params struct {
		Level string `json:"level"`
	}
	json.Unmarshal(req.Params, &params)
	log.Printf("log level set to: %s", params.Level)
	writeResult(w, req.ID, map[string]any{})
}

// --- SSE ---

func handleSSE(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		http.Error(w, "Mcp-Session-Id header required", http.StatusBadRequest)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := &sseClient{
		events:    make(chan []byte, 64),
		sessionID: sessionID,
	}

	sseClientMu.Lock()
	sseClients[sessionID] = client
	sseClientMu.Unlock()

	log.Printf("SSE client connected: session=%s", sessionID)

	defer func() {
		sseClientMu.Lock()
		delete(sseClients, sessionID)
		sseClientMu.Unlock()
		log.Printf("SSE client disconnected: session=%s", sessionID)
	}()

	// Send initial keepalive
	fmt.Fprintf(w, ": keepalive\n\n")
	flusher.Flush()

	// Keepalive ticker
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-client.events:
			fmt.Fprintf(w, "data: %s\n\n", event)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func sendSSENotification(sessionID string, notification map[string]any) {
	if sessionID == "" {
		return
	}
	sseClientMu.Lock()
	client, ok := sseClients[sessionID]
	sseClientMu.Unlock()
	if !ok {
		return
	}
	data, err := json.Marshal(notification)
	if err != nil {
		return
	}
	select {
	case client.events <- data:
	default:
		log.Printf("SSE event dropped for session %s (buffer full)", sessionID)
	}
}

// --- Helpers ---

func writeResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonrpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonrpcError{Code: code, Message: msg},
	})
}

func newSession() string {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	id := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	sessions[id] = true
	return id
}
