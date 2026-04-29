package caddymcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TokenInfo holds metadata for a single token.
type TokenInfo struct {
	Name           string    `json:"name"`
	TokenHash      string    `json:"token_hash,omitempty"`
	AllowedTunnels []string  `json:"allowed_tunnels,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
}

// TokenStore abstracts token persistence.
type TokenStore interface {
	Validate(ctx context.Context, token string) (*TokenInfo, bool)
	Issue(name string, ttl time.Duration, allowedTunnels []string) (string, error)
	Revoke(name string) error
	List() []TokenInfo
	Close() error
	CleanExpired() int
}

func checkACL(info *TokenInfo, tunnelName string) bool {
	if len(info.AllowedTunnels) == 0 {
		return true
	}
	for _, pattern := range info.AllowedTunnels {
		if matched, err := filepath.Match(pattern, tunnelName); err == nil && matched {
			return true
		}
	}
	return false
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return "mcp_" + hex.EncodeToString(b), nil
}

// --- JSON file implementation ---

type jsonTokenStore struct {
	mu     sync.RWMutex
	saveMu sync.Mutex
	path   string
	tokens map[string]*TokenInfo
}

var _ TokenStore = (*jsonTokenStore)(nil)

func newJSONTokenStore(path string) (*jsonTokenStore, error) {
	ts := &jsonTokenStore{
		path:   path,
		tokens: make(map[string]*TokenInfo),
	}
	if path != "" {
		if err := ts.load(); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("load token store: %w", err)
		}
	}
	return ts, nil
}

func (ts *jsonTokenStore) load() error {
	ts.saveMu.Lock()
	defer ts.saveMu.Unlock()
	data, err := os.ReadFile(ts.path)
	if err != nil {
		return err
	}
	var file tokenFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse token file: %w", err)
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.tokens = make(map[string]*TokenInfo, len(file.Tokens))
	for hash, info := range file.Tokens {
		info.TokenHash = hash
		ts.tokens[hash] = info
	}
	return nil
}

type tokenFile struct {
	Tokens map[string]*TokenInfo `json:"tokens"`
}

func (ts *jsonTokenStore) save() error {
	if ts.path == "" {
		return nil
	}
	ts.saveMu.Lock()
	defer ts.saveMu.Unlock()

	ts.mu.RLock()
	file := tokenFile{Tokens: make(map[string]*TokenInfo, len(ts.tokens))}
	for hash, info := range ts.tokens {
		file.Tokens[hash] = info
	}
	ts.mu.RUnlock()

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token file: %w", err)
	}
	dir := filepath.Dir(ts.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create token dir: %w", err)
	}
	tmp := ts.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return os.Rename(tmp, ts.path)
}

func (ts *jsonTokenStore) Validate(_ context.Context, token string) (*TokenInfo, bool) {
	hash := hashToken(token)
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	info, ok := ts.tokens[hash]
	if !ok {
		return nil, false
	}
	if !info.ExpiresAt.IsZero() && time.Now().After(info.ExpiresAt) {
		return nil, false
	}
	return info, true
}

func (ts *jsonTokenStore) Issue(name string, ttl time.Duration, allowedTunnels []string) (string, error) {
	token, err := generateToken()
	if err != nil {
		return "", err
	}
	hash := hashToken(token)
	info := &TokenInfo{
		Name:           name,
		TokenHash:      hash,
		AllowedTunnels: allowedTunnels,
		CreatedAt:      time.Now().UTC(),
	}
	if ttl > 0 {
		info.ExpiresAt = time.Now().Add(ttl).UTC()
	}
	ts.mu.Lock()
	for _, existing := range ts.tokens {
		if existing.Name == name {
			ts.mu.Unlock()
			return "", fmt.Errorf("token with name %q already exists", name)
		}
	}
	ts.tokens[hash] = info
	ts.mu.Unlock()

	if err := ts.save(); err != nil {
		ts.mu.Lock()
		delete(ts.tokens, hash)
		ts.mu.Unlock()
		return "", fmt.Errorf("persist token: %w", err)
	}
	return token, nil
}

func (ts *jsonTokenStore) Revoke(name string) error {
	ts.mu.Lock()
	var foundHash string
	for hash, info := range ts.tokens {
		if info.Name == name {
			foundHash = hash
			break
		}
	}
	if foundHash == "" {
		ts.mu.Unlock()
		return fmt.Errorf("token %q not found", name)
	}
	removed := ts.tokens[foundHash]
	delete(ts.tokens, foundHash)
	ts.mu.Unlock()

	if err := ts.save(); err != nil {
		ts.mu.Lock()
		ts.tokens[foundHash] = removed
		ts.mu.Unlock()
		return fmt.Errorf("persist revocation: %w", err)
	}
	return nil
}

func (ts *jsonTokenStore) List() []TokenInfo {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	result := make([]TokenInfo, 0, len(ts.tokens))
	for _, info := range ts.tokens {
		result = append(result, TokenInfo{
			Name:           info.Name,
			AllowedTunnels: info.AllowedTunnels,
			CreatedAt:      info.CreatedAt,
			ExpiresAt:      info.ExpiresAt,
		})
	}
	return result
}

func (ts *jsonTokenStore) Close() error { return nil }

func (ts *jsonTokenStore) CleanExpired() int {
	now := time.Now()
	ts.mu.Lock()
	var expired []string
	for hash, info := range ts.tokens {
		if !info.ExpiresAt.IsZero() && now.After(info.ExpiresAt) {
			expired = append(expired, hash)
		}
	}
	for _, hash := range expired {
		delete(ts.tokens, hash)
	}
	ts.mu.Unlock()

	if len(expired) > 0 {
		if err := ts.save(); err != nil {
			fmt.Fprintf(os.Stderr, "caddy-mcp: failed to persist token cleanup: %v\n", err)
		}
	}
	return len(expired)
}
