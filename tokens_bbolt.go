package caddymcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

var tokenBucket = []byte("tokens")

type bboltTokenStore struct {
	db *bolt.DB
}

var _ TokenStore = (*bboltTokenStore)(nil)

func newBBoltTokenStore(path string) (*bboltTokenStore, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bolt db: %w", err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(tokenBucket)
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init bucket: %w", err)
	}
	return &bboltTokenStore{db: db}, nil
}

func (s *bboltTokenStore) Validate(_ context.Context, token string) (*TokenInfo, bool) {
	hash := hashToken(token)
	var info TokenInfo
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(tokenBucket)
		data := b.Get([]byte(hash))
		if data == nil {
			return fmt.Errorf("not found")
		}
		return json.Unmarshal(data, &info)
	})
	if err != nil {
		return nil, false
	}
	if !info.ExpiresAt.IsZero() && time.Now().After(info.ExpiresAt) {
		return nil, false
	}
	return &info, true
}

func (s *bboltTokenStore) Issue(name string, ttl time.Duration, allowedTunnels []string) (string, error) {
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

	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(tokenBucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var existing TokenInfo
			if json.Unmarshal(v, &existing) == nil && existing.Name == name {
				return fmt.Errorf("token with name %q already exists", name)
			}
		}
		data, err := json.Marshal(info)
		if err != nil {
			return err
		}
		return b.Put([]byte(hash), data)
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

func (s *bboltTokenStore) Revoke(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(tokenBucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var info TokenInfo
			if json.Unmarshal(v, &info) == nil && info.Name == name {
				return b.Delete(k)
			}
		}
		return fmt.Errorf("token %q not found", name)
	})
}

func (s *bboltTokenStore) List() []TokenInfo {
	var result []TokenInfo
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(tokenBucket)
		return b.ForEach(func(_, v []byte) error {
			var info TokenInfo
			if json.Unmarshal(v, &info) == nil {
				result = append(result, TokenInfo{
					Name:           info.Name,
					AllowedTunnels: info.AllowedTunnels,
					CreatedAt:      info.CreatedAt,
					ExpiresAt:      info.ExpiresAt,
				})
			}
			return nil
		})
	}); err != nil {
		fmt.Fprintf(os.Stderr, "caddy-mcp: bbolt List failed: %v\n", err)
	}
	return result
}

func (s *bboltTokenStore) Close() error {
	return s.db.Close()
}

func (s *bboltTokenStore) CleanExpired() int {
	now := time.Now()
	var count int
	if err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(tokenBucket)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var info TokenInfo
			if json.Unmarshal(v, &info) == nil && !info.ExpiresAt.IsZero() && now.After(info.ExpiresAt) {
				if err := b.Delete(k); err != nil {
					fmt.Fprintf(os.Stderr, "caddy-mcp: bbolt delete expired token: %v\n", err)
				}
				count++
			}
		}
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "caddy-mcp: bbolt CleanExpired failed: %v\n", err)
	}
	return count
}
