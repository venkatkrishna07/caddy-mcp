// Package proto defines the caddy-mcp wire protocol.
//
// Control stream: 4-byte big-endian length prefix followed by a JSON-encoded ControlMsg.
// Data streams:   24-byte tunnel header [tunnelID uint32 BE][sessionID 16 bytes][reserved 4 bytes].
package proto

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"go.uber.org/zap/zapcore"
)

const (
	TypeAuth         = "auth"
	TypeAuthOK       = "auth_ok"
	TypeRegister     = "register"
	TypeRegisterOK   = "register_ok"
	TypeError        = "error"
	TypeHeartbeat    = "heartbeat"
	TypeCapabilities = "capabilities"
)

// TunnelHeaderSize is the fixed size of the data stream header.
const TunnelHeaderSize = 24

// TunnelRegistration describes a tunnel the client wants to register.
type TunnelRegistration struct {
	Name string `json:"name"`
}

// ControlMsg is the JSON payload exchanged on the control stream.
type ControlMsg struct {
	Type              string               `json:"type"`
	Token             string               `json:"token,omitempty"`
	Tunnels           []TunnelRegistration  `json:"tunnels,omitempty"`
	RegisteredTunnels []string              `json:"registered_tunnels,omitempty"`
	TunnelID          uint32                `json:"tunnel_id,omitempty"`
	Error             string                `json:"error,omitempty"`
	Tunnel            string                `json:"tunnel,omitempty"`
	Tools             []string              `json:"tools,omitempty"`
	Resources         []string              `json:"resources,omitempty"`
	Prompts           []string              `json:"prompts,omitempty"`
}

func redactToken(token string) string {
	if len(token) <= 8 {
		return "***"
	}
	return token[:8] + "..."
}

// MarshalLogObject implements zapcore.ObjectMarshaler.
// Token field is redacted to prevent bearer-token leakage in logs.
func (m *ControlMsg) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("type", m.Type)
	if m.Token != "" {
		enc.AddString("token_prefix", redactToken(m.Token))
	}
	if m.TunnelID != 0 {
		enc.AddUint64("tunnel_id", uint64(m.TunnelID))
	}
	if m.Tunnel != "" {
		enc.AddString("tunnel", m.Tunnel)
	}
	if m.Error != "" {
		enc.AddString("error", m.Error)
	}
	return nil
}

// WriteMsg serialises msg as a length-prefixed JSON frame.
func WriteMsg(w io.Writer, msg *ControlMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal control msg: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(data)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write length prefix: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return fmt.Errorf("write control msg payload: %w", err)
	}
	return nil
}

// ReadMsg reads one length-prefixed JSON frame from r.
func ReadMsg(r io.Reader) (*ControlMsg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > 64*1024 {
		return nil, fmt.Errorf("control msg too large: %d bytes", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read control msg payload: %w", err)
	}
	var msg ControlMsg
	if err := json.Unmarshal(buf, &msg); err != nil {
		return nil, fmt.Errorf("unmarshal control msg: %w", err)
	}
	return &msg, nil
}

// TunnelHeader is the 24-byte header prepended to every data stream.
type TunnelHeader struct {
	TunnelID  uint32
	SessionID [16]byte
}

// WriteHeader writes the 24-byte tunnel header to w.
func WriteHeader(w io.Writer, h TunnelHeader) error {
	var buf [TunnelHeaderSize]byte
	binary.BigEndian.PutUint32(buf[:4], h.TunnelID)
	copy(buf[4:20], h.SessionID[:])
	if _, err := w.Write(buf[:]); err != nil {
		return fmt.Errorf("write tunnel header: %w", err)
	}
	return nil
}

// ReadHeader reads the 24-byte tunnel header from r.
func ReadHeader(r io.Reader) (TunnelHeader, error) {
	var buf [TunnelHeaderSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return TunnelHeader{}, fmt.Errorf("read tunnel header: %w", err)
	}
	var h TunnelHeader
	h.TunnelID = binary.BigEndian.Uint32(buf[:4])
	copy(h.SessionID[:], buf[4:20])
	return h, nil
}
