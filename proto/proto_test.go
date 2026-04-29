package proto

import (
	"bytes"
	"testing"
)

func TestWriteReadMsg(t *testing.T) {
	tests := []struct {
		name string
		msg  ControlMsg
	}{
		{
			name: "auth message",
			msg:  ControlMsg{Type: TypeAuth, Token: "mcp_test123"},
		},
		{
			name: "auth ok",
			msg:  ControlMsg{Type: TypeAuthOK},
		},
		{
			name: "register with tunnels",
			msg: ControlMsg{
				Type: TypeRegister,
				Tunnels: []TunnelRegistration{
					{Name: "code-server"},
				},
			},
		},
		{
			name: "register ok",
			msg:  ControlMsg{Type: TypeRegisterOK, RegisteredTunnels: []string{"code-server"}},
		},
		{
			name: "error",
			msg:  ControlMsg{Type: TypeError, Error: "auth failed"},
		},
		{
			name: "heartbeat",
			msg:  ControlMsg{Type: TypeHeartbeat},
		},
		{
			name: "capabilities",
			msg: ControlMsg{
				Type:      TypeCapabilities,
				Tunnel:    "code-server",
				Tools:     []string{"read_file", "search"},
				Resources: []string{"file:///repo/*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteMsg(&buf, &tt.msg); err != nil {
				t.Fatalf("WriteMsg: %v", err)
			}
			got, err := ReadMsg(&buf)
			if err != nil {
				t.Fatalf("ReadMsg: %v", err)
			}
			if got.Type != tt.msg.Type {
				t.Errorf("Type = %q, want %q", got.Type, tt.msg.Type)
			}
			if got.Token != tt.msg.Token {
				t.Errorf("Token = %q, want %q", got.Token, tt.msg.Token)
			}
			if got.Error != tt.msg.Error {
				t.Errorf("Error = %q, want %q", got.Error, tt.msg.Error)
			}
			if got.Tunnel != tt.msg.Tunnel {
				t.Errorf("Tunnel = %q, want %q", got.Tunnel, tt.msg.Tunnel)
			}
		})
	}
}

func TestWriteReadMsg_TooLarge(t *testing.T) {
	var buf bytes.Buffer
	msg := &ControlMsg{Type: TypeError, Error: string(make([]byte, 128*1024))}
	if err := WriteMsg(&buf, msg); err != nil {
		t.Fatalf("WriteMsg: %v", err)
	}
	_, err := ReadMsg(&buf)
	if err == nil {
		t.Fatal("expected error for oversized message")
	}
}

func TestWriteReadTunnelHeader(t *testing.T) {
	tests := []struct {
		name   string
		header TunnelHeader
	}{
		{
			name:   "basic header",
			header: TunnelHeader{TunnelID: 42, SessionID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
		},
		{
			name:   "zero session",
			header: TunnelHeader{TunnelID: 1},
		},
		{
			name:   "max tunnel id",
			header: TunnelHeader{TunnelID: 0xFFFFFFFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteHeader(&buf, tt.header); err != nil {
				t.Fatalf("WriteHeader: %v", err)
			}
			if buf.Len() != TunnelHeaderSize {
				t.Fatalf("header size = %d, want %d", buf.Len(), TunnelHeaderSize)
			}
			got, err := ReadHeader(&buf)
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			if got.TunnelID != tt.header.TunnelID {
				t.Errorf("TunnelID = %d, want %d", got.TunnelID, tt.header.TunnelID)
			}
			if got.SessionID != tt.header.SessionID {
				t.Errorf("SessionID = %v, want %v", got.SessionID, tt.header.SessionID)
			}
		})
	}
}

func TestControlMsg_MarshalLogObject_RedactsToken(t *testing.T) {
	msg := &ControlMsg{Type: TypeAuth, Token: "mcp_abcdefghij1234567890"}
	redacted := redactToken(msg.Token)
	if redacted == msg.Token {
		t.Error("token was not redacted")
	}
	if len(redacted) >= len(msg.Token) {
		t.Error("redacted token should be shorter than original")
	}
}
