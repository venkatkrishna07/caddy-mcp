package caddymcp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// tunnelNameRe allows lowercase alphanumeric, hyphens, and underscores.
// Must start and end with a letter or digit, max 63 chars (DNS label safe).
var tunnelNameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$`)

func validateTunnelName(name string) error {
	if !tunnelNameRe.MatchString(name) {
		return fmt.Errorf("invalid tunnel name %q: must be 1-63 lowercase alphanumeric characters, hyphens, or underscores, starting and ending with a letter or digit", name)
	}
	return nil
}

// sessionIDRe validates UUID v4 format.
var sessionIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateSessionID(id string) error {
	if !sessionIDRe.MatchString(id) {
		return fmt.Errorf("invalid session ID %q: must be UUID format", id)
	}
	return nil
}

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	if err := validateSessionID(s); err != nil {
		return uuid, err
	}
	hex := strings.ReplaceAll(s, "-", "")
	for i := 0; i < 16; i++ {
		b, err := strconv.ParseUint(hex[i*2:i*2+2], 16, 8)
		if err != nil {
			return uuid, fmt.Errorf("parse UUID byte %d: %w", i, err)
		}
		uuid[i] = byte(b)
	}
	return uuid, nil
}
