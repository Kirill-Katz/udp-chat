package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	protocolVersion = 1
	maxDatagram     = 8192
	defaultGroup    = "239.255.42.99"
)

// Packet is the language-neutral wire format documented in ../PROTOCOL.md.
// An endpoint is always taken from recvfrom, never from a claimed JSON address.
type Packet struct {
	Version    int    `json:"v"`
	Type       string `json:"type"`
	PeerID     string `json:"peer_id"`
	Name       string `json:"name"`
	MessageID  string `json:"message_id"`
	To         string `json:"to,omitempty"`
	Text       string `json:"text,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Ciphertext string `json:"ciphertext,omitempty"`
}

func validID(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 16 && s == strings.ToLower(s)
}
func validName(s string) bool {
	if len(s) == 0 || len(s) > 32 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
func validText(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) < 1 || utf8.RuneCountInString(s) > 500 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// encoding/json replaces lone UTF-16 surrogate escapes with U+FFFD. Reject
// those instead, so malformed strings cannot decode differently in Java/Go.
func validSurrogates(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		n, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func decodePacket(data []byte) (Packet, error) {
	var p Packet
	if len(data) > maxDatagram || !utf8.Valid(data) {
		return p, errors.New("invalid size or UTF-8")
	}
	// Validate the object separately: encoding/json alone accepts duplicate keys.
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return p, errors.New("expected JSON object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return p, err
		}
		k, ok := key.(string)
		if !ok {
			return p, errors.New("invalid key")
		}
		if _, exists := fields[k]; exists {
			return p, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return p, err
		}
		if !validSurrogates(value) {
			return p, errors.New("unpaired Unicode surrogate")
		}
		fields[k] = value
	}
	if _, err := d.Token(); err != nil {
		return p, err
	}
	if _, err := d.Token(); err != io.EOF {
		return p, errors.New("trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if p.Version != protocolVersion || !validID(p.PeerID) || !validID(p.MessageID) || !validName(p.Name) {
		return p, errors.New("invalid header")
	}
	allowed := "v type peer_id name message_id"
	switch p.Type {
	case "claim", "announce", "heartbeat", "leave":
	case "hello", "conflict":
		allowed += " to"
		if !validID(p.To) {
			return p, errors.New("invalid recipient")
		}
	case "general":
		allowed += " text"
		if !validText(p.Text) {
			return p, errors.New("text must contain 1-500 characters without controls")
		}
	case "private":
		allowed += " to nonce ciphertext"
		nonce, e1 := base64.StdEncoding.Strict().DecodeString(p.Nonce)
		ciphertext, e2 := base64.StdEncoding.Strict().DecodeString(p.Ciphertext)
		if !validID(p.To) || e1 != nil || e2 != nil || len(nonce) != 12 || len(ciphertext) < 17 || len(ciphertext) > 2016 || base64.StdEncoding.EncodeToString(nonce) != p.Nonce || base64.StdEncoding.EncodeToString(ciphertext) != p.Ciphertext {
			return p, errors.New("invalid encrypted payload")
		}
	default:
		return p, errors.New("unknown type")
	}
	for key, value := range fields {
		if !strings.Contains(" "+allowed+" ", " "+key+" ") || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return p, errors.New("unexpected or null field")
		}
	}
	return p, nil
}
