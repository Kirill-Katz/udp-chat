package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

const (
	anaID     = "00000000000000000000000000000001"
	ionID     = "00000000000000000000000000000002"
	messageID = "10000000000000000000000000000001"
)

func testPacket(kind string) Packet {
	return Packet{Version: 1, Type: kind, PeerID: anaID, Name: "Ana", MessageID: messageID}
}
func TestProtocolValidation(t *testing.T) {
	for _, kind := range []string{"claim", "announce", "heartbeat", "leave", "hello", "conflict", "general", "private"} {
		p := testPacket(kind)
		switch kind {
		case "hello", "conflict":
			p.To = ionID
		case "general":
			p.Text = strings.Repeat("界", 500)
		case "private":
			p.To = ionID
			p.Nonce = base64.StdEncoding.EncodeToString(make([]byte, 12))
			p.Ciphertext = base64.StdEncoding.EncodeToString(make([]byte, 2016))
		}
		b, _ := json.Marshal(p)
		if _, err := decodePacket(b); err != nil {
			t.Fatalf("valid %s: %v", kind, err)
		}
	}
	b, _ := json.Marshal(testPacket("claim"))
	original := string(b)
	bad := []string{"", `[]`, `null`, `{`, original + ` {}`, strings.Replace(original, `"v":1`, `"v":2`, 1), strings.Replace(original, `"name":"Ana"`, `"name":null`, 1), strings.Replace(original, `"name":"Ana"`, `"name":"Ana","name":"Ion"`, 1), strings.Replace(original, `"name":"Ana"`, `"name":"Ana","n\u0061me":"Ion"`, 1), strings.Replace(original, `"name":"Ana"`, `"name":"bad name"`, 1), strings.Replace(original, `"type":"claim"`, `"type":"oops"`, 1), strings.TrimSuffix(original, "}") + `,"text":""}`, strings.TrimSuffix(original, "}") + `,"unknown":1}`}
	for _, text := range bad {
		if _, err := decodePacket([]byte(text)); err == nil {
			t.Errorf("accepted %s", text)
		}
	}
	for _, text := range []string{"", strings.Repeat("a", 501), "hi\nthere", "\x1b[31m"} {
		p := testPacket("general")
		p.Text = text
		b, _ := json.Marshal(p)
		if _, err := decodePacket(b); err == nil {
			t.Errorf("accepted text %q", text)
		}
	}
	for _, data := range [][]byte{{0xff}, bytes.Repeat([]byte("x"), maxDatagram+1)} {
		if _, err := decodePacket(data); err == nil {
			t.Error("accepted invalid bytes")
		}
	}
}
func TestUnicodeEscapes(t *testing.T) {
	p := testPacket("general")
	p.Text = "placeholder"
	data, _ := json.Marshal(p)
	for _, text := range []string{`\ud800`, `\udc00`, `\ud800X`, `\ud800\u0041`} {
		b := strings.Replace(string(data), "placeholder", text, 1)
		if _, err := decodePacket([]byte(b)); err == nil {
			t.Fatalf("accepted lone surrogate: %s", text)
		}
	}
	for _, text := range []string{`\ud83d\ude80`, `\\ud800`} {
		b := strings.Replace(string(data), "placeholder", text, 1)
		if _, err := decodePacket([]byte(b)); err != nil {
			t.Fatalf("valid escape %s: %v", text, err)
		}
	}
}

func TestNamesAndIDs(t *testing.T) {
	for _, s := range []string{"Ana", "Ion_2", "名字", "a-b"} {
		if !validName(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", "with space", "/etc", "\x1b", strings.Repeat("界", 11)} {
		if validName(s) {
			t.Fatal(s)
		}
	}
	for _, s := range []string{"", strings.Repeat("a", 31), strings.Repeat("A", 32), strings.Repeat("z", 32)} {
		if validID(s) {
			t.Fatal(s)
		}
	}
	if !validID(anaID) {
		t.Fatal("valid id rejected")
	}
}
func FuzzDecodePacket(f *testing.F) {
	b, _ := json.Marshal(testPacket("claim"))
	f.Add(b)
	f.Add([]byte{0xff})
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) { decodePacket(b) })
}
