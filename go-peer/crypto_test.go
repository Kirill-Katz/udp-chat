package main

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestKDFVector(t *testing.T) {
	key, err := deriveKey("correct horse battery staple", defaultGroup, 9000)
	if err != nil {
		t.Fatal(err)
	}
	// Independently calculated using Python hashlib.pbkdf2_hmac.
	if hex.EncodeToString(key) != "c37b2a13646807667bf8fc9a232df3c0044a5f47e3b8b47b39238d16e2512fa0" {
		t.Fatalf("wrong key: %x", key)
	}
}
func TestPrivateAuthentication(t *testing.T) {
	aead, err := newCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	p := testPacket("private")
	p.To = ionID
	if err := encryptPrivate(aead, &p, "Ion", "hello 世界"); err != nil {
		t.Fatal(err)
	}
	text, err := decryptPrivate(aead, p, "Ion")
	if err != nil || text != "hello 世界" {
		t.Fatalf("%q: %v", text, err)
	}
	other := p
	if err := encryptPrivate(aead, &other, "Ion", "hello 世界"); err != nil {
		t.Fatal(err)
	}
	if other.Nonce == p.Nonce {
		t.Fatal("nonce reused")
	}
	mutations := []func(*Packet){func(p *Packet) { p.Name = "Maria" }, func(p *Packet) { p.To = anaID }, func(p *Packet) { p.MessageID = ionID }, func(p *Packet) { p.PeerID = ionID }, func(p *Packet) {
		b, _ := base64.StdEncoding.DecodeString(p.Ciphertext)
		b[0] ^= 1
		p.Ciphertext = base64.StdEncoding.EncodeToString(b)
	}, func(p *Packet) { p.Nonce = "AA==" }}
	for _, mutate := range mutations {
		copy := p
		mutate(&copy)
		if _, err := decryptPrivate(aead, copy, "Ion"); err == nil {
			t.Fatal("accepted modified encrypted packet")
		}
	}
	if _, err := decryptPrivate(aead, p, "Maria"); err == nil {
		t.Fatal("wrong recipient accepted")
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	wrong, _ := newCipher(wrongKey)
	if _, err := decryptPrivate(wrong, p, "Ion"); err == nil {
		t.Fatal("wrong key accepted")
	}
	if err := encryptPrivate(aead, &p, "Ion", "\x1b[31m"); err != nil {
		t.Fatal(err)
	}
	if _, err := decryptPrivate(aead, p, "Ion"); err == nil {
		t.Fatal("invalid plaintext accepted")
	}
}

func TestEncryptionVector(t *testing.T) {
	key, _ := hex.DecodeString("c37b2a13646807667bf8fc9a232df3c0044a5f47e3b8b47b39238d16e2512fa0")
	aead, _ := newCipher(key)
	p := testPacket("private")
	p.To = ionID
	nonce, _ := hex.DecodeString("000102030405060708090a0b")
	encrypted := aead.Seal(nil, nonce, []byte("hello 世界"), associatedData(p, "Ion"))
	// Independently verified with Java 21 HmacSHA256 and AES/GCM/NoPadding.
	if got := base64.StdEncoding.EncodeToString(encrypted); got != "NWmjMQ7kkUzwSB2AhLYb1I+q8deJM1uwIRaXoQ==" {
		t.Fatalf("encryption vector mismatch: %s", got)
	}
}
