package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
)

const kdfIterations = 600000

func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func deriveKey(passphrase, group string, port int) ([]byte, error) {
	salt := fmt.Sprintf("lan-chat-v1|%s|%d", group, port)
	return pbkdf2.Key(sha256.New, passphrase, []byte(salt), kdfIterations, 32)
}
func newCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func associatedData(p Packet, recipientName string) []byte {
	return []byte(strings.Join([]string{"lan-chat-private-v1", p.PeerID, p.Name, p.To, recipientName, p.MessageID}, "\x00"))
}
func encryptPrivate(aead cipher.AEAD, p *Packet, recipientName, text string) error {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, []byte(text), associatedData(*p, recipientName))
	p.Nonce = base64.StdEncoding.EncodeToString(nonce)
	p.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	return nil
}
func decryptPrivate(aead cipher.AEAD, p Packet, recipientName string) (string, error) {
	nonce, err := base64.StdEncoding.Strict().DecodeString(p.Nonce)
	if err != nil || len(nonce) != aead.NonceSize() {
		return "", fmt.Errorf("invalid nonce")
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(p.Ciphertext)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData(p, recipientName))
	if err != nil {
		return "", fmt.Errorf("authentication failed")
	}
	if !validText(string(plaintext)) {
		return "", fmt.Errorf("invalid decrypted text")
	}
	return string(plaintext), nil
}
