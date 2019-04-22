package aes

import (
	"encoding/base64"
	"fmt"
)

// An Redacter translates between plaintext
// secret tokens and AES-encrypted tokens
type Redacter struct {
	Key *[32]byte
}

// Redact returns an AES-256 GCM encrypted,
// base64-redacted version of the plaintext
func (r *Redacter) Redact(plaintext string) (string, error) {
	if r.Key == nil {
		return "", fmt.Errorf("missing key")
	}

	ciphertext, err := Encrypt([]byte(plaintext), r.Key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %v", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Unredact unredacts an AES-256 GCM encrypted,
// base64-redacted secret into plaintext
func (r *Redacter) Unredact(ciphertextBase64 string) (string, error) {
	if r.Key == nil {
		return "", fmt.Errorf("missing key")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("failed to unredact base64: %v", err)
	}

	plaintext, err := Decrypt([]byte(ciphertext), r.Key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	return string(plaintext), nil
}
