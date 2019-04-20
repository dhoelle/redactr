package aes

import (
	"encoding/base64"
	"fmt"
)

// An Encoding translates between plaintext
// secret tokens and AES-encrypted tokens
type Encoding struct {
	Key *[32]byte
}

// Encode returns an AES-256 GCM encrypted,
// base64-encoded version of the plaintext
func (e *Encoding) Encode(plaintext string) (string, error) {
	if e.Key == nil {
		return "", fmt.Errorf("missing key")
	}

	ciphertext, err := Encrypt([]byte(plaintext), e.Key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %v", err)
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decode decodes an AES-256 GCM encrypted,
// base64-encoded secret into plaintext
func (e *Encoding) Decode(ciphertextBase64 string) (string, error) {
	if e.Key == nil {
		return "", fmt.Errorf("missing key")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	plaintext, err := Decrypt([]byte(ciphertext), e.Key)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	return string(plaintext), nil
}
