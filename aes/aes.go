// Package aes provides wrappers for AES-GCM encryption and decryption.
package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// NewEncryptionKey generates a random 256-bit key for Encrypt() and
// Decrypt()
//
// The implementation is copied (and trivially-altered) from
// https://github.com/gtank/cryptopasta/blob/bc3a108a5776376aa811eea34b93383837994340/encrypt.go#L23-L32
func NewEncryptionKey() (*[32]byte, error) {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to read random data: %v", err)
	}
	return &key, nil
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
//
// The implementation is copied (and then trivially-altered) from
// https://github.com/gtank/cryptopasta/blob/bc3a108a5776376aa811eea34b93383837994340/encrypt.go#L34-L55
func Encrypt(plaintext []byte, key *[32]byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create new aes cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to read nonce: %v", err)
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
//
// The implementation is copied (and then trivially-altered) from
// https://github.com/gtank/cryptopasta/blob/bc3a108a5776376aa811eea34b93383837994340/encrypt.go#L57-L80
func Decrypt(ciphertext []byte, key *[32]byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create new aes cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create new GCM: %v", err)
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return gcm.Open(nil,
		ciphertext[:gcm.NonceSize()],
		ciphertext[gcm.NonceSize():],
		nil,
	)
}
