package cryptr

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/dhoelle/cryptr/crypto"
)

var (
	secretRE    = regexp.MustCompile("(?U)secret:(.+):secret")
	encryptedRE = regexp.MustCompile("(?U)secret-encrypted:(.+):secret-encrypted")
)

// Encrypt encrypts all secrets embedded in the provided plaintext.
func Encrypt(plaintext string, key *[32]byte) (string, error) {
	// get the location of all secret tags in the input
	is := secretRE.FindAllStringSubmatchIndex(plaintext, -1)

	if len(is) > 0 && key == nil {
		return "", fmt.Errorf("found %v secrets to encrypt, but key is nil", len(is))
	}

	// walk through the matches in reverse order;
	// we'll be cutting and inserting, and this
	// simplifies the calculation
	for i := len(is) - 1; i >= 0; i-- {
		match := is[i]
		ei, ej := match[0], match[1] // envelope
		si, sj := match[2], match[3] // secret
		secret := plaintext[si:sj]

		ciphertext, err := crypto.Encrypt([]byte(secret), key)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt secret: %v", err)
		}
		b64 := base64.StdEncoding.EncodeToString(ciphertext)

		// Cut the placeholder out of the original plaintext,
		// and replace it with the new ciphertext
		plaintext = plaintext[:ei] + "secret-encrypted:" + b64 + ":secret-encrypted" + plaintext[ej:]
	}

	return plaintext, nil
}

func Decrypt(pec string, key *[32]byte, strip bool) (string, error) {
	is := encryptedRE.FindAllStringSubmatchIndex(pec, -1)

	if len(is) > 0 && key == nil {
		return "", fmt.Errorf("found %v secrets to decrypt, but key is empty", len(is))
	}

	// walk through the matches in reverse order,
	// and replace each with its decrypted plaintext.
	// (going backwards simplifies the logic; if we
	// went forwards, the index of remaining matches
	// would change with each replacement)
	for i := len(is) - 1; i >= 0; i-- {
		match := is[i]
		ei, ej := match[0], match[1]
		si, sj := match[2], match[3]
		ciphertextB64 := pec[si:sj]
		ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
		if err != nil {
			return "", fmt.Errorf("could not base64-decode ciphertext: %v", err)
		}

		plaintext, err := crypto.Decrypt([]byte(ciphertext), key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt secret: %v", err)
		}

		if strip {
			pec = pec[:ei] + string(plaintext) + pec[ej:]
		} else {
			pec = pec[:ei] + "secret:" + string(plaintext) + ":secret" + pec[ej:]
		}
	}

	return pec, nil
}
