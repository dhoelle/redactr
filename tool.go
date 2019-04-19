package cryptr

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"

	"github.com/dhoelle/cryptr/aes"
	"github.com/dhoelle/cryptr/vault"
)

type Tool struct {
	SecretDecoder *TokenDecoder
	VaultDecoder  *TokenDecoder

	SecretEncoder *TokenEncoder
}

func New(opts ...NewOption) (*Tool, error) {
	c := &Config{}
	for _, o := range opts {
		o(c)
	}

	t := &Tool{}

	if c.AESKey != "" {
		key, err := keyFromString(c.AESKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key: %v", err)
		}

		t.SecretEncoder = &TokenEncoder{
			Locator: &RegexTokenLocator{RE: regexp.MustCompile(`(?U)secret:(.+):secret`)},
			Encoder: &aes.Encoding{Key: key},
			Wrapper: &StringWrapper{Before: "secret-encrypted:", After: ":secret-encrypted"},
		}

		t.SecretDecoder = &TokenDecoder{
			Locator: &RegexTokenLocator{RE: regexp.MustCompile(`(?U)secret-encrypted:(.+):secret-encrypted`)},
			Decoder: &aes.Encoding{Key: key},
			Wrapper: &StringWrapper{Before: "secret:", After: ":secret"},
		}
	}

	vaultEncoding, err := vault.NewEncoding()
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault encoding: %v", err)
	}
	t.VaultDecoder = &TokenDecoder{
		Locator: &RegexTokenLocator{RE: vault.LookupTokenRE},
		Decoder: vaultEncoding,
	}

	return t, nil
}

type Config struct {
	AESKey string
}

type NewOption func(*Config)

func AESKey(key string) NewOption {
	return func(c *Config) {
		c.AESKey = key
	}
}

func FromEnv(c *Config) {
	c.AESKey = os.Getenv("AES_KEY")
}

func (a *Tool) EncodeTokens(s string) (string, error) {
	var err error

	if a.SecretEncoder != nil {
		s, err = a.SecretEncoder.EncodeTokens(s)
		if err != nil {
			return "", fmt.Errorf("secret encoder failed: %v", err)
		}
	}

	return s, nil
}

func (a *Tool) DecodeTokens(s string, opts ...DecodeTokensOption) (string, error) {
	var err error

	if a.SecretDecoder != nil {
		s, err = a.SecretDecoder.DecodeTokens(s, opts...)
		if err != nil {
			return "", fmt.Errorf("secret decoder failed: %v", err)
		}
	}

	if a.VaultDecoder != nil {
		s, err = a.VaultDecoder.DecodeTokens(s, opts...)
		if err != nil {
			return "", fmt.Errorf("vault decoder failed: %v", err)
		}
	}

	return s, nil
}

func keyFromString(s string) (*[32]byte, error) {
	// keys should be base64 encoded
	d, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("could not base64-decode key: %v", err)
	}

	if len(d) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes (got %v)", len(d))
	}
	b := &[32]byte{}
	copy(b[:], d)
	return b, nil
}
