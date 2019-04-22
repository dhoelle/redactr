package cryptr

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/dhoelle/cryptr/aes"
	"github.com/dhoelle/cryptr/vault"
	"github.com/hashicorp/vault/api"
)

// Tool is a "master encoder/decoder". It wraps
// the combined functionality of cryptr into a
// simpler interface.
type Tool struct {
	SecretDecoder *TokenDecoder
	VaultDecoder  *TokenDecoder

	SecretEncoder *TokenEncoder
	VaultEncoder  *TokenEncoder
}

// New creates a new Tool
func New(opts ...NewToolOption) (*Tool, error) {
	c := &NewToolConfig{}
	for _, o := range opts {
		o(c)
	}

	t := &Tool{}

	//
	// AES encoding
	//
	if c.aesKey != "" {
		key, err := keyFromString(c.aesKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse AES key: %v", err)
		}

		t.SecretEncoder = &TokenEncoder{
			Locator: &RegexTokenLocator{RE: regexp.MustCompile(`(?U)secret:(.+):secret`)},
			Encoder: &aes.Encoding{Key: key},
			Wrapper: &StringWrapper{Before: "secret-aes-256-gcm:", After: ":secret-aes-256-gcm"},
		}

		t.SecretDecoder = &TokenDecoder{
			Locator: &RegexTokenLocator{RE: regexp.MustCompile(`(?U)secret-aes-256-gcm:(.+):secret-aes-256-gcm`)},
			Decoder: &aes.Encoding{Key: key},
			Wrapper: &StringWrapper{Before: "secret:", After: ":secret"},
		}
	}

	//
	// Vault encoding
	//
	vaultClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}
	vaultWrapper := &vault.StandardClientWrapper{Client: vaultClient}
	vaultEncoding := vault.NewEncoding(vaultWrapper)
	t.VaultDecoder = &TokenDecoder{
		Locator: &RegexTokenLocator{RE: vault.EncodedRE},
		Decoder: vaultEncoding,
		Wrapper: &vault.TokenWrapper{Before: "vault-secret:"},
	}
	t.VaultEncoder = &TokenEncoder{
		Locator: &RegexTokenLocator{RE: vault.UnencodedRE},
		Encoder: vaultEncoding,
		Wrapper: &StringWrapper{Before: "vault:"},
	}

	return t, nil
}

// NewToolConfig is used to configure a Tool created by New()
type NewToolConfig struct {
	aesKey string
}

// NewToolOption configures a Tool on a call to New()
type NewToolOption func(*NewToolConfig)

// AESKey sets the key used for AES encryption and decryption
func AESKey(key string) NewToolOption {
	return func(c *NewToolConfig) {
		c.aesKey = key
	}
}

// EncodeTokens encodes all tokens in the string
func (a *Tool) EncodeTokens(s string) (string, error) {
	var err error

	if a.SecretEncoder != nil {
		s, err = a.SecretEncoder.EncodeTokens(s)
		if err != nil {
			return "", fmt.Errorf("secret encoder failed: %v", err)
		}
	}

	if a.VaultEncoder != nil {
		s, err = a.VaultEncoder.EncodeTokens(s)
		if err != nil {
			return "", fmt.Errorf("vault encoder failed: %v", err)
		}
	}

	return s, nil
}

// DecodeTokens decodes all tokens in the string
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
