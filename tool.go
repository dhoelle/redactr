package redactr

import (
	"encoding/base64"
	"fmt"
	"regexp"

	"github.com/dhoelle/redactr/aes"
	"github.com/dhoelle/redactr/vault"
	"github.com/hashicorp/vault/api"
)

// Tool is a "master redacter/unredacter". It wraps
// the combined functionality of redactr into a
// simpler interface.
type Tool struct {
	SecretUnredacter *TokenUnredacter
	VaultUnredacter  *TokenUnredacter

	SecretRedacter *TokenRedacter
	VaultRedacter  *TokenRedacter
}

// New creates a new Tool
func New(opts ...NewToolOption) (*Tool, error) {
	c := &NewToolConfig{}
	for _, o := range opts {
		o(c)
	}

	t := &Tool{}

	//
	// AES redacter
	//
	if c.aesKey != "" {
		key, err := keyFromString(c.aesKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse AES key: %v", err)
		}

		t.SecretRedacter = &TokenRedacter{
			Locator:  &RegexTokenLocator{RE: regexp.MustCompile(`(?U)secret:(.+):secret`)},
			Redacter: &aes.Redacter{Key: key},
			Wrapper:  &StringWrapper{Before: "secret-aes-256-gcm:", After: ":secret-aes-256-gcm"},
		}

		t.SecretUnredacter = &TokenUnredacter{
			Locator:    &RegexTokenLocator{RE: regexp.MustCompile(`(?U)secret-aes-256-gcm:(.+):secret-aes-256-gcm`)},
			Unredacter: &aes.Redacter{Key: key},
			Wrapper:    &StringWrapper{Before: "secret:", After: ":secret"},
		}
	}

	//
	// Vault redacter
	//
	vaultClient, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}
	vaultWrapper := &vault.StandardClientWrapper{Client: vaultClient}
	vaultRedacter := vault.NewRedacter(vaultWrapper)
	t.VaultUnredacter = &TokenUnredacter{
		Locator:    &RegexTokenLocator{RE: vault.RedactedRE},
		Unredacter: vaultRedacter,
		Wrapper:    &vault.TokenWrapper{Before: "vault-secret:"},
	}
	t.VaultRedacter = &TokenRedacter{
		Locator:  &RegexTokenLocator{RE: vault.UnredactedRE},
		Redacter: vaultRedacter,
		Wrapper:  &StringWrapper{Before: "vault:"},
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

// RedactTokens redacts all tokens in the string
func (a *Tool) RedactTokens(s string) (string, error) {
	var err error

	if a.SecretRedacter != nil {
		s, err = a.SecretRedacter.RedactTokens(s)
		if err != nil {
			return "", fmt.Errorf("secret redacter failed: %v", err)
		}
	}

	if a.VaultRedacter != nil {
		s, err = a.VaultRedacter.RedactTokens(s)
		if err != nil {
			return "", fmt.Errorf("vault redacter failed: %v", err)
		}
	}

	return s, nil
}

// UnredactTokens unredacts all tokens in the string
func (a *Tool) UnredactTokens(s string, opts ...UnredactTokensOption) (string, error) {
	var err error

	if a.SecretUnredacter != nil {
		s, err = a.SecretUnredacter.UnredactTokens(s, opts...)
		if err != nil {
			return "", fmt.Errorf("secret unredacter failed: %v", err)
		}
	}

	if a.VaultUnredacter != nil {
		s, err = a.VaultUnredacter.UnredactTokens(s, opts...)
		if err != nil {
			return "", fmt.Errorf("vault unredacter failed: %v", err)
		}
	}

	return s, nil
}

func keyFromString(s string) (*[32]byte, error) {
	// keys should be base64 redacted
	d, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("could not base64-unredact key: %v", err)
	}

	if len(d) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes (got %v)", len(d))
	}
	b := &[32]byte{}
	copy(b[:], d)
	return b, nil
}
