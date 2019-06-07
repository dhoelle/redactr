package redactr

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"

	"github.com/dhoelle/redactr/aes"
	"github.com/dhoelle/redactr/exec"
	"github.com/dhoelle/redactr/vault"
	"github.com/hashicorp/vault/api"
)

// A Tool can be used to redact and unredact secrets.
// If you want to use redactr as a library, you probably
// want to create and use a Tool.
type Tool struct {
	SecretUnredacter TokenUnredacter
	VaultUnredacter  TokenUnredacter

	SecretRedacter TokenRedacter
	VaultRedacter  TokenRedacter
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

		t.SecretRedacter = &CompositeTokenRedacter{
			Locator:  &RegexTokenLocator{RE: regexp.MustCompile(`(?U)secret:(.+):secret`)},
			Redacter: &aes.Redacter{Key: key},
			Wrapper:  &StringWrapper{Before: "secret-aes-256-gcm:", After: ":secret-aes-256-gcm"},
		}

		t.SecretUnredacter = &CompositeTokenUnredacter{
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
	t.VaultUnredacter = &CompositeTokenUnredacter{
		Locator:    &RegexTokenLocator{RE: vault.RedactedRE},
		Unredacter: vaultRedacter,
		Wrapper:    &vault.TokenWrapper{Before: "vault-secret:"},
	}
	t.VaultRedacter = &CompositeTokenRedacter{
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

// RedactTokens redacts all tokens in a string
func (t *Tool) RedactTokens(s string) (string, error) {
	var err error

	if t.SecretRedacter != nil {
		s, err = t.SecretRedacter.RedactTokens(s)
		if err != nil {
			return "", fmt.Errorf("secret redacter failed: %v", err)
		}
	}

	if t.VaultRedacter != nil {
		s, err = t.VaultRedacter.RedactTokens(s)
		if err != nil {
			return "", fmt.Errorf("vault redacter failed: %v", err)
		}
	}

	return s, nil
}

// UnredactTokens unredacts all tokens in a string
func (t *Tool) UnredactTokens(s string, opts ...UnredactTokensOption) (string, error) {
	var err error

	if t.SecretUnredacter != nil {
		sc := s
		s, err = t.SecretUnredacter.UnredactTokens(sc, opts...)
		if err != nil {
			return "", fmt.Errorf("failed to unredact secret token %v: %v", sc, err)
		}
	}

	if t.VaultUnredacter != nil {
		sc := s
		s, err = t.VaultUnredacter.UnredactTokens(sc, opts...)
		if err != nil {
			return "", fmt.Errorf("failed to unredact vault token %v: %v", sc, err)
		}
	}

	return s, nil
}

// Exec executes a command. It acts like os.Exec,
// but with a couple of features that are helpful
// when working with redacted secrets:
//
//  1. Before running the command, redacted secrets
//     in the environment will be unredacted.
//
//  2. When called with the RestartIfEnvChanges or
//     StopIfEnvChanges option, Exec will periodically
//     re-evaluate the environment. If the environment
//     has changed, Exec will restart or stop the command
//     as requested.
func (t *Tool) Exec(name string, args []string, opts ...ExecOption) error {
	runner := exec.NewRunner(
		os.Stdin,
		os.Stdout,
		os.Environ(),
		toolUnredactReplacer(*t),
		name,
		args...)
	return Exec(runner, opts...)
}

// A toolUnredactReplacer uses a Tool to replace
// redacted tokens with unredacted values
type toolUnredactReplacer Tool

// Replace will replace any redacted tokens
// in the given string with unredacted values
func (r toolUnredactReplacer) Replace(s string) (string, error) {
	t := Tool(r)
	return t.UnredactTokens(s)
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
