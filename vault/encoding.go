package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// An Encoding translates between Vault
// secret declarations and vaulted secrets
type Encoding struct {
	client Client
}

// NewEncoding creates a new Encoding
func NewEncoding(client Client) *Encoding {
	return &Encoding{
		client: client,
	}
}

// Decode replaces a Vault secret declaration with the
// target secret.
//
// It expects an input like:
//
//    path/to/secret#secret_key
//
func (e *Encoding) Decode(secretDeclaration string) (string, error) {
	ss := strings.Split(secretDeclaration, "#")
	if len(ss) != 2 {
		return "", fmt.Errorf("expected secret declaration with two parts, got %v", len(ss))
	}
	path, key := ss[0], ss[1]

	secret, err := e.client.ReadSecret(path, key)
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %v", err)
	}

	switch typed := secret.(type) {
	case string:
		return typed, nil
	case int:
		return strconv.Itoa(typed), nil
	default:
		b, err := json.Marshal(secret)
		if err != nil {
			return "", fmt.Errorf("failed to marshal secret value: %v", err)
		}
		return string(b), nil
	}
}

// A Client can get secrets from a Hashicorp Vault instance
type Client interface {
	ReadSecret(path, key string) (interface{}, error)
}

// StandardClientWrapper wraps the standard Vault client into a Client
type StandardClientWrapper struct {
	Client *api.Client
}

// ReadSecret reads a secret using the standard Vault client
func (w *StandardClientWrapper) ReadSecret(path, key string) (interface{}, error) {
	secret, err := w.Client.Logical().Read(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %v", err)
	}
	return secret.Data[key], nil
}
