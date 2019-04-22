package vault

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

// A Redacter redacts secrets by storing
// them in a Hashicorp Vault
type Redacter struct {
	client Client
}

// NewRedacter creates a new Redacter
func NewRedacter(client Client) *Redacter {
	return &Redacter{
		client: client,
	}
}

// Unredact replaces a Vault secret declaration with the
// target secret.
//
// It expects an input like:
//
//    path/to/secret#secret_key
//
func (r *Redacter) Unredact(secretDeclaration string) (string, error) {
	ss := strings.Split(secretDeclaration, "#")
	if len(ss) != 2 {
		return "", fmt.Errorf("expected secret declaration with two parts, got %v", len(ss))
	}
	path, key := ss[0], ss[1]

	secret, err := r.client.ReadSecret(path, key)
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

// Redact inserts a declared secret into Vault
//
// It expects an input like:
//
//    path/to/secret#key#value
//
func (r *Redacter) Redact(secretDeclaration string) (string, error) {
	ss := strings.Split(secretDeclaration, "#")
	if len(ss) != 3 {
		return "", fmt.Errorf("expected secret declaration with three parts, got %v", len(ss))
	}
	path, key, value := ss[0], ss[1], ss[2]

	err := r.client.WriteSecret(path, key, value)
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %v", err)
	}
	return fmt.Sprintf("%v#%v", path, key), nil
}

// A Client can get secrets from a Hashicorp Vault instance
type Client interface {
	ReadSecret(path, key string) (interface{}, error)
	WriteSecret(path, key, value string) error
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

// WriteSecret writes a secret using the standard Vault client
func (w *StandardClientWrapper) WriteSecret(path, key, value string) error {
	// Fetch the existing vault secret, if one exists
	secret, err := w.Client.Logical().Read(path)
	if err != nil {
		return fmt.Errorf("failed to read secret: %v", err)
	}
	var data map[string]interface{}
	if secret != nil {
		data = secret.Data
	} else {
		data = make(map[string]interface{})
	}
	data[key] = value

	_, err = w.Client.Logical().Write(path, data)
	if err != nil {
		return fmt.Errorf("failed to write secret: %v", err)
	}
	return nil
}
