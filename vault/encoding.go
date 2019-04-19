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
	client *api.Client
}

func NewEncoding() (*Encoding, error) {
	c, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %v", err)
	}

	return &Encoding{
		client: c,
	}, nil
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

	secret, err := e.client.Logical().Read(path)
	if err != nil {
		return "", fmt.Errorf("failed to read secret: %v", err)
	}

	value := secret.Data[key]
	switch typed := value.(type) {
	case string:
		return typed, nil
	case int:
		return strconv.Itoa(typed), nil
	default:
		b, err := json.Marshal(value)
		if err != nil {
			return "", fmt.Errorf("failed to marshal value: %v", err)
		}
		return string(b), nil
	}
}
