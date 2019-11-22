package vault

import "fmt"

// TokenWrapper wraps a vault token by putting
// the original payload in front of it
type TokenWrapper struct {
	Before string
	After  string
}

// WrapToken wraps the string with Before and After
func (w *TokenWrapper) WrapToken(token, originalPayload, originalEnvelope string) string {
	return fmt.Sprintf("%v%v#%v%v", w.Before, originalPayload, token, w.After)
}
