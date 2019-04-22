package redactr

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/token_wrapper.go --fake-name TokenWrapper . TokenWrapper

// A TokenWrapper wraps tokens
type TokenWrapper interface {
	WrapToken(token, originalPayload, originalEnvelope string) string
}

// StringWrapper wraps tokens by putting
// strings before and after each token
type StringWrapper struct {
	Before, After string
}

// WrapToken wraps the string with Before and After
func (w *StringWrapper) WrapToken(token, originalPayload, originalEnvelope string) string {
	return w.Before + token + w.After
}
