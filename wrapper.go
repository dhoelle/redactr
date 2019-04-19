package cryptr

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/token_wrapper.go --fake-name TokenWrapper . TokenWrapper

// A TokenWrapper wraps a token
type TokenWrapper interface {
	WrapToken(string) string
}

type StringWrapper struct {
	Before, After string
}

func (w *StringWrapper) WrapToken(s string) string {
	return w.Before + s + w.After
}
