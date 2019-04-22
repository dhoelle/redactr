package redactr

import "fmt"

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/token_redacter_unredacter.go --fake-name TokenRedacterUnredacter . TokenRedacterUnredacter

// A TokenRedacterUnredacter can redact and unredact tokens
type TokenRedacterUnredacter interface {
	RedactTokens(string) (string, error)
	UnredactTokens(string, ...UnredactTokensOption) (string, error)
}

// A UnredactTokensConfig configures a request to unredact tokens.
type UnredactTokensConfig struct {
	wrapTokens bool
}

// A UnredactTokensOption configures a request to unredact tokens.
type UnredactTokensOption func(*UnredactTokensConfig)

// WrapTokens requests that unredacted secrets be wrapped
// in secret envelopes (ideally in the format
// understood by the corresponding redacter)
//
// For example, a secret unredacter might try to unredact the token:
//
//   secret-redacted:zzz:secret-redacted
//
// Assuming "zzz" is an redacted version of "hunter2", then a
// regular, unwrapped output would be:
//
//   hunter2
//
// With the WrapTokens option, the output should become:
//
//   secret:hunter2:secret
//
// This is helpful when a user wants to see a reversible output,
// such as when users want to rotate secrets or keys.
func WrapTokens(c *UnredactTokensConfig) {
	c.wrapTokens = true
}

// A TokenRedacter looks for secret tokens
// within text, and redacts them
type TokenRedacter struct {
	Redacter Redacter
	Locator  TokenLocator
	Wrapper  TokenWrapper
}

// A TokenUnredacter looks for redacted secret tokens
// within text, and unredacts them
type TokenUnredacter struct {
	Unredacter Unredacter
	Locator    TokenLocator
	Wrapper    TokenWrapper
}

// RedactTokens looks for secret tokens within text, and redacts them
func (e *TokenRedacter) RedactTokens(s string) (string, error) {
	locations, err := e.Locator.LocateTokens(s)
	if err != nil {
		return "", fmt.Errorf("failed to locate tokens: %v", err)
	}

	// walk through the matches in reverse order;
	// we'll be cutting and inserting, and this
	// simplifies the calculation
	for i := len(locations) - 1; i >= 0; i-- {
		location := locations[i]
		payload := s[location.PayloadStart:location.PayloadEnd]
		envelope := s[location.EnvelopeStart:location.EnvelopeEnd]

		redacted, err := e.Redacter.Redact(payload)
		if err != nil {
			return "", fmt.Errorf("failed to unredact payload: %v", err)
		}

		// Cut the placeholder out of the original plaintext,
		// and replace it with the new ciphertext
		wrappedToken := e.Wrapper.WrapToken(redacted, payload, envelope)
		s = s[:location.EnvelopeStart] + wrappedToken + s[location.EnvelopeEnd:]
	}

	return s, nil
}

// UnredactTokens looks for redacted secret tokens within text, and unredacts them
func (d *TokenUnredacter) UnredactTokens(s string, opts ...UnredactTokensOption) (string, error) {
	conf := &UnredactTokensConfig{}
	for _, o := range opts {
		o(conf)
	}

	locations, err := d.Locator.LocateTokens(s)
	if err != nil {
		return "", fmt.Errorf("failed to locate tokens: %v", err)
	}

	// walk through the matches in reverse order;
	// we'll be cutting and inserting, and this
	// simplifies the calculation
	for i := len(locations) - 1; i >= 0; i-- {
		location := locations[i]
		payload := s[location.PayloadStart:location.PayloadEnd]
		envelope := s[location.EnvelopeStart:location.EnvelopeEnd]

		redacted, err := d.Unredacter.Unredact(payload)
		if err != nil {
			return "", fmt.Errorf(`failed to unredact payload "%v": %v`, payload, err)
		}

		ins := redacted
		if conf.wrapTokens && d.Wrapper != nil {
			ins = d.Wrapper.WrapToken(redacted, payload, envelope)
		}

		// Cut the placeholder out of the original plaintext,
		// and replace it with the new ciphertext
		s = s[:location.EnvelopeStart] + ins + s[location.EnvelopeEnd:]
	}

	return s, nil
}
