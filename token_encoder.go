package cryptr

import "fmt"

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/token_encoder_decoder.go --fake-name TokenEncoderDecoder . TokenEncoderDecoder

// A TokenEncoderDecoder can encode and decode tokens
type TokenEncoderDecoder interface {
	EncodeTokens(string) (string, error)
	DecodeTokens(string, ...DecodeTokensOption) (string, error)
}

// A DecodeTokensConfig configures a request to decode tokens.
type DecodeTokensConfig struct {
	wrapTokens bool
}

// A DecodeTokensOption configures a request to decode tokens.
type DecodeTokensOption func(*DecodeTokensConfig)

// WrapTokens requests that decoded secrets be wrapped
// in secret envelopes (ideally in the format
// understood by the corresponding encoder)
//
// For example, a secret decoder might try to decode the token:
//
//   secret-encoded:zzz:secret-encoded
//
// Assuming "zzz" is an encoded version of "hunter2", then a
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
func WrapTokens(c *DecodeTokensConfig) {
	c.wrapTokens = true
}

// A TokenEncoder looks for secret tokens
// within text, and encodes them
type TokenEncoder struct {
	Encoder Encoder
	Locator TokenLocator
	Wrapper TokenWrapper
}

// A TokenDecoder looks for encoded secret tokens
// within text, and decodes them
type TokenDecoder struct {
	Decoder Decoder
	Locator TokenLocator
	Wrapper TokenWrapper
}

// EncodeTokens looks for secret tokens within text, and encodes them
func (e *TokenEncoder) EncodeTokens(s string) (string, error) {
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

		encoded, err := e.Encoder.Encode(payload)
		if err != nil {
			return "", fmt.Errorf("failed to decode payload: %v", err)
		}

		// Cut the placeholder out of the original plaintext,
		// and replace it with the new ciphertext
		s = s[:location.EnvelopeStart] + e.Wrapper.WrapToken(encoded) + s[location.EnvelopeEnd:]
	}

	return s, nil
}

// DecodeTokens looks for encoded secret tokens within text, and decodes them
func (d *TokenDecoder) DecodeTokens(s string, opts ...DecodeTokensOption) (string, error) {
	conf := &DecodeTokensConfig{}
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

		encoded, err := d.Decoder.Decode(payload)
		if err != nil {
			return "", fmt.Errorf(`failed to decode payload "%v": %v`, payload, err)
		}

		ins := encoded
		if conf.wrapTokens && d.Wrapper != nil {
			ins = d.Wrapper.WrapToken(encoded)
		}

		// Cut the placeholder out of the original plaintext,
		// and replace it with the new ciphertext
		s = s[:location.EnvelopeStart] + ins + s[location.EnvelopeEnd:]
	}

	return s, nil
}
