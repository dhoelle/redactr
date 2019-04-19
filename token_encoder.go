package cryptr

import "fmt"

type ITokenEncoder interface {
	EncodeTokens(string) (string, error)
}

type ITokenDecoder interface {
	DecodeTokens(string, ...DecodeTokensOption) (string, error)
}

type DecodeTokensConfig struct {
	WrapTokens bool
}

type DecodeTokensOption func(*DecodeTokensConfig)

func WrapTokens(c *DecodeTokensConfig) {
	c.WrapTokens = true
}

// A TokenEncoder encodes secrets which
// are embedded within a plaintext.
type TokenEncoder struct {
	Encoder Encoder
	Locator TokenLocator
	Wrapper TokenWrapper
}

type TokenDecoder struct {
	Decoder Decoder
	Locator TokenLocator
	Wrapper TokenWrapper
}

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
		if conf.WrapTokens && d.Wrapper != nil {
			ins = d.Wrapper.WrapToken(encoded)
		}

		// Cut the placeholder out of the original plaintext,
		// and replace it with the new ciphertext
		s = s[:location.EnvelopeStart] + ins + s[location.EnvelopeEnd:]
	}

	return s, nil
}
