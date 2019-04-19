package cryptr

import "regexp"

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/secret_locator.go --fake-name TokenLocator . TokenLocator

// A TokenLocator locates tokens
type TokenLocator interface {
	LocateTokens(string) ([]struct{ EnvelopeStart, PayloadStart, PayloadEnd, EnvelopeEnd int }, error)
}

type TokenLocation struct {
	EnvelopeStart, PayloadStart, PayloadEnd, EnvelopeEnd int
}

type RegexTokenLocator struct {
	// RE is a regex that finds tokens inside text.
	// The entire regex should capture a token envelope,
	// and it should have one capturing group which captures
	// the token payload. If the payload is the same as the
	// envelope, the entire regex should be a capturing group.
	RE *regexp.Regexp
}

// LocateTokens locates all secrets according
// to the embedded regular expression
func (l *RegexTokenLocator) LocateTokens(s string) ([]struct{ EnvelopeStart, PayloadStart, PayloadEnd, EnvelopeEnd int }, error) {
	matches := l.RE.FindAllStringSubmatchIndex(s, -1)
	sls := make([]struct{ EnvelopeStart, PayloadStart, PayloadEnd, EnvelopeEnd int }, len(matches))
	for i, m := range matches {
		sls[i] = struct{ EnvelopeStart, PayloadStart, PayloadEnd, EnvelopeEnd int }{
			EnvelopeStart: m[0],
			PayloadStart:  m[2],
			PayloadEnd:    m[3],
			EnvelopeEnd:   m[1],
		}
	}
	return sls, nil
}
