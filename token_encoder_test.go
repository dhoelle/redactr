package cryptr_test

import (
	"testing"

	"github.com/dhoelle/cryptr"
	"github.com/dhoelle/cryptr/fakes"
)

func TestTokenEncoder_EncodeTokens(t *testing.T) {
	t.Run("it should locate, encode, and replace tokens", func(t *testing.T) {
		fakeEncoder := &fakes.Encoder{}
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeTokenWrapper := &fakes.TokenWrapper{}
		e := &cryptr.TokenEncoder{
			Encoder: fakeEncoder,
			Locator: fakeTokenLocator,
			Wrapper: fakeTokenWrapper,
		}

		input := "foo secret:hunter2:secret secret:swordfish:secret baz"
		fakeTokenLocator.LocateTokensReturns([]struct {
			EnvelopeStart int
			PayloadStart  int
			PayloadEnd    int
			EnvelopeEnd   int
		}{
			{
				EnvelopeStart: 4,
				PayloadStart:  12,
				PayloadEnd:    19,
				EnvelopeEnd:   25,
			},
			{
				EnvelopeStart: 26,
				PayloadStart:  34,
				PayloadEnd:    43,
				EnvelopeEnd:   49,
			},
		}, nil)
		fakeEncoder.EncodeReturnsOnCall(0, "aaa", nil)
		fakeEncoder.EncodeReturnsOnCall(1, "bbb", nil)
		fakeTokenWrapper.WrapTokenStub = func(s string) string {
			return "secret-encoded:" + s + ":secret-encoded"
		}
		want := "foo secret-encoded:bbb:secret-encoded secret-encoded:aaa:secret-encoded baz"

		got, err := e.EncodeTokens(input)
		if err != nil {
			t.Errorf("TokenEncoder.Encode() got err: %v", err)
			return
		}
		if got != want {
			t.Errorf("TokenEncoder.Encode()\n\twant %v\n\t got %v", want, got)
			return
		}
	})

	t.Run("if it doesn't locate any secrets in the input, it should return the input unchanged", func(t *testing.T) {
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeEncoder := &fakes.Encoder{}
		e := &cryptr.TokenEncoder{
			Locator: fakeTokenLocator,
			Encoder: fakeEncoder,
		}

		got, err := e.EncodeTokens("foo")
		if err != nil {
			t.Errorf("TokenEncoder.Encode() got err: %v", err)
			return
		}
		if got != "foo" {
			t.Errorf("TokenEncoder.Encode() got %v, want %v", got, "foo")
			return
		}
	})
}

func TestTokenDecoder_DecodeTokens(t *testing.T) {
	t.Run("it should locate, decode, and replace tokens", func(t *testing.T) {
		fakeDecoder := &fakes.Decoder{}
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeTokenWrapper := &fakes.TokenWrapper{}
		e := &cryptr.TokenDecoder{
			Decoder: fakeDecoder,
			Locator: fakeTokenLocator,
			Wrapper: fakeTokenWrapper,
		}

		input := "foo secret-encoded:bbb:secret-encoded secret-encoded:aaa:secret-encoded baz"
		fakeTokenLocator.LocateTokensReturns([]struct {
			EnvelopeStart int
			PayloadStart  int
			PayloadEnd    int
			EnvelopeEnd   int
		}{
			{
				EnvelopeStart: 4,
				PayloadStart:  19,
				PayloadEnd:    22,
				EnvelopeEnd:   37,
			},
			{
				EnvelopeStart: 38,
				PayloadStart:  53,
				PayloadEnd:    56,
				EnvelopeEnd:   71,
			},
		}, nil)
		fakeDecoder.DecodeReturnsOnCall(0, "swordfish", nil)
		fakeDecoder.DecodeReturnsOnCall(1, "hunter2", nil)
		fakeTokenWrapper.WrapTokenStub = func(s string) string {
			return "secret:" + s + ":secret"
		}

		want := "foo hunter2 swordfish baz"
		got, err := e.DecodeTokens(input)
		if err != nil {
			t.Errorf("TokenDecoder.Decode() got err: %v", err)
			return
		}
		if got != want {
			t.Errorf("TokenDecoder.Decode()\n\twant %v\n\t got %v", want, got)
			return
		}

		t.Run("it should respect the WrapTokens option", func(t *testing.T) {
			fakeDecoder.DecodeReturnsOnCall(2, "swordfish", nil)
			fakeDecoder.DecodeReturnsOnCall(3, "hunter2", nil)
			want = "foo secret:hunter2:secret secret:swordfish:secret baz"
			got, err = e.DecodeTokens(input, cryptr.WrapTokens)
			if err != nil {
				t.Errorf("TokenDecoder.Decode() got err: %v", err)
				return
			}
			if got != want {
				t.Errorf("TokenDecoder.Decode()\n\twant %v\n\t got %v", want, got)
				return
			}
		})
	})

	t.Run("if it doesn't locate any secrets in the input, it should return the input unchanged", func(t *testing.T) {
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeDecoder := &fakes.Decoder{}
		e := &cryptr.TokenDecoder{
			Locator: fakeTokenLocator,
			Decoder: fakeDecoder,
		}

		got, err := e.DecodeTokens("foo")
		if err != nil {
			t.Errorf("TokenDecoder.Decode() got err: %v", err)
			return
		}
		if got != "foo" {
			t.Errorf("TokenDecoder.Decode() got %v, want %v", got, "foo")
			return
		}
	})
}
