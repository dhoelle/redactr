package redactr_test

import (
	"testing"

	"github.com/dhoelle/redactr"
	"github.com/dhoelle/redactr/fakes"
)

func TestTokenRedacter_RedactTokens(t *testing.T) {
	t.Run("it should locate, redact, and replace tokens", func(t *testing.T) {
		fakeRedacter := &fakes.Redacter{}
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeTokenWrapper := &fakes.TokenWrapper{}
		e := &redactr.TokenRedacter{
			Redacter: fakeRedacter,
			Locator:  fakeTokenLocator,
			Wrapper:  fakeTokenWrapper,
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
		fakeRedacter.RedactReturnsOnCall(0, "aaa", nil)
		fakeRedacter.RedactReturnsOnCall(1, "bbb", nil)
		fakeTokenWrapper.WrapTokenStub = func(s, p, e string) string {
			return "secret-redacted:" + s + ":secret-redacted"
		}
		want := "foo secret-redacted:bbb:secret-redacted secret-redacted:aaa:secret-redacted baz"

		got, err := e.RedactTokens(input)
		if err != nil {
			t.Errorf("TokenRedacter.Redact() got err: %v", err)
			return
		}
		if got != want {
			t.Errorf("TokenRedacter.Redact()\n\twant %v\n\t got %v", want, got)
			return
		}
	})

	t.Run("if it doesn't locate any secrets in the input, it should return the input unchanged", func(t *testing.T) {
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeRedacter := &fakes.Redacter{}
		e := &redactr.TokenRedacter{
			Locator:  fakeTokenLocator,
			Redacter: fakeRedacter,
		}

		got, err := e.RedactTokens("foo")
		if err != nil {
			t.Errorf("TokenRedacter.Redact() got err: %v", err)
			return
		}
		if got != "foo" {
			t.Errorf("TokenRedacter.Redact() got %v, want %v", got, "foo")
			return
		}
	})
}

func TestTokenUnredacter_UnredactTokens(t *testing.T) {
	t.Run("it should locate, unredact, and replace tokens", func(t *testing.T) {
		fakeUnredacter := &fakes.Unredacter{}
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeTokenWrapper := &fakes.TokenWrapper{}
		e := &redactr.TokenUnredacter{
			Unredacter: fakeUnredacter,
			Locator:    fakeTokenLocator,
			Wrapper:    fakeTokenWrapper,
		}

		input := "foo secret-redacted:bbb:secret-redacted secret-redacted:aaa:secret-redacted baz"
		fakeTokenLocator.LocateTokensReturns([]struct {
			EnvelopeStart int
			PayloadStart  int
			PayloadEnd    int
			EnvelopeEnd   int
		}{
			{
				EnvelopeStart: 4,
				PayloadStart:  20,
				PayloadEnd:    23,
				EnvelopeEnd:   39,
			},
			{
				EnvelopeStart: 40,
				PayloadStart:  56,
				PayloadEnd:    59,
				EnvelopeEnd:   75,
			},
		}, nil)
		fakeUnredacter.UnredactReturnsOnCall(0, "swordfish", nil)
		fakeUnredacter.UnredactReturnsOnCall(1, "hunter2", nil)
		fakeTokenWrapper.WrapTokenStub = func(s, p, e string) string {
			return "secret:" + s + ":secret"
		}

		want := "foo hunter2 swordfish baz"
		got, err := e.UnredactTokens(input)
		if err != nil {
			t.Errorf("TokenUnredacter.Unredact() got err: %v", err)
			return
		}
		if got != want {
			t.Errorf("TokenUnredacter.Unredact()\n\twant %v\n\t got %v", want, got)
			return
		}

		t.Run("it should respect the WrapTokens option", func(t *testing.T) {
			fakeUnredacter.UnredactReturnsOnCall(2, "swordfish", nil)
			fakeUnredacter.UnredactReturnsOnCall(3, "hunter2", nil)
			want = "foo secret:hunter2:secret secret:swordfish:secret baz"
			got, err = e.UnredactTokens(input, redactr.WrapTokens)
			if err != nil {
				t.Errorf("TokenUnredacter.Unredact() got err: %v", err)
				return
			}
			if got != want {
				t.Errorf("TokenUnredacter.Unredact()\n\twant %v\n\t got %v", want, got)
				return
			}
		})
	})

	t.Run("if it doesn't locate any secrets in the input, it should return the input unchanged", func(t *testing.T) {
		fakeTokenLocator := &fakes.TokenLocator{}
		fakeUnredacter := &fakes.Unredacter{}
		e := &redactr.TokenUnredacter{
			Locator:    fakeTokenLocator,
			Unredacter: fakeUnredacter,
		}

		got, err := e.UnredactTokens("foo")
		if err != nil {
			t.Errorf("TokenUnredacter.Unredact() got err: %v", err)
			return
		}
		if got != "foo" {
			t.Errorf("TokenUnredacter.Unredact() got %v, want %v", got, "foo")
			return
		}
	})
}
