package cryptr

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/encoder.go --fake-name Encoder . Encoder

// An Encoder encodes values from one form to another.
// Cryptr encoders typically encode plaintext to
// ciphertext, or secrets to placeholders.
type Encoder interface {
	Encode(string) (string, error)
}

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/decoder.go --fake-name Decoder . Decoder

// A Decoder decodes values from one form to another.
// Cryptr decoders typically decode ciphertext
// into plaintext, or placeholders into secrets.
type Decoder interface {
	Decode(string) (string, error)
}
