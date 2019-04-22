package redactr

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/redacter.go --fake-name Redacter . Redacter

// A Redacter redacts secrets into a redacted form
type Redacter interface {
	Redact(string) (string, error)
}

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/unredacter.go --fake-name Unredacter . Unredacter

// An Unredacter unredacts secrets
type Unredacter interface {
	Unredact(string) (string, error)
}
