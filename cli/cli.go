package cli

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dhoelle/redactr"
	"github.com/dhoelle/redactr/aes"
	"github.com/urfave/cli"
)

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/token_redacter_unredacter.go --fake-name TokenRedacterUnredacter . TokenRedacterUnredacter

// A TokenRedacterUnredacter can redact and unredact tokens
type TokenRedacterUnredacter interface {
	RedactTokens(string) (string, error)
	UnredactTokens(string, ...redactr.UnredactTokensOption) (string, error)
}

//go:generate gobin -m -run github.com/maxbrunsfeld/counterfeiter/v6 -o ./fakes/execer.go --fake-name Execer . Execer

// An Execer can exec a shell command
type Execer interface {
	Exec(name string, args []string, opts ...redactr.ExecOption) error
}

// CLI provides a command-line interface for redactr
type CLI struct {
	cliApp *cli.App
}

// Run runs the CLI
func (c *CLI) Run(arguments []string) error {
	return c.cliApp.Run(arguments)
}

// Config is used to configure a CLI
type Config struct {
	version string
	commit  string
	date    string
}

// A NewOption is used to alter a new CLI
type NewOption func(*Config)

// Version sets the version of redactr, as reported by the CLI
func Version(v string) NewOption {
	return func(c *Config) {
		c.version = v
	}
}

// Commit sets the commit of redactr, as reported by the CLI
func Commit(v string) NewOption {
	return func(c *Config) {
		c.commit = v
	}
}

// Date sets the date of redactr, as reported by the CLI
func Date(v string) NewOption {
	return func(c *Config) {
		c.date = v
	}
}

// New creates a new CLI
func New(ted TokenRedacterUnredacter, execer Execer, opts ...NewOption) (*CLI, error) {
	conf := &Config{}
	for _, o := range opts {
		o(conf)
	}

	app := cli.NewApp()
	app.Usage = "redact and unredact secrets"
	app.Version = versionString(conf.version, conf.commit, conf.date)
	app.Commands = []cli.Command{
		{
			Name:    "keygen",
			Aliases: []string{"key", "k"},
			Usage:   "generate a key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "type, t",
					Usage: "type of key to generate (choices: 32byte) (default: 32byte)",
				},
			},
			Action: keygen(os.Stdout),
		},
		{
			Name:    "redact",
			Aliases: []string{"r"},
			Usage:   "redact embedded secrets",
			Action:  redact(ted, os.Stdin, os.Stdout),
		},
		{
			Name:    "unredact",
			Aliases: []string{"u"},
			Usage:   "unredact embedded secrets",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "wrap-tokens, w",
					Usage: "wrap unredacted tokens",
				},
			},
			Action: unredact(ted, os.Stdin, os.Stdout),
		},
		{
			Name:  "exec",
			Usage: "execute a command (run `exec --help` for details)",
			UsageText: `Execute a command, with bonus features to make it easier to work with redacted environments:

		1. Redacted secrets in the environment will be unredacted.

		   For example:

				$ AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=" \
				MY_PASSWORD="secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm" \
				redactr exec echo 'my password is $MY_PASSWORD'

				# example output:
				# my password is hunter2

		2. If you set the --restart-if-env-changes or --stop-if-env-changes options, 
		   it will periodically re-check the environment. If the environment changes 
		   (e.g. a secret is updated in Vault), the command will be restarted or stopped.

		   For example:
		   
				$ VAULT_ADDR=http://localhost:8222 \
					VAULT_TOKEN=myroot \
					SECRET_KEY=vault:secret/data/db_password#value \
					redactr exec \
						--restart-if-env-changes 1000ms \
						/bin/bash -c 'echo "$(date): secret key: $SECRET_KEY"; sleep 2073600'
			
				# example output:
				# Tue Apr 30 18:42:24 PDT 2019: secret key: swordfish
				# Tue Apr 30 18:42:25 PDT 2019: secret key: hunter2
				# Tue Apr 30 18:42:26 PDT 2019: secret key: swordfish
				# ...
				
			(See https://github.com/dhoelle/redactr for complete examples)`,
			Flags: []cli.Flag{
				cli.DurationFlag{
					Name:  "restart-if-env-changes, r",
					Usage: "periodically re-evaluate the environment. If it changes, restart the command",
				},
				cli.DurationFlag{
					Name:  "stop-if-env-changes, s",
					Usage: "periodically re-evaluate the environment. If it changes, stop the command",
				},
			},
			Action: exec(execer),
		},
	}

	return &CLI{
		cliApp: app,
	}, nil
}

func keygen(out io.Writer) func(*cli.Context) error {
	return func(c *cli.Context) error {
		// the "type" flag is reserved for use with future
		// key types, but for now there is only one option :)
		typ := c.String("type")
		if typ != "" && typ != "32byte" {
			return fmt.Errorf("type must be in: [32byte]")
		}

		key, err := aes.NewEncryptionKey()
		if err != nil {
			return fmt.Errorf("failed to generate AES encryption key: %v", err)
		}

		fmt.Fprintln(out, base64.StdEncoding.EncodeToString(key[:]))
		return nil
	}
}

func redact(ted redactr.TokenRedacterUnredacter, in io.Reader, out io.Writer) func(*cli.Context) error {
	return func(c *cli.Context) error {
		var input string
		if c.Args().Present() {
			input = strings.Join(c.Args(), " ")
		} else {
			b, err := ioutil.ReadAll(in)
			if err != nil {
				return fmt.Errorf("failed to read input: %v", err)
			}
			input = string(b)
		}

		redacted, err := ted.RedactTokens(input)
		if err != nil {
			return fmt.Errorf("failed to redact tokens: %v", err)
		}

		fmt.Fprintln(out, redacted)
		return nil
	}
}

func unredact(ted redactr.TokenRedacterUnredacter, in io.Reader, out io.Writer) func(*cli.Context) error {
	return func(c *cli.Context) error {
		var input string
		if c.Args().Present() {
			input = strings.Join(c.Args(), " ")
		} else {
			b, err := ioutil.ReadAll(in)
			if err != nil {
				return fmt.Errorf("failed to read input: %v", err)
			}
			input = string(b)
		}

		var opts []redactr.UnredactTokensOption
		if c.Bool("wrap-tokens") {
			opts = append(opts, redactr.WrapTokens)
		}

		unredacted, err := ted.UnredactTokens(input, opts...)
		if err != nil {
			return fmt.Errorf("failed to unredact tokens: %v", err)
		}

		fmt.Fprintln(out, unredacted)
		return nil
	}
}

func exec(execer Execer) func(*cli.Context) error {
	return func(c *cli.Context) error {
		var args []string
		if c.Args().Present() {
			args = c.Args()
		} else {
			b, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read input: %v", err)
			}
			args = strings.Fields(string(b))
		}

		switch {
		case c.Duration("stop-if-env-changes") > 0:
			return execer.Exec(args[0], args[1:], redactr.StopIfEnvChanges(c.Duration("stop-if-env-changes")))
		case c.Duration("restart-if-env-changes") > 0:
			return execer.Exec(args[0], args[1:], redactr.RestartIfEnvChanges(c.Duration("restart-if-env-changes")))
		default:
			return execer.Exec(args[0], args[1:])
		}
	}
}

func versionString(version, commit, date string) string {
	return fmt.Sprintf("%v (%v, %v)", version, commit, date)
}
