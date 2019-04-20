package cli

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dhoelle/cryptr"
	"github.com/dhoelle/cryptr/aes"
	"github.com/urfave/cli"
)

// CLI provides a command-line interface for cryptr
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

// Version sets the version of cryptr, as reported by the CLI
func Version(v string) NewOption {
	return func(c *Config) {
		c.version = v
	}
}

// Commit sets the commit of cryptr, as reported by the CLI
func Commit(v string) NewOption {
	return func(c *Config) {
		c.commit = v
	}
}

// Date sets the date of cryptr, as reported by the CLI
func Date(v string) NewOption {
	return func(c *Config) {
		c.date = v
	}
}

// New creates a new CLI
func New(ted cryptr.TokenEncoderDecoder, opts ...NewOption) (*CLI, error) {
	conf := &Config{}
	for _, o := range opts {
		o(conf)
	}

	app := cli.NewApp()
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
			Name:   "encode",
			Usage:  "encode embedded secrets",
			Action: encode(ted, os.Stdin, os.Stdout),
		},
		{
			Name:  "decode",
			Usage: "decode embedded secrets",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "wrap-tokens, w",
					Usage: "wrap decoded tokens",
				},
			},
			Action: decode(ted, os.Stdin, os.Stdout),
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

func encode(ted cryptr.TokenEncoderDecoder, in io.Reader, out io.Writer) func(*cli.Context) error {
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

		encoded, err := ted.EncodeTokens(input)
		if err != nil {
			return fmt.Errorf("failed to encode tokens: %v", err)
		}

		fmt.Fprintln(out, encoded)
		return nil
	}
}

func decode(ted cryptr.TokenEncoderDecoder, in io.Reader, out io.Writer) func(*cli.Context) error {
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

		var opts []cryptr.DecodeTokensOption
		if c.Bool("wrap-tokens") {
			opts = append(opts, cryptr.WrapTokens)
		}

		decoded, err := ted.DecodeTokens(input, opts...)
		if err != nil {
			return fmt.Errorf("failed to decode tokens: %v", err)
		}

		fmt.Fprintln(out, decoded)
		return nil
	}
}

func versionString(version, commit, date string) string {
	return fmt.Sprintf("%v (%v, %v)", version, commit, date)
}
