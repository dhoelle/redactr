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

type CLI struct {
	cliApp *cli.App
}

func (c *CLI) Run(arguments []string) error {
	return c.cliApp.Run(arguments)
}

func New() (*CLI, error) {
	tool, err := cryptr.New(cryptr.FromEnv)
	if err != nil {
		return nil, fmt.Errorf("failed to create cryptr tool: %v", err)
	}

	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:    "keygen",
			Aliases: []string{"key", "k"},
			Usage:   "generate a key",
			Action:  keygenAES(os.Stdout),
		},
		{
			Name:   "encode",
			Usage:  "encode embedded secrets",
			Action: encode(tool, os.Stdin, os.Stdout),
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
			Action: decode(tool, os.Stdin, os.Stdout),
		},
	}

	return &CLI{
		cliApp: app,
	}, nil
}

func keygenAES(out io.Writer) func(*cli.Context) error {
	return func(c *cli.Context) error {
		key, err := aes.NewEncryptionKey()
		if err != nil {
			return fmt.Errorf("failed to generate AES encryption key: %v", err)
		}

		fmt.Fprintln(out, base64.StdEncoding.EncodeToString(key[:]))
		return nil
	}
}

func encode(tool *cryptr.Tool, in io.Reader, out io.Writer) func(*cli.Context) error {
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

		encoded, err := tool.EncodeTokens(input)
		if err != nil {
			return fmt.Errorf("failed to encode tokens: %v", err)
		}

		fmt.Fprintln(out, encoded)
		return nil
	}
}

func decode(tool *cryptr.Tool, in io.Reader, out io.Writer) func(*cli.Context) error {
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

		decoded, err := tool.DecodeTokens(input, opts...)
		if err != nil {
			return fmt.Errorf("failed to decode tokens: %v", err)
		}

		fmt.Fprintln(out, decoded)
		return nil
	}
}
