package main

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/dhoelle/cryptr"
	"github.com/dhoelle/cryptr/crypto"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()

	app.Commands = []cli.Command{
		{
			Name:    "key",
			Aliases: []string{"k"},
			Usage:   "generate a new key",
			Action: func(c *cli.Context) error {
				k, err := key()
				if err != nil {
					return err
				}
				fmt.Println(k)
				return nil
			},
		},
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "encrypt all secrets embedded in the input",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key, k",
					Usage:  "a 32-byte key (use the `key` command to create one)",
					EnvVar: "KEY",
				},
				cli.BoolFlag{
					Name:   "all, a",
					Usage:  "treat the input as one big secret, rather than looking for a secret envelope",
					EnvVar: "NOSTRIP",
				},
			},
			Action: func(c *cli.Context) error {
				if c.String("key") == "" {
					return fmt.Errorf("must provide a key (--key key, -k key, [$KEY]) (use `%v key` to generate one)", app.Name)
				}
				key, err := keyFromString(c.String("key"))
				if err != nil {
					return fmt.Errorf("failed to get key: %v", err)
				}

				var plaintext string
				if c.Args().Present() {
					plaintext = strings.Join(c.Args(), " ")
				} else {
					b, err := ioutil.ReadAll(os.Stdin)
					if err != nil {
						log.Fatalf("failed to read input: %v", err)
					}
					plaintext = string(b)
				}

				var encrypted string
				if c.Bool("all") {
					ciphertext, err := crypto.Encrypt([]byte(plaintext), key)
					if err != nil {
						return fmt.Errorf("failed to encrypt secret: %v", err)
					}
					b64 := base64.StdEncoding.EncodeToString(ciphertext)
					encrypted = "secret-encrypted:" + b64 + ":secret-encrypted"
				} else {
					encrypted, err = cryptr.Encrypt(plaintext, key)
					if err != nil {
						return fmt.Errorf("failed to encrypt: %v", err)
					}
				}
				fmt.Println(encrypted)
				return nil
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "decrypt all encrypted secrets embedded in the input",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "key, k",
					Usage:  "a 32-byte key (use the `key` command to create one)",
					EnvVar: "KEY",
				},
				cli.BoolFlag{
					Name:   "nostrip, n",
					Usage:  `return secrets with their envelopes attached (e.g. "secret:foo:secret", instead of the default "foo")`,
					EnvVar: "NOSTRIP",
				},
			},
			Action: func(c *cli.Context) error {
				if c.String("key") == "" {
					return fmt.Errorf("must provide a key (--key key, -k key, [$KEY]) (use `%v key` to generate one)", app.Name)
				}
				key, err := keyFromString(c.String("key"))
				if err != nil {
					return fmt.Errorf("failed to get key: %v", err)
				}

				var mixed string
				if c.Args().Present() {
					mixed = strings.Join(c.Args(), " ")
				} else {
					b, err := ioutil.ReadAll(os.Stdin)
					if err != nil {
						log.Fatalf("failed to read input: %v", err)
					}
					mixed = string(b)
				}
				plaintext, err := cryptr.Decrypt(mixed, key, !c.Bool("nostrip"))
				if err != nil {
					return fmt.Errorf("failed to decrypt: %v", err)
				}
				fmt.Println(plaintext)

				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("failed to run: %v", err)
	}
}

func key() (string, error) {
	key, err := crypto.NewEncryptionKey()
	if err != nil {
		return "", fmt.Errorf("failed to generate random encryption key: %v", err)
	}
	return base64.StdEncoding.EncodeToString([]byte(key[:])), nil
}

func keyFromString(s string) (*[32]byte, error) {
	// keys should be base64 encoded
	d, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("could not base64-decode key: %v", err)
	}

	if len(d) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes (got %v)", len(d))
	}
	b := &[32]byte{}
	copy(b[:], d)
	return b, nil
}
