# cryptr

Keep obscured secrets alongside plaintext.

`cryptr` searches for secret declarations inside
text, and replaces them with secrets.

## Example (CLI)

```sh
AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=" \
VAULT_ADDR=http://localhost:7777 \
VAULT_TOKEN=secret_root_token \
cryptr decode <<EOF
{
    "secret_1": "secret-encrypted:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-encrypted",
    "secret_2": "secret-encrypted:AHgF0qDSX/TmRxxlftMvdnY2LMXRgA4DpFB9jy0/uh8kMXQqyQ==:secret-encrypted",
    "vault_secret_1": "vault:path/to/kv/secret#my_key:vault",
    "some_plaintext": "hello world",
}
EOF
```
Output:
```sh
{
    "secret_1": "hunter2",
    "secret_2": "swordfish",
    "vault_secret_1": "bond007",
    "some_plaintext": "hello world",
}
```

Note: this example is formatted in JSON, but `cryptr`
is agnostic to the content surrounding secrets.

## Example (Go Library)

```go
package main

import (
	"fmt"
	"log"

	"github.com/dhoelle/cryptr"
)

func main() {
	c, _ := cryptr.New(
        // cryptr.FromEnv,
		cryptr.AESKey("xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="),
	)

	plaintext := "foo secret:hunter2:secret baz"
    encoded, _ := c.EncodeTokens(plaintext)
    fmt.Println(encoded) // "foo secret-encrypted:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-encrypted baz"

    decoded, _ := c.DecodeTokens(encoded)
    fmt.Println(encoded) // "foo hunter2 baz"

    decoded, _ = c.DecodeTokens(encoded, cryptr.WrapTokens)
    fmt.Println(encoded) // "foo secret:hunter2:secret baz"
}
```

## Install

go get github.com/dhoelle/cryptr/cmd/cryptr

## Usage

### Keys

`cryptr` encrypts secrets with 256-bit AES-GCM. It requires a 32-byte key, base64 encoded.

You can generate a key with `cryptr key`:

```sh
$ cryptr key
xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=
```

### Encrypting

Use `cryptr encrypt` to encrypt secrets.

`cryptr encrypt` encrypts anything between matching `secret:` and `:secret` tags.

```sh
$ KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=" ./cryptr encrypt <<EOF
{
    "secret_1": "secret:hunter2:secret",
    "secret_2": "secret:swordfish:secret",
    "a_plaintext_key": "hello world",
}
EOF
```
Outputs:
```sh
{
    "secret_1": "secret-encrypted:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-encrypted",
    "secret_2": "secret-encrypted:AHgF0qDSX/TmRxxlftMvdnY2LMXRgA4DpFB9jy0/uh8kMXQqyQ==:secret-encrypted",
    "a_plaintext_key": "hello world",
}
```

With the `--all`/`-a` option, the entire input is treated as a secret.
This is useful for encrypting individual secrets.

```sh
KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=" ./cryptr encrypt -a hunter2
```
Outputs:
```sh
secret-encrypted:wjILSknIupncnCteD6599ts4BBcrPYikM28moYiWM/kXbs0=:secret-encrypted
```

### Decrypting

Use `cryptr decrypt` to decrypt secrets

`cryptr decrypt` decrypts anything between matching `secret-encrypted:` and `:secret-encrypted` tags.

```sh
$ KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=" ./cryptr decrypt <<EOF
{
    "secret_1": "secret-encrypted-aes256:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-encrypted",
    "secret_2": "secret-encrypted:AHgF0qDSX/TmRxxlftMvdnY2LMXRgA4DpFB9jy0/uh8kMXQqyQ==:secret-encrypted",
    "vault_secret_1": "vault:path/to/kv/secret#my_key:vault",
    "aws_secret_1": "aws-secret:path/to/secret#my_key:aws-secret",
    "a_plaintext_key": "hello world",
}
EOF
```
Outputs:
```sh
{
    "secret_1": "hunter2",
    "secret_2": "swordfish",
    "a_plaintext_key": "hello world",
}
```


# Development

