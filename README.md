# redactr

Use `redactr` to obscure secrets alongside plaintext.

`redactr redact` finds secrets, and replaces them with redaction tokens.

`redactr unredact` finds redaction tokens, and replaces them with secrets.

## Install

### Binary
Download binaries from the [releases page](https://github.com/dhoelle/redactr/releases)

### Brew (Mac OS):
```sh
brew tap dhoelle/tap
brew install dhoelle/tap/redactr
```

### Build from source

Requires Go 1.11+
```sh
go get github.com/dhoelle/redactr/cmd/redactr
```

## Example (CLI)

Set some environment variables:
```
export AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=my_token
```

Redact some secrets:

```sh
redactr redact <<EOF
{
    "aes_secret": "secret:hunter2:secret",
    "not_a_secret": 42,
    "vault_secret_1": "vault-secret:path/to/kv/secret#my_key#swordfish"
}
EOF
```
Output:
```json
{
    "aes_secret": "secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm",
    "not_a_secret": 42,
    "vault_secret_1": "vault:path/to/kv/secret#my_key"
}
```

Unredact those secrets:
```sh
redactr unredact <<EOF
{
    "aes_secret": "secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm",
    "not_a_secret": 42,
    "vault_secret_1": "vault:path/to/kv/secret#my_key"
}
EOF
```
Output:
```json
{
    "aes_secret": "hunter2",
    "not_a_secret": 42,
    "vault_secret_1": "swordfish"
}
```

By default secrets are unredacted without the original secret wrapping.
You can add it back with the `-w` flag:

Unredact those secrets:
```sh
redactr unredact -w <<EOF
{
    "aes_secret": "secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm",
    "not_a_secret": 42,
    "vault_secret_1": "vault:path/to/kv/secret#my_key"
}
EOF
```
Output:
```json
{
    "aes_secret": "secret:hunter2:secret",
    "not_a_secret": 42,
    "vault_secret_1": "vault-secret:path/to/kv/secret#my_key#swordfish"
}
```

_Note: these examples use JSON, but `redactr` is content agnostic_

## Example (Go Library)

```go
package main

import (
	"fmt"
	"log"

	"github.com/dhoelle/redactr"
)

func main() {
	c, _ := redactr.New(
		redactr.AESKey("xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="),
	)

	plaintext := "foo secret:hunter2:secret baz"
    redacted, _ := c.RedactTokens(plaintext)
    fmt.Println(redacted) // "foo secret-encrypted:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-encrypted baz"

    unredacted, _ := c.UnredactTokens(redacted)
    fmt.Println(redacted) // "foo hunter2 baz"

    unredacted, _ = c.UnredactTokens(redacted, redactr.WrapTokens)
    fmt.Println(redacted) // "foo secret:hunter2:secret baz"
}
```

## Supported Secret types

| type            	| unredacted form                        	| redacted form                            	|
|-----------------	|---------------------------------------	|-----------------------------------------	|
| local secret    	| secret:*:secret                       	| secret-aes-256-gcm:*:secret-aes-256-gcm 	|
| vault KV secret 	| vault-secret:path/to/secret#key#value 	| vault:path/to/secret#key                	|

### Inline encrypted secrets (AES-256-GCM)

Inline secrets are encrypted with 256-bit AES-GCM.

You must supply a 32-byte key, base64 redacted. You can generate a key with `redactr key`:

```sh
$ redactr key
xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=

$ export AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="

$ redactr redact "secret:hunter2:secret"
secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm

$ redactr unredact "secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm"
hunter2

# Use the -w (--wrap) flag for reversible wrapped input
$ redactr unredact -w "secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm"
secret:hunter2:secret
```

### Hashicorp Vault

Secrets may be stored in a Hashicorp Vault instance.

The vault adapter uses the vault CLI's standard environment variables (see: https://www.vaultproject.io/docs/commands/#environment-variables)

Assuming vault has been appropriately configured, it can be used like:

```sh
$ redactr redact "vault-secret:secret/dev#my_password#hunter2"
vault:secret/dev#my_password

$ redactr unredact "vault:secret/dev#my_password"
hunter2

# Use the -w (--wrap) flag for reversible wrapped input
$ redactr unredact -w "vault:secret/dev#my_password"
vault-secret:secret/dev#my_password#hunter2
```
