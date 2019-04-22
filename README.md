# cryptr

`cryptr` enables you to keep obscured secrets alongside plaintext.

`cryptr encode` finds tokens with encodable secrets, and encodes them.

`cryptr decode` finds tokens with decodable secrets, and decodes them.

## Install

```sh
go get github.com/dhoelle/cryptr/cmd/cryptr
```

## Example (CLI)

Set some environment variables:
```
export AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=my_token
```

Encode some secrets:

```sh
cryptr encode <<EOF
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

Decode those secrets:
```sh
cryptr decode <<EOF
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

By default secrets are decoded without the original secret wrapping,
but you can add it back with the `-w` flag:
```
Decode those secrets:
```sh
cryptr decode -w <<EOF
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

_Note: these examples use JSON content, but `cryptr`
is agnostic to the content surrounding secrets_

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

## Supported Secret types

| type            	| unencoded form                        	| encoded form                            	|
|-----------------	|---------------------------------------	|-----------------------------------------	|
| local secret    	| secret:*:secret                       	| secret-aes-256-gcm:*:secret-aes-256-gcm 	|
| vault KV secret 	| vault-secret:path/to/secret#key#value 	| vault:path/to/secret#key                	|

### Inline encrypted secrets (AES-256-GCM)

Inline secrets are encrypted with 256-bit AES-GCM.

You must supply a 32-byte key, base64 encoded. You can generate a key with `cryptr key`:

```sh
$ cryptr key
xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=

$ export AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="

$ cryptr encode "secret:hunter2:secret"
secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm

$ cryptr decode "secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm"
hunter2

# Use the -w (--wrap) flag for reversible wrapped input
$ cryptr decode -w "secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm"
secret:hunter2:secret
```

### Hashicorp Vault

Secrets may be stored in a Hashicorp Vault instance.

The vault adapter uses the vault CLI's standard environment variables (see: https://www.vaultproject.io/docs/commands/#environment-variables)

Assuming vault has been appropriately configured, it can be used like:

```sh
$ cryptr encode "vault-secret:secret/dev#my_password#hunter2"
vault:secret/dev#my_password

$ cryptr decode "vault:secret/dev#my_password"
hunter2

# Use the -w (--wrap) flag for reversible wrapped input
$ cryptr decode -w "vault:secret/dev#my_password"
vault-secret:secret/dev#my_password#hunter2
```
