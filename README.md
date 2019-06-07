# redactr

[![Build Status](https://cloud.drone.io/api/badges/dhoelle/redactr/status.svg)](https://cloud.drone.io/dhoelle/redactr) [![](https://godoc.org/github.com/dhoelle/redactr?status.svg)](http://godoc.org/github.com/dhoelle/redactr) [![Go Report Card](https://goreportcard.com/badge/github.com/dhoelle/redactr)](https://goreportcard.com/report/github.com/dhoelle/redactr) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`redactr` replaces **secrets** with **Redacted Secrets**.

With the right privileges, `redactr` can replace **Redacted Secrets** with **secrets**.

Table of Contents
=================

   * [redactr](#redactr)
      * [Install](#install)
         * [Binary](#binary)
         * [Brew (Mac OS)](#brew-mac-os)
         * [Build from source](#build-from-source)
      * [Example (CLI)](#example-cli)
         * [Redact secrets](#redact-secrets)
         * [Unredact secrets](#unredact-secrets)
         * [Execute commands](#execute-commands)
            * [Re-evaluating the environment](#re-evaluating-the-environment)
      * [Example (Docker)](#example-docker)
      * [Supported Secret types](#supported-secret-types)
         * [Inline encrypted secrets (AES-256-GCM)](#inline-encrypted-secrets-aes-256-gcm)
         * [Hashicorp Vault](#hashicorp-vault)

## Install

### Binary
Binaries are available on [the releases page](https://github.com/dhoelle/redactr/releases)

### Brew (Mac OS)

```sh
brew tap dhoelle/tap
brew install dhoelle/tap/redactr
```

### Build from source

_Requires Go >1.11_
```sh
go get github.com/dhoelle/redactr/cmd/redactr
```

## Example (CLI)

First, set some environment variables, which `redactr` will use to redact and unredact secrets:

```
export AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=my_token
```

### Redact secrets

```sh
redactr redact <<EOF
My email password is secret:hunter2:secret
My database password is vault-secret:path/to/kv/secret#my_key#swordfish
EOF
# output:
# My email password is secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm
# My database password is vault:path/to/kv/secret#my_key
```

### Unredact secrets

```sh
redactr unredact <<EOF
My email password is secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm
My database password is vault:path/to/kv/secret#my_key
EOF
# output:
# My email password is hunter2
# My database password is swordfish
```

By default secrets are unredacted without the original secret wrapping.
You can add it back with the `-w`/`--wrap-tokens` flag:

```sh
redactr unredact -w <<EOF
My email password is secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm
My database password is vault:path/to/kv/secret#my_key
EOF
# output:
# My email password is secret:hunter2:secret
# My database password is vault-secret:path/to/kv/secret#my_key#swordfish
```

### Execute commands

`redactr exec` executes commands with redacted secrets in its environment

```sh
PASSWORD="secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm" \
redactr exec echo 'my password is $PASSWORD'
# output: my password is hunter2
```

#### Re-evaluating the environment

Some `redactr` secrets are dynamic. For example, passwords in a `vault` instance can change over time.

`redactr exec` can be configured to periodically unredact the 
secrets that a command uses and, if they have changed,
either stop or restart the command.

The following example creates a local vault instance and
changes a password every second, then runs a command with
`redactr exec` which re-runs on each change:

```
# Start a local vault instance
docker run -d --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -p 8222:8200 vault
sleep 1

# Start a background job which changes a secret every second for 20 seconds
func changesecrets() {
    for i in {1..10}
    do
        VAULT_ADDR=http://0.0.0.0:8222 VAULT_TOKEN=myroot vault kv put secret/db_password value=hunter2
        sleep 1
        VAULT_ADDR=http://0.0.0.0:8222 VAULT_TOKEN=myroot vault kv put secret/db_password value=swordfish
        sleep 1
    done
}
changesecrets &>/dev/null &
sleep 1

# use `redactr exec` to print the secret and block.
# Each time the secret changes, the command will
# restart and the new secret will be printed.
VAULT_ADDR=http://localhost:8222 \
VAULT_TOKEN=myroot \
SECRET_KEY=vault:secret/data/db_password#value \
redactr exec \
    -r 1000ms 
    /bin/bash -c 'echo "$(date): secret key: $SECRET_KEY"; sleep 3'

# example output:
# Tue Apr 30 18:42:24 PDT 2019: secret key: swordfish
# Tue Apr 30 18:42:25 PDT 2019: secret key: hunter2
# Tue Apr 30 18:42:26 PDT 2019: secret key: swordfish
# ...

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

## Example (Docker)

A docker image is available: https://cloud.docker.com/repository/docker/dhoelle/redactr

```sh
$ docker run \
    -e AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=" \
    dhoelle/redactr \
    unredact "secret-aes-256-gcm:DYeT3hCH1unjeWl9whMhjn/ILcM3r24XaX7xgWO8sOJkvCs=:secret-aes-256-gcm"

# output:
# hunter2
```

## Secret types

| type            	| unredacted form                        	| redacted form                            	|
|-----------------	|---------------------------------------	|-----------------------------------------	|
| local secret    	| secret:*:secret                       	| secret-aes-256-gcm:*:secret-aes-256-gcm 	|
| vault KV secret 	| vault-secret:path/to/secret#key#value 	| vault:path/to/secret#key                	|

### Encrypted secrets (AES-256-GCM)

Secrets can be redacted via 256-bit AES-GCM encryption. 

```sh
$ redactr key
xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc=

$ export AES_KEY="xuY6/V0ZE29RtPD3TNWga/EkdU3XYsPtBIk8U4nzZyc="

$ redactr redact "secret:hunter2:secret"
secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm

$ redactr unredact "secret-aes-256-gcm:JOf+CmAfgyCSbesz6zstfUx7gHIuJ/JMeyyf8UqCGvkxjkc=:secret-aes-256-gcm"
hunter2

# Use the -w (--wrap) flag to return a reversible wrapped secret
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

# Use the -w (--wrap) flag to return a reversible wrapped secret
$ redactr unredact -w "vault:secret/dev#my_password"
vault-secret:secret/dev#my_password#hunter2
```
