package vault

import "regexp"

// RedactedRE matches redacted secret tokens, like:
//
//    ~~redacted-vault:path/to/kv/secret#my_key~~
//
// A match must be isolated by word boundaries on both ends.
//
// The payload (capturing group) is the secret location
// (in the example above, "path/to/kv/secret#my_key")
var RedactedRE = regexp.MustCompile(`` +
	// Must start with ~~redacted-vault:
	`~~redacted-vault:` +

	// Begin capturing group to capture the token
	`(` +

	// Match a secret path, which can
	// be any non-whitespace characters besides #
	`[^#\s]+` +

	// A literal # must separate the path and the key
	`#` +

	// Match the secret key, which can
	// be any non-whitespace characters besides #
	`[^#\s]+` +

	// Close capturing group
	`)` +

	// Must end with ~~
	`~~`)

// UnredactedRE matches unredacted secret tokens, like:
//
//    ~~redact-vault:path/to/kv/secret#my_key#my_value~~
//
// A match must be isolated by word boundaries on both ends.
//
// The payload (capturing group) is the secret path+key+value
// (in the example above, "path/to/kv/secret#my_key#my_value")
var UnredactedRE = regexp.MustCompile(`` +
	// Must start with ~~redact-vault:
	`~~redact-vault:` +

	// Begin capturing group to capture the token
	`(` +

	// Match a secret path, which can
	// be any non-whitespace characters besides #
	`[^#\s]+` +

	// A literal # must separate the path and the key
	`#` +

	// Match the secret key, which can
	// be any non-whitespace characters besides #
	`[^#\s]+` +

	// A literal # must separate the key and value
	`#` +

	// Match the secret value, which can
	// be any non-whitespace characters besides #
	`[^#\s]+` +

	// Close capturing group
	`)` +

	// Must end with ~~
	`~~`)
