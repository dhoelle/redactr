package vault

import "regexp"

// RedactedRE matches redacted secret tokens, like:
//
//    vault:path/to/kv/secret#my_key
//
// A match must be isolated by word boundaries on both ends.
//
// The payload (capturing group) is the secret location
// (in the example above, "path/to/kv/secret#my_key")
var RedactedRE = regexp.MustCompile(`` +
	// Must start after a word boundary
	`\b` +

	// Must start with vault:
	`vault:` +

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

	// Must end with a word boundary
	`\b`)

// UnredactedRE matches redacted secret tokens, like:
//
//    vault-secret:path/to/kv/secret#my_key#my_value
//
// A match must be isolated by word boundaries on both ends.
//
// The payload (capturing group) is the secret path+key+value
// (in the example above, "path/to/kv/secret#my_key#my_value")
var UnredactedRE = regexp.MustCompile(`` +
	// Must start after a word boundary
	`\b` +

	// Must start with vault:
	`vault-secret:` +

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

	// Must end with a word boundary
	`\b`)
