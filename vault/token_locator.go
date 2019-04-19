package vault

import "regexp"

// LookupTokenRE matches a vault lookup
// token, like:
//
//    vault:path/to/kv/secret#my_key
//
// A match must be isolated by word boundaries on both ends.
//
// The payload (capturing group) is the secret location
// (in the example above, "path/to/kv/secret#my_key")
var LookupTokenRE = regexp.MustCompile(`` +
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
	// be any set of characters besides #
	`[^#\s]+` +

	// Close capturing group
	`)` +

	// Must end with a word boundary
	`\b`)
