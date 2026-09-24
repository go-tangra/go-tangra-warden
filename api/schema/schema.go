// Package schema embeds the Bitwarden import document schema.
package schema

import _ "embed"

// Bitwarden is the JSON Schema of the accepted Bitwarden export.
//
//go:embed bitwarden.schema.json
var Bitwarden []byte
