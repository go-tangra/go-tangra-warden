// Package openapi embeds the warden browser API contract.
package openapi

import _ "embed"

// Warden is the OpenAPI 3.1 document served and validated by the service.
//
//go:embed warden.yaml
var Warden []byte
