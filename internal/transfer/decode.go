// Package transfer moves credentials in and out: Bitwarden JSON import
// (validate, then import with a duplicate strategy) and export, and tenant
// backups with or without material. Documents are decoded with bounds on
// size, nesting depth and counts before anything is interpreted.
package transfer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Limits (research R6/R7).
const (
	MaxBytes   = 16 << 20
	MaxDepth   = 8
	MaxItems   = 50000
	MaxFolders = 10000
)

// Errors.
var (
	ErrTooLarge  = errors.New("transfer: document too large")
	ErrTooDeep   = errors.New("transfer: document nested too deep")
	ErrMalformed = errors.New("transfer: malformed document")
	ErrInvalid   = errors.New("transfer: invalid document")
)

// ReadBounded reads at most limit bytes; more is ErrTooLarge.
func ReadBounded(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}

// Depth returns the maximum nesting depth of a JSON document or an error
// when it is not well formed.
func Depth(data []byte) (int, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	depth, max := 0, 0
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, ErrMalformed
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
				if depth > max {
					max = depth
				}
			case '}', ']':
				depth--
			}
		}
	}
	if depth != 0 {
		return 0, ErrMalformed
	}
	return max, nil
}

// DecodeBounded checks size and depth, then decodes into v.
func DecodeBounded(data []byte, v any) error {
	if len(data) > MaxBytes {
		return ErrTooLarge
	}
	d, err := Depth(data)
	if err != nil {
		return err
	}
	if d > MaxDepth {
		return ErrTooDeep
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return nil
}
