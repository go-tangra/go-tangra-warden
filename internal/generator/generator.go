// Package generator produces random passwords from a cryptographic source:
// every requested character class is present at least once and characters
// are chosen uniformly (rejection sampling, no modulo bias). Output is never
// logged or audited.
package generator

import (
	"crypto/rand"
	"errors"
	"io"
)

// Bounds (contracts/warden-api.openapi.yaml).
const (
	MinLength = 8
	MaxLength = 128
)

// Character classes.
const (
	Lower   = "abcdefghijklmnopqrstuvwxyz"
	Upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits  = "0123456789"
	Symbols = "!@#$%^&*()-_=+[]{};:,.<>?/~"
)

// Options selects length and classes.
type Options struct {
	Length  int
	Lower   bool
	Upper   bool
	Digits  bool
	Symbols bool
}

// Errors.
var (
	ErrLength  = errors.New("generator: length out of bounds")
	ErrNoClass = errors.New("generator: at least one character class is required")
)

// Default is 20 characters from every class.
func Default() Options {
	return Options{Length: 20, Lower: true, Upper: true, Digits: true, Symbols: true}
}

// Generator draws from a random source (crypto/rand unless injected).
type Generator struct{ rand io.Reader }

// New returns a generator over crypto/rand.
func New() *Generator { return &Generator{rand: rand.Reader} }

// NewWithReader injects the random source (tests).
func NewWithReader(r io.Reader) *Generator { return &Generator{rand: r} }

// classes lists the selected alphabets in a stable order.
func (o Options) classes() []string {
	var out []string
	if o.Lower {
		out = append(out, Lower)
	}
	if o.Upper {
		out = append(out, Upper)
	}
	if o.Digits {
		out = append(out, Digits)
	}
	if o.Symbols {
		out = append(out, Symbols)
	}
	return out
}

// Validate checks the options.
func (o Options) Validate() error {
	if o.Length < MinLength || o.Length > MaxLength {
		return ErrLength
	}
	if len(o.classes()) == 0 {
		return ErrNoClass
	}
	return nil
}

// Generate returns a password satisfying the options.
func (g *Generator) Generate(o Options) (string, error) {
	if err := o.Validate(); err != nil {
		return "", err
	}
	classes := o.classes()
	all := ""
	for _, c := range classes {
		all += c
	}
	out := make([]byte, o.Length)
	// One character from each class first, then the rest from the union.
	for i := range out {
		alphabet := all
		if i < len(classes) {
			alphabet = classes[i]
		}
		n, err := g.uniform(len(alphabet))
		if err != nil {
			return "", err
		}
		out[i] = alphabet[n]
	}
	// Fisher–Yates so the class-guaranteed characters are not positional.
	for i := len(out) - 1; i > 0; i-- {
		j, err := g.uniform(i + 1)
		if err != nil {
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

// uniform draws an integer in [0, n) without modulo bias.
func (g *Generator) uniform(n int) (int, error) {
	limit := 256 - (256 % n)
	var b [1]byte
	for {
		if _, err := io.ReadFull(g.rand, b[:]); err != nil {
			return 0, errors.New("generator: random source failed")
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}

// Satisfies reports whether p meets the options (tests, fuzzing).
func Satisfies(p string, o Options) bool {
	if len(p) != o.Length {
		return false
	}
	for _, c := range o.classes() {
		found := false
		for i := 0; i < len(p); i++ {
			if indexByte(c, p[i]) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	all := ""
	for _, c := range o.classes() {
		all += c
	}
	for i := 0; i < len(p); i++ {
		if !indexByte(all, p[i]) {
			return false
		}
	}
	return true
}

func indexByte(s string, b byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return true
		}
	}
	return false
}
