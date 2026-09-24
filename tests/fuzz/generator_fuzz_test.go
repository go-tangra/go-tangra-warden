package fuzz

import (
	"testing"

	"github.com/go-tangra/go-tangra-warden/v4/internal/generator"
)

// FuzzGenerator: options never panic and every accepted request is satisfied.
func FuzzGenerator(f *testing.F) {
	f.Add(20, true, true, true, true)
	f.Add(8, false, false, true, false)
	f.Add(128, true, false, false, true)
	f.Add(0, true, true, true, true)
	f.Add(1000, false, false, false, false)
	g := generator.New()
	f.Fuzz(func(t *testing.T, length int, lower, upper, digits, symbols bool) {
		o := generator.Options{Length: length, Lower: lower, Upper: upper, Digits: digits, Symbols: symbols}
		p, err := g.Generate(o)
		if err != nil {
			if length >= generator.MinLength && length <= generator.MaxLength && (lower || upper || digits || symbols) {
				t.Fatalf("valid options refused: %+v %v", o, err)
			}
			return
		}
		if !generator.Satisfies(p, o) {
			t.Fatalf("%+v → %q", o, p)
		}
	})
}
