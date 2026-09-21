package generator

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	g := New()
	for _, o := range []Options{Default(), {Length: 8, Digits: true}, {Length: 128, Lower: true, Upper: true}, {Length: 12, Symbols: true, Lower: true}} {
		p, err := g.Generate(o)
		if err != nil || !Satisfies(p, o) {
			t.Fatalf("%+v → %q %v", o, p, err)
		}
	}
	// Distinct outputs and every class present across draws.
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		p, _ := g.Generate(Default())
		seen[p] = true
	}
	if len(seen) != 50 {
		t.Fatal("collisions")
	}
	for _, o := range []Options{{Length: 7, Lower: true}, {Length: 129, Lower: true}, {Length: 20}} {
		if _, err := g.Generate(o); !errors.Is(err, ErrLength) && !errors.Is(err, ErrNoClass) {
			t.Fatalf("%+v accepted", o)
		}
	}
	if !Satisfies("abc12345", Options{Length: 8, Lower: true, Digits: true}) || Satisfies("abcdefgh", Options{Length: 8, Lower: true, Digits: true}) || Satisfies("abc1234!", Options{Length: 8, Lower: true, Digits: true}) || Satisfies("short", Options{Length: 8, Lower: true}) {
		t.Fatal("Satisfies")
	}
}

func TestUniformAndInjectedReader(t *testing.T) {
	// A deterministic source yields a deterministic password; rejection sampling skips bytes >= limit.
	src := bytes.Repeat([]byte{255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, 64)
	g := NewWithReader(bytes.NewReader(src))
	p, err := g.Generate(Options{Length: 8, Lower: true})
	if err != nil || len(p) != 8 || strings.Trim(p, Lower) != "" {
		t.Fatalf("%q %v", p, err)
	}
	g2 := NewWithReader(bytes.NewReader(src))
	p2, _ := g2.Generate(Options{Length: 8, Lower: true})
	if p != p2 {
		t.Fatal("not deterministic for the same source")
	}
	// An exhausted source fails closed at every draw site.
	if _, err := NewWithReader(bytes.NewReader(nil)).Generate(Default()); err == nil {
		t.Fatal("empty source")
	}
	if _, err := NewWithReader(bytes.NewReader(make([]byte, 20))).Generate(Default()); err == nil {
		t.Fatal("source exhausted during the shuffle")
	}
	// Bias check: with n=26 and single-byte draws, values >= 234 must be rejected.
	g3 := NewWithReader(bytes.NewReader([]byte{240, 250, 234, 233}))
	n, err := g3.uniform(26)
	if err != nil || n != 233%26 {
		t.Fatalf("%d %v", n, err)
	}
}
