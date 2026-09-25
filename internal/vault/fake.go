package vault

import (
	"context"
	"sync"
)

// Fake is an in-memory Store with KV v2 version semantics for unit tests.
type Fake struct {
	mu          sync.Mutex
	passwords   map[string][]string // path → versions (index+1 = version); "" = destroyed
	totp        map[string]string
	Down        bool // every call fails with ErrUnavailable
	FailAfter   int  // fail the n-th write (1-based); 0 = never
	writes      int
	HealthState Health
}

// NewFake returns an empty fake.
func NewFake() *Fake {
	return &Fake{passwords: map[string][]string{}, totp: map[string]string{}, HealthState: HealthOK}
}

func (f *Fake) gate() error {
	if f.Down {
		return ErrUnavailable
	}
	return nil
}

func (f *Fake) PutPassword(_ context.Context, tenantID, secretID, password string) (int, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return 0, err
	}
	f.writes++
	if f.FailAfter > 0 && f.writes >= f.FailAfter {
		return 0, ErrUnavailable
	}
	f.passwords[p] = append(f.passwords[p], password)
	return len(f.passwords[p]), nil
}

// SkipVersion consumes a version number without material (see Client.SkipVersion).
func (f *Fake) SkipVersion(_ context.Context, tenantID, secretID string) (int, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return 0, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return 0, err
	}
	f.writes++
	if f.FailAfter > 0 && f.writes >= f.FailAfter {
		return 0, ErrUnavailable
	}
	f.passwords[p] = append(f.passwords[p], "")
	return len(f.passwords[p]), nil
}

func (f *Fake) GetPassword(_ context.Context, tenantID, secretID string, version int) (string, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return "", err
	}
	vs := f.passwords[p]
	if len(vs) == 0 {
		return "", ErrNotFound
	}
	if version <= 0 {
		version = len(vs)
	}
	if version > len(vs) || vs[version-1] == "" {
		return "", ErrNotFound
	}
	return vs[version-1], nil
}

func (f *Fake) Versions(_ context.Context, tenantID, secretID string) ([]int, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return nil, err
	}
	var out []int
	for i, v := range f.passwords[p] {
		if v != "" {
			out = append(out, i+1)
		}
	}
	return out, nil
}

func (f *Fake) DeleteSecret(_ context.Context, tenantID, secretID string) error {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return err
	}
	delete(f.passwords, p)
	delete(f.totp, p)
	return nil
}

func (f *Fake) PutTOTP(_ context.Context, tenantID, secretID, seed string) error {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return err
	}
	f.writes++
	if f.FailAfter > 0 && f.writes >= f.FailAfter {
		return ErrUnavailable
	}
	f.totp[p] = seed
	return nil
}

func (f *Fake) GetTOTP(_ context.Context, tenantID, secretID string) (string, error) {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return "", err
	}
	s, ok := f.totp[p]
	if !ok {
		return "", ErrNotFound
	}
	return s, nil
}

func (f *Fake) DeleteTOTP(_ context.Context, tenantID, secretID string) error {
	p, err := Path(tenantID, secretID)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.gate(); err != nil {
		return err
	}
	delete(f.totp, p)
	return nil
}

func (f *Fake) Health(context.Context) Health {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return HealthUnreachable
	}
	return f.HealthState
}

// Dump returns every stored value (tests: material-leak assertions on the fake itself).
func (f *Fake) Dump() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, vs := range f.passwords {
		out = append(out, vs...)
	}
	for _, s := range f.totp {
		out = append(out, s)
	}
	return out
}

// Writes returns the number of write calls so far (tests aim FailAfter).
func (f *Fake) Writes() int { f.mu.Lock(); defer f.mu.Unlock(); return f.writes }
