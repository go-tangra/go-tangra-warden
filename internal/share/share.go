// Package share hands a secret to an outsider: a time-limited link mailed to
// a recipient, backed by a 256-bit token stored only as its SHA-256, with an
// open budget and an optional network policy. Every refusal on the public
// side is a uniform not-found; every creation, disclosure, refusal and
// cancellation is audited.
package share

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/store"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

// Bounds (contracts/warden-api.openapi.yaml).
const (
	MinValidity = 300
	MaxValidity = 7 * 24 * 3600
	MinOpens    = 1
	MaxOpens    = 10
	MessageMax  = 1000
	TokenLength = 43 // 32 bytes, base64url, no padding
)

// Errors.
var (
	ErrNotFound          = authz.ErrNotFound // uniform on the public side and for foreign resources
	ErrInvalid           = errors.New("share: invalid input")
	ErrRegionUnavailable = errors.New("share: region policies unavailable")
	ErrForbidden         = authz.ErrForbidden
	ErrMail              = errors.New("share: mail delivery failed")
)

var tokenRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Store is the persistence share uses (repo.Store satisfies it).
type Store interface {
	GetSecret(ctx context.Context, tenantID, id string) (store.Secret, error)
	InsertShare(ctx context.Context, s store.Share) error
	ShareByTokenHash(ctx context.Context, hash string) (store.Share, error)
	GetShare(ctx context.Context, tenantID, id string) (store.Share, error)
	SharesOfSecret(ctx context.Context, tenantID, secretID, createdBy string) ([]store.Share, error)
	ConsumeShareOpen(ctx context.Context, id string) (store.Share, error)
	SetShareState(ctx context.Context, tenantID, id, state string) error
	ExpireShares(ctx context.Context, now time.Time) (int64, error)
}

// Config tunes defaults and the public origin of links.
type Config struct {
	PublicOrigin    string
	DefaultValidity time.Duration
	DefaultMaxOpens int
}

// Service manages shares.
type Service struct {
	st    Store
	vault vault.Store
	az    *authz.Authz
	audit *audit.Writer
	mail  Sender
	cfg   Config
	now   func() time.Time
	rand  io.Reader
}

// New wires the service.
func New(st Store, v vault.Store, az *authz.Authz, aw *audit.Writer, mail Sender, cfg Config) *Service {
	if cfg.DefaultValidity <= 0 {
		cfg.DefaultValidity = time.Hour
	}
	if cfg.DefaultMaxOpens <= 0 {
		cfg.DefaultMaxOpens = 1
	}
	return &Service{st: st, vault: v, az: az, audit: aw, mail: mail, cfg: cfg, now: time.Now, rand: rand.Reader}
}

// SetClock / SetRandom inject the clock and the random source (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }
func (s *Service) SetRandom(r io.Reader)         { s.rand = r }

// NewToken draws a 256-bit token as 43 base64url characters.
func NewToken(r io.Reader) (string, error) {
	var b [32]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", errors.New("share: random source failed")
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ValidToken reports whether s has the token shape.
func ValidToken(s string) bool { return tokenRE.MatchString(s) }

// Hash is the constant-length SHA-256 hex of a token; only this is stored.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Input creates a share.
type Input struct {
	RecipientEmail  string
	Message         string
	ValiditySeconds int
	MaxOpens        int
	CIDR            string
	Region          string
}

// View is a share as returned to its creator (never the token).
type View struct {
	ID             string    `json:"id"`
	SecretID       string    `json:"secret_id"`
	RecipientEmail string    `json:"recipient_email"`
	Message        string    `json:"message,omitempty"`
	MaxOpens       int       `json:"max_opens"`
	Opens          int       `json:"opens"`
	ExpiresAt      time.Time `json:"expires_at"`
	CIDR           string    `json:"cidr,omitempty"`
	Region         string    `json:"region,omitempty"`
	State          string    `json:"state"`
	CreatedAt      time.Time `json:"created_at"`
}

func view(sh store.Share) View {
	v := View{ID: sh.ID, SecretID: sh.SecretID, RecipientEmail: sh.RecipientEmail, Message: sh.Message, MaxOpens: sh.MaxOpens, Opens: sh.Opens, ExpiresAt: sh.ExpiresAt, State: sh.State, CreatedAt: sh.CreatedAt}
	if sh.CIDR != nil {
		v.CIDR = *sh.CIDR
	}
	if sh.Region != nil {
		v.Region = *sh.Region
	}
	return v
}

func (s *Service) emit(e audit.Event) {
	if s.audit != nil {
		_ = s.audit.Emit(e)
	}
}

// Create mails a link for a secret the caller may share.
func (s *Service) Create(ctx context.Context, subj authz.Subjects, secretID string, in Input) (View, error) {
	addr, err := mail.ParseAddress(in.RecipientEmail)
	if err != nil || addr.Name != "" || len(in.RecipientEmail) > 254 || strings.ContainsAny(in.RecipientEmail, "<>\r\n") {
		return View{}, ErrInvalid
	}
	if len(in.Message) > MessageMax || strings.ContainsAny(in.Message, "\x00") {
		return View{}, ErrInvalid
	}
	validity := in.ValiditySeconds
	if validity == 0 {
		validity = int(s.cfg.DefaultValidity / time.Second)
	}
	if validity < MinValidity || validity > MaxValidity {
		return View{}, ErrInvalid
	}
	opens := in.MaxOpens
	if opens == 0 {
		opens = s.cfg.DefaultMaxOpens
	}
	if opens < MinOpens || opens > MaxOpens {
		return View{}, ErrInvalid
	}
	var cidr, region *string
	if in.CIDR != "" {
		if _, _, err := net.ParseCIDR(in.CIDR); err != nil {
			return View{}, ErrInvalid
		}
		c := in.CIDR
		cidr = &c
	}
	if in.Region != "" {
		// No GeoIP source is configured: region policies cannot be honoured
		// and are refused rather than silently ignored.
		return View{}, ErrRegionUnavailable
	}
	if _, err := s.az.Require(ctx, subj, authz.Secret, secretID, authz.Share); err != nil {
		return View{}, err
	}
	sec, err := s.st.GetSecret(ctx, subj.TenantID, secretID)
	if err != nil {
		return View{}, notFound(err)
	}
	token, err := NewToken(s.rand)
	if err != nil {
		return View{}, err
	}
	now := s.now()
	sh := store.Share{ID: store.NewID(), TenantID: subj.TenantID, SecretID: secretID, TokenHash: Hash(token), RecipientEmail: addr.Address, Message: in.Message,
		MaxOpens: opens, ExpiresAt: now.Add(time.Duration(validity) * time.Second), CIDR: cidr, Region: region, State: "active", CreatedBy: subj.UserID}
	if err := s.st.InsertShare(ctx, sh); err != nil {
		return View{}, err
	}
	// The token rides in the fragment: browsers never send it to any server,
	// so it cannot land in gateway, proxy or module request logs.
	link := strings.TrimRight(s.cfg.PublicOrigin, "/") + "/warden/share#" + token
	text := fmt.Sprintf("A credential named %q has been shared with you.\n\nOpen it here (valid until %s, %d opening(s)):\n\n%s\n", sec.Name, sh.ExpiresAt.UTC().Format(time.RFC1123), opens, link)
	if in.Message != "" {
		text += "\nMessage from the sender:\n" + in.Message + "\n"
	}
	if err := s.mail.Send(ctx, Message{To: addr.Address, Subject: "A credential was shared with you", Text: text}); err != nil {
		_ = s.st.SetShareState(ctx, subj.TenantID, sh.ID, "cancelled")
		s.emit(audit.Event{Type: audit.ShareCreated, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "share", SubjectID: sh.ID, Outcome: "failed", Reason: "mail_failed",
			Details: map[string]any{"secret_id": secretID}})
		return View{}, ErrMail
	}
	s.emit(audit.Event{Type: audit.ShareCreated, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "share", SubjectID: sh.ID, Outcome: "ok",
		Details: map[string]any{"secret_id": secretID, "recipient": addr.Address, "max_opens": opens, "validity_seconds": validity, "cidr": cidr != nil}})
	return view(sh), nil
}

func notFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

// Disclosure is what a recipient sees on a successful open.
type Disclosure struct {
	Name      string `json:"name"`
	Username  string `json:"username"`
	HostURL   string `json:"host_url"`
	Password  string `json:"password"`
	OpensLeft int    `json:"opens_left"`
	Message   string `json:"message,omitempty"`
}

// Open discloses the secret behind a token once; every refusal (bad token,
// unknown, expired, exhausted, cancelled, policy mismatch) is ErrNotFound
// and audited as share_refused. clientAddr is the address relayed by the
// gateway ("" when it was not).
func (s *Service) Open(ctx context.Context, token, clientAddr string) (Disclosure, error) {
	if !ValidToken(token) {
		return Disclosure{}, ErrNotFound
	}
	sh, err := s.st.ShareByTokenHash(ctx, Hash(token))
	if err != nil {
		return Disclosure{}, notFound(err)
	}
	refuse := func(reason string) (Disclosure, error) {
		s.emit(audit.Event{Type: audit.ShareRefused, TenantID: sh.TenantID, ActorKind: "recipient", ActorID: sh.RecipientEmail, SubjectKind: "share", SubjectID: sh.ID, Outcome: "refused", Reason: reason})
		return Disclosure{}, ErrNotFound
	}
	now := s.now()
	switch {
	case sh.State != "active":
		return refuse(sh.State)
	case !sh.ExpiresAt.After(now):
		return refuse("expired")
	case sh.Opens >= sh.MaxOpens:
		return refuse("exhausted")
	}
	if sh.CIDR != nil {
		_, network, err := net.ParseCIDR(*sh.CIDR)
		ip := net.ParseIP(strings.TrimSpace(clientAddr))
		if err != nil || ip == nil || !network.Contains(ip) {
			return refuse("cidr")
		}
	}
	// Material is read before the open is consumed so a vault failure never
	// burns an opening; disclosure happens only after the atomic increment.
	sec, err := s.st.GetSecret(ctx, sh.TenantID, sh.SecretID)
	if err != nil {
		return refuse("secret_gone")
	}
	pw, err := s.vault.GetPassword(ctx, sh.TenantID, sh.SecretID, 0)
	if err != nil {
		s.emit(audit.Event{Type: audit.ShareOpened, TenantID: sh.TenantID, ActorKind: "recipient", ActorID: sh.RecipientEmail, SubjectKind: "share", SubjectID: sh.ID, Outcome: "failed", Reason: "vault_unavailable"})
		return Disclosure{}, err
	}
	opened, err := s.st.ConsumeShareOpen(ctx, sh.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return refuse("exhausted")
		}
		return Disclosure{}, err
	}
	s.emit(audit.Event{Type: audit.ShareOpened, TenantID: sh.TenantID, ActorKind: "recipient", ActorID: sh.RecipientEmail, SubjectKind: "share", SubjectID: sh.ID, Outcome: "ok",
		Details: map[string]any{"secret_id": sh.SecretID, "opens": opened.Opens, "max_opens": opened.MaxOpens, "client_address_checked": sh.CIDR != nil}})
	return Disclosure{Name: sec.Name, Username: sec.Username, HostURL: sec.HostURL, Password: pw, OpensLeft: opened.MaxOpens - opened.Opens, Message: sh.Message}, nil
}

// Cancel ends an active share; the creator or anyone who may share the
// secret can cancel.
func (s *Service) Cancel(ctx context.Context, subj authz.Subjects, shareID string) error {
	sh, err := s.st.GetShare(ctx, subj.TenantID, shareID)
	if err != nil {
		return notFound(err)
	}
	if sh.CreatedBy != subj.UserID {
		if _, err := s.az.Require(ctx, subj, authz.Secret, sh.SecretID, authz.Share); err != nil {
			return err
		}
	}
	if err := s.st.SetShareState(ctx, subj.TenantID, shareID, "cancelled"); err != nil {
		return notFound(err)
	}
	s.emit(audit.Event{Type: audit.ShareCancelled, TenantID: subj.TenantID, ActorKind: "user", ActorID: subj.UserID, SubjectKind: "share", SubjectID: shareID, Outcome: "ok",
		Details: map[string]any{"secret_id": sh.SecretID}})
	return nil
}

// List returns the caller's shares of a secret they may share.
func (s *Service) List(ctx context.Context, subj authz.Subjects, secretID string) ([]View, error) {
	if _, err := s.az.Require(ctx, subj, authz.Secret, secretID, authz.Share); err != nil {
		return nil, err
	}
	rows, err := s.st.SharesOfSecret(ctx, subj.TenantID, secretID, subj.UserID)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(rows))
	now := s.now()
	for _, sh := range rows {
		v := view(sh)
		if v.State == "active" && !sh.ExpiresAt.After(now) {
			v.State = "expired"
		}
		out = append(out, v)
	}
	return out, nil
}

// Sweep marks expired shares (periodic).
func (s *Service) Sweep(ctx context.Context) (int64, error) {
	return s.st.ExpireShares(ctx, s.now())
}

// RunSweeper runs Sweep every interval until ctx ends.
func (s *Service) RunSweeper(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Sweep(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
