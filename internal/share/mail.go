package share

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

// Message is one transactional mail.
type Message struct {
	To, Subject, Text string
}

// Sender delivers a message.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// SMTPConfig configures the SMTP sender; TLS is required unless AllowPlaintext.
type SMTPConfig struct {
	Host, Username, Password, From string
	Port                           int
	AllowPlaintext                 bool
}

// SMTP sends through a relay with implicit TLS (465) or STARTTLS (587).
type SMTP struct{ cfg SMTPConfig }

// NewSMTP validates the configuration.
func NewSMTP(cfg SMTPConfig) (*SMTP, error) {
	if cfg.Host == "" || cfg.Port <= 0 || cfg.From == "" {
		return nil, errors.New("share: mail host, port and from are required")
	}
	if !cfg.AllowPlaintext && cfg.Port != 465 && cfg.Port != 587 {
		return nil, errors.New("share: mail TLS is required (port 465 or 587) unless allow_plaintext")
	}
	return &SMTP{cfg: cfg}, nil
}

// Send delivers via net/smtp (STARTTLS negotiated when offered).
func (s *SMTP) Send(_ context.Context, m Message) error {
	body := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		s.cfg.From, sanitizeHeader(m.To), sanitizeHeader(m.Subject), m.Text)
	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)
	}
	return smtp.SendMail(fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port), auth, s.cfg.From, []string{m.To}, []byte(body))
}

func sanitizeHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

// LogSink records that a mail would have been sent (development). The body
// carries the share link, so only the recipient and subject are logged.
type LogSink struct{ Log *slog.Logger }

// Send implements Sender.
func (l LogSink) Send(_ context.Context, m Message) error {
	if l.Log != nil {
		l.Log.Info("mail (dev sink, body withheld)", "to", m.To, "subject", m.Subject)
	}
	return nil
}
