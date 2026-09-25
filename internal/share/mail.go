package share

import (
	"context"
	"log/slog"
)

// TemplateShare is the notification system template carrying a share link.
// Its variables: link (secret: redacted in notification's delivery log),
// secret_name, expires, openings and the optional message.
const TemplateShare = "warden.share"

// Message is one transactional mail: a notification system template sent to
// one recipient for a tenant. The wording lives in the template; warden only
// supplies the variables.
type Message struct {
	To            string
	Template      string
	Vars          map[string]string
	TenantID      string
	CorrelationID string // the share id: ties notification's log entry to warden's audit
}

// Sender delivers a message; any error means the recipient will not get it.
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// LogSink records that a mail would have been sent (development). The
// variables carry the share link, so only the recipient and the template are
// logged.
type LogSink struct{ Log *slog.Logger }

// Send implements Sender.
func (l LogSink) Send(_ context.Context, m Message) error {
	if l.Log != nil {
		l.Log.Info("mail (dev sink, variables withheld)", "to", m.To, "template", m.Template)
	}
	return nil
}
