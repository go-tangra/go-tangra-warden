package share

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/status"

	"github.com/go-tangra/go-tangra-notification/sdk/v4/pkg/notifyclient"
)

// Dial obtains the connection to the notification module (Freya.Client).
type Dial func(ctx context.Context) (grpc.ClientConnInterface, error)

// Notification sends share mail through the notification module by system
// template key over the mTLS mesh. The connection is obtained on the first
// send, so warden starts (and serves everything else) while notification is
// still coming up; a failed dial is retried on the next send.
type Notification struct {
	dial   Dial
	log    *slog.Logger
	mu     sync.Mutex
	client *notifyclient.Client
}

// NewNotification wires the sender; nothing is dialled yet.
func NewNotification(dial Dial, log *slog.Logger) *Notification {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Notification{dial: dial, log: log}
}

func (n *Notification) conn(ctx context.Context) (*notifyclient.Client, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.client == nil {
		conn, err := n.dial(ctx)
		if err != nil {
			return nil, err
		}
		n.client = notifyclient.New(conn)
	}
	return n.client, nil
}

// Send implements Sender. Only a confirmed delivery is success: a retryable
// outcome is an error too, because the share is cancelled rather than left
// behind a link nobody received. The link never appears in logs or errors.
func (n *Notification) Send(ctx context.Context, m Message) error {
	attrs := []any{"template", m.Template, "tenant", m.TenantID, "correlation_id", m.CorrelationID}
	c, err := n.conn(ctx)
	if err != nil {
		n.log.Warn("share mail not sent: notification unreachable", append(attrs, "err", err)...)
		return errors.New("share: notification unreachable")
	}
	res, err := c.SendKey(ctx, m.TenantID, m.Template, m.To, m.Vars, m.CorrelationID)
	if err != nil {
		st := status.Convert(err)
		n.log.Warn("share mail refused by notification", append(attrs, "code", st.Code().String(), "reason", st.Message())...)
		return fmt.Errorf("share: notification refused the mail (%s)", st.Code())
	}
	if !res.Sent {
		n.log.Warn("share mail not sent", append(attrs, "log_id", res.LogID, "retryable", res.Retryable, "reason", res.Reason)...)
		return errors.New("share: notification did not deliver the mail")
	}
	n.log.Info("share mail sent", append(attrs, "log_id", res.LogID)...)
	return nil
}
