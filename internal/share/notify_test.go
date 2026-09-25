package share

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	notificationv1 "github.com/go-tangra/go-tangra-notification/sdk/v4/api/proto/notification/v1"
)

// fakeNotifier is a notification.v1.Notifier server recording key sends.
type fakeNotifier struct {
	notificationv1.UnimplementedNotifierServer
	mu   sync.Mutex
	reqs []*notificationv1.SendRequest
	resp *notificationv1.SendResponse
	err  error
}

func (f *fakeNotifier) Send(_ context.Context, in *notificationv1.SendRequest) (*notificationv1.SendResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, in)
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
}

func (f *fakeNotifier) set(resp *notificationv1.SendResponse, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resp, f.err = resp, err
}

type notifyFx struct {
	fake  *fakeNotifier
	dials int
	fail  error
	log   bytes.Buffer
	n     *Notification
}

func newNotifyFx(t *testing.T) *notifyFx {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	fx := &notifyFx{fake: &fakeNotifier{resp: &notificationv1.SendResponse{LogId: "log-1", Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_SENT}}}
	notificationv1.RegisterNotifierServer(srv, fx.fake)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	fx.n = NewNotification(func(context.Context) (grpc.ClientConnInterface, error) {
		fx.dials++
		if fx.fail != nil {
			return nil, fx.fail
		}
		return conn, nil
	}, slog.New(slog.NewTextHandler(&fx.log, nil)))
	return fx
}

const testLink = "https://platform.example.org/warden/share#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func shareMsg() Message {
	return Message{To: "bob@x.test", Template: TemplateShare, TenantID: tA, CorrelationID: "share-1",
		Vars: map[string]string{"link": testLink, "secret_name": "prod-db", "expires": "Tue, 14 Nov 2023 23:13:20 UTC", "openings": "1"}}
}

func TestNotificationSendsKey(t *testing.T) {
	fx := newNotifyFx(t)
	if fx.dials != 0 {
		t.Fatal("connection must be obtained lazily, on first send")
	}
	ctx := context.Background()
	if err := fx.n.Send(ctx, shareMsg()); err != nil {
		t.Fatal(err)
	}
	if err := fx.n.Send(ctx, shareMsg()); err != nil {
		t.Fatal(err)
	}
	if fx.dials != 1 {
		t.Fatalf("dialled %d times, want 1 (connection reused)", fx.dials)
	}
	if len(fx.fake.reqs) != 2 {
		t.Fatalf("%d requests", len(fx.fake.reqs))
	}
	r := fx.fake.reqs[0]
	if r.GetTenantId() != tA || r.GetTemplateKey() != "warden.share" || r.GetTemplateId() != "" || r.GetRecipient() != "bob@x.test" || r.GetCorrelationId() != "share-1" ||
		r.GetVariables()["link"] != testLink || r.GetVariables()["secret_name"] != "prod-db" || r.GetVariables()["openings"] != "1" {
		t.Fatalf("request %+v", r)
	}
	if strings.Contains(fx.log.String(), "warden/share#") {
		t.Fatalf("link logged: %s", fx.log.String())
	}
}

func TestNotificationConnectionFailure(t *testing.T) {
	fx := newNotifyFx(t)
	fx.fail = errors.New("no notification endpoint")
	if err := fx.n.Send(context.Background(), shareMsg()); err == nil {
		t.Fatal("dial failure must fail the send")
	}
	// A failed dial is not remembered: the next send tries again.
	fx.fail = nil
	if err := fx.n.Send(context.Background(), shareMsg()); err != nil {
		t.Fatal(err)
	}
	if fx.dials != 2 {
		t.Fatalf("dials %d", fx.dials)
	}
}

func TestNotificationFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		resp *notificationv1.SendResponse
		err  error
	}{
		"retryable outcome": {resp: &notificationv1.SendResponse{LogId: "l", Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_FAILED, Error: "relay 451", Retryable: true}},
		"permanent outcome": {resp: &notificationv1.SendResponse{LogId: "l", Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_FAILED, Error: "relay 550"}},
		"pending":           {resp: &notificationv1.SendResponse{LogId: "l", Status: notificationv1.DeliveryStatus_DELIVERY_STATUS_PENDING}},
		"unavailable":       {err: status.Error(codes.Unavailable, "down")},
		"throttled":         {err: status.Error(codes.ResourceExhausted, "slow down")},
		"foreign namespace": {err: status.Error(codes.PermissionDenied, "key outside namespace")},
		"not configured":    {err: status.Error(codes.FailedPrecondition, "email_not_configured")},
	} {
		t.Run(name, func(t *testing.T) {
			fx := newNotifyFx(t)
			fx.fake.set(tc.resp, tc.err)
			err := fx.n.Send(context.Background(), shareMsg())
			if err == nil {
				t.Fatal("undelivered mail reported as sent")
			}
			if strings.Contains(err.Error(), "warden/share#") || strings.Contains(fx.log.String(), "warden/share#") {
				t.Fatalf("link leaked: %v / %s", err, fx.log.String())
			}
			if !strings.Contains(fx.log.String(), TemplateShare) || !strings.Contains(fx.log.String(), "share-1") {
				t.Fatalf("failure not logged with template and correlation: %s", fx.log.String())
			}
		})
	}
}

func TestNotificationWithoutLogger(t *testing.T) {
	n := NewNotification(func(context.Context) (grpc.ClientConnInterface, error) { return nil, errors.New("down") }, nil)
	if err := n.Send(context.Background(), shareMsg()); err == nil {
		t.Fatal("dial failure")
	}
}
