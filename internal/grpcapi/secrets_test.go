package grpcapi

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/go-freya/freya/services/auth/pkg/authclient"
	wardenv1 "github.com/go-freya/freya/services/warden/api/proto/warden/v1"
	"github.com/go-freya/freya/services/warden/internal/audit"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/memstore"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

func TestSecretsServer(t *testing.T) {
	ms := memstore.New()
	aw := audit.NewWriter(ms, nil)
	defer aw.Close()
	az := authz.New(ms, aw)
	vt := vault.NewFake()
	svc := secrets.New(ms, vt, az, aw)
	srv := &SecretsServer{Secrets: svc, Authz: az}
	alice := authclient.WithIdentity(context.Background(), authclient.Identity{UserID: uA, TenantID: tA, Roles: []string{"member"}})
	bob := authclient.WithIdentity(context.Background(), authclient.Identity{UserID: uB, TenantID: tA})
	v, err := svc.Create(alice, authz.Subjects{TenantID: tA, UserID: uA}, secrets.Input{Name: "db", Username: "root", Password: "WARDEN-MARKER-PW-grpc"})
	if err != nil {
		t.Fatal(err)
	}
	// Identity is required on every call.
	for name, fn := range map[string]func(ctx context.Context) error{
		"get": func(ctx context.Context) error { _, err := srv.Get(ctx, &wardenv1.GetRequest{Id: v.ID}); return err },
		"password": func(ctx context.Context) error {
			_, err := srv.GetPassword(ctx, &wardenv1.GetPasswordRequest{Id: v.ID})
			return err
		},
		"check": func(ctx context.Context) error {
			_, err := srv.Check(ctx, &wardenv1.CheckRequest{ResourceType: "secret", ResourceId: v.ID, Permission: "read"})
			return err
		},
	} {
		if err := fn(context.Background()); status.Code(err) != codes.Unauthenticated {
			t.Errorf("%s anonymous: %v", name, err)
		}
	}
	got, err := srv.Get(alice, &wardenv1.GetRequest{Id: v.ID})
	if err != nil || got.Secret.Name != "db" || got.Secret.CurrentVersion != 1 || got.Secret.Username != "root" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := srv.Get(alice, &wardenv1.GetRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("empty id")
	}
	if _, err := srv.Get(bob, &wardenv1.GetRequest{Id: v.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("bob get: %v", err)
	}
	if _, err := srv.Get(alice, &wardenv1.GetRequest{Id: "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c99"}); status.Code(err) != codes.NotFound {
		t.Fatalf("missing: %v", err)
	}
	pwd, err := srv.GetPassword(alice, &wardenv1.GetPasswordRequest{Id: v.ID})
	if err != nil || pwd.Password != "WARDEN-MARKER-PW-grpc" || pwd.Version != 1 {
		t.Fatalf("%v %v", pwd, err)
	}
	if _, err := srv.GetPassword(alice, &wardenv1.GetPasswordRequest{Id: v.ID, Version: -1}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("negative version")
	}
	if _, err := srv.GetPassword(bob, &wardenv1.GetPasswordRequest{Id: v.ID}); status.Code(err) != codes.PermissionDenied {
		t.Fatal("bob password")
	}
	vt.Down = true
	if _, err := srv.GetPassword(alice, &wardenv1.GetPasswordRequest{Id: v.ID}); status.Code(err) != codes.Unavailable || status.Convert(err).Message() != "vault_unavailable" {
		t.Fatalf("vault down: %v", err)
	}
	vt.Down = false
	chk, err := srv.Check(alice, &wardenv1.CheckRequest{ResourceType: "secret", ResourceId: v.ID, Permission: "delete"})
	if err != nil || !chk.Allowed || chk.Relation != "owner" {
		t.Fatalf("%v %v", chk, err)
	}
	chk, _ = srv.Check(bob, &wardenv1.CheckRequest{ResourceType: "secret", ResourceId: v.ID, Permission: "read"})
	if chk.Allowed {
		t.Fatal("bob allowed")
	}
	if _, err := srv.Check(alice, &wardenv1.CheckRequest{ResourceType: "thing", ResourceId: v.ID, Permission: "read"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("bad type")
	}
	aw.Flush()
	okReads := 0
	for _, r := range ms.AuditEvents(tA, "secret_password_read") {
		if r.Outcome == "ok" {
			okReads++
		}
	}
	if okReads != 1 {
		t.Fatalf("audit %d", okReads)
	}
	if n := len(ms.AuditEvents(tA, "access_refused")); n < 2 {
		t.Fatalf("refusals %d", n)
	}
	// Unknown errors are unavailable, invalid input mapped.
	if status.Code(grpcError(errors.New("db"))) != codes.Unavailable || status.Code(grpcError(secrets.ErrInvalid)) != codes.InvalidArgument {
		t.Fatal("mapping")
	}
	ms.FailOn("GetSecret", errors.New("db"))
	if _, err := srv.Get(alice, &wardenv1.GetRequest{Id: v.ID}); status.Code(err) != codes.Unavailable {
		t.Fatalf("db: %v", err)
	}
}
