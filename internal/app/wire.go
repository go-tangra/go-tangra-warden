package app

import (
	"time"

	"github.com/go-freya/freya/services/auth/pkg/authclient"
	wardenv1 "github.com/go-freya/freya/services/warden/api/proto/warden/v1"
	"github.com/go-freya/freya/services/warden/internal/authz"
	"github.com/go-freya/freya/services/warden/internal/folders"
	"github.com/go-freya/freya/services/warden/internal/generator"
	"github.com/go-freya/freya/services/warden/internal/grpcapi"
	"github.com/go-freya/freya/services/warden/internal/httpapi"
	"github.com/go-freya/freya/services/warden/internal/secrets"
	"github.com/go-freya/freya/services/warden/internal/share"
	"github.com/go-freya/freya/services/warden/internal/stats"
	"github.com/go-freya/freya/services/warden/internal/transfer"
	"github.com/go-freya/freya/services/warden/internal/vault"
)

// Version is reported by the health route.
const Version = "1.0.0"

// Wire builds the domain services and mounts every story's handlers on the
// HTTP server and the gRPC service, then checks that every declared route
// has a handler so the contract and the implementation cannot drift.
func Wire(a *App) error {
	a.Authz = authz.New(a.Repo, a.Audit)
	a.Secrets = secrets.New(a.Repo, a.Vault, a.Authz, a.Audit)
	a.Folders = folders.New(a.Repo, a.Authz, a.Audit, a.Secrets)
	deps := httpapi.StoryDeps{Folders: a.Folders, Secrets: a.Secrets, Authz: a.Authz}
	a.HTTP.RegisterFolders(deps)
	a.HTTP.RegisterSecrets(deps)
	a.HTTP.RegisterGrants(deps)
	a.Transfer = transfer.New(a.Repo, a.Folders, a.Secrets, a.Authz, a.Audit)
	a.HTTP.RegisterTransfer(httpapi.TransferDeps{Transfer: a.Transfer, Vault: a.Vault, MaxBytes: a.Cfg.Limits.TransferMaxBytes})
	var sender share.Sender = a.Mail
	if sender == nil {
		if a.Cfg.Mail.Transport == "log" {
			sender = share.LogSink{Log: a.Log}
		} else {
			smtp, err := share.NewSMTP(share.SMTPConfig{Host: a.Cfg.Mail.Host, Port: a.Cfg.Mail.Port, Username: a.Cfg.Mail.Username, Password: a.Cfg.Mail.Password, From: a.Cfg.Mail.From, AllowPlaintext: a.Cfg.Mail.AllowPlaintext})
			if err != nil {
				return err
			}
			sender = smtp
		}
	}
	a.Shares = share.New(a.Repo, a.Vault, a.Authz, a.Audit, sender, share.Config{PublicOrigin: a.Cfg.Share.PublicOrigin,
		DefaultValidity: time.Duration(a.Cfg.Share.DefaultValiditySeconds) * time.Second, DefaultMaxOpens: a.Cfg.Share.DefaultMaxOpens})
	a.HTTP.RegisterShares(httpapi.ShareDeps{Shares: a.Shares, Cache: a.Cache, OpenLimit: a.Cfg.Limits.LookupRatePerMinute})
	a.workers = append(a.workers, func(ctx contextT) {
		a.Shares.RunSweeper(ctx, time.Minute, func(err error) { a.Log.Warn("share sweep", "err", err) })
	})
	a.HTTP.RegisterOps(httpapi.OpsDeps{Generator: generator.New(), Stats: stats.New(a.Repo), Audit: a.Repo, Version: Version,
		Health: func(ctx contextT) (string, vault.Health) { h := a.Health(ctx); return h.DB, h.Vault }})
	if v, ok := a.Verifier.(*authclient.Verifier); ok {
		a.Freya.GRPC().Use("/warden.v1.Secrets/*", authclient.KratosMiddleware(v))
	} else if a.GRPCAuth != nil {
		a.Freya.GRPC().Use("/warden.v1.Secrets/*", a.GRPCAuth)
	}
	wardenv1.RegisterSecretsServer(a.Freya.GRPC(), &grpcapi.SecretsServer{Secrets: a.Secrets, Authz: a.Authz})
	a.workers = append(a.workers, func(ctx contextT) {
		a.Secrets.RunReconciler(ctx, ReconcileInterval, func(err error) { a.Log.Warn("reconcile", "err", err) })
	})
	return nil
}

// ReconcileInterval is how often interrupted writes are settled.
const ReconcileInterval = time.Minute
