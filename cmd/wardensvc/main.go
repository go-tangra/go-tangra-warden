// Command wardensvc runs the warden module (default) or prepares a
// deployment: `wardensvc bootstrap -config deploy/dev.yaml` applies the
// migrations, checks the vault (AppRole login, KV mount) and prints the
// dependency health. `wardensvc export-v3` / `import-v3` move a warden v3
// tenant into v4 (docs/migration-v3.md).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-tangra/go-tangra-warden/v4/internal/app"
	"github.com/go-tangra/go-tangra-warden/v4/internal/config"
	"github.com/go-tangra/go-tangra-warden/v4/ui"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "bootstrap":
			os.Exit(bootstrap(os.Args[2:]))
		case "export-v3":
			os.Exit(exportV3(os.Args[2:]))
		case "import-v3":
			os.Exit(importV3(os.Args[2:]))
		}
	}
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("wardensvc", flag.ContinueOnError)
	cfgPath := fs.String("config", "deploy/dev.yaml", "configuration file")
	noMigrate := fs.Bool("no-migrate", false, "do not apply database migrations on start")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	opts := app.Options{Migrate: !*noMigrate, Register: app.Wire}
	if remote, ok := ui.Remote(); ok {
		opts.Remote = remote
	}
	a, err := app.Build(ctx, cfg, opts)
	if err != nil {
		return fail(err)
	}
	defer a.Close()
	if ep, err := a.Freya.HTTP().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "wardensvc: browser API (via gateway) on", ep.String())
	}
	if ep, err := a.Freya.GRPC().Endpoint(); err == nil {
		fmt.Fprintln(os.Stderr, "wardensvc: grpc listening on", ep.String())
	}
	if err := a.Run(ctx); err != nil {
		return fail(err)
	}
	return 0
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "wardensvc:", err)
	return 1
}
