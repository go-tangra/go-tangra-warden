// Package migrate3 moves a warden v3 tenant into warden v4 in two steps that
// run in separate processes, because the two stacks live on separate networks
// and both Vaults answer to the same name:
//
//   - export (v3 network): reads the v3 tables in one read-only transaction
//     and every still-available Vault KV version and TOTP URL, verifies the
//     passwords against the recorded checksums and writes a sealed bundle
//     (gzip, AES-256-GCM with a random one-time key written to its own file);
//   - import (v4 network): opens the bundle in memory, maps v3 users (by
//     e-mail), roles (by an operator map) and the tenant subject onto v4 and
//     hands the result to transfer.ImportMigration.
//
// Neither step prints or logs material, seeds, links or the key.
package migrate3
