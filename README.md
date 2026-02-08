# go-tangra-warden

Secret and credential management service built on HashiCorp Vault. Provides secure secret storage with folder organization, version history, Zanzibar-style permissions, and Bitwarden import/export.

## Features

- **Secret Management** — CRUD operations with username, password, host URL, metadata
- **Version History** — Full password version tracking with rollback capability
- **Folder Organization** — Hierarchical folder structure with unlimited depth
- **Zanzibar Permissions** — Fine-grained access control (Owner/Editor/Viewer/Sharer)
- **Vault Backend** — Passwords stored in HashiCorp Vault KV v2, not in the database
- **Bitwarden Transfer** — Import from and export to Bitwarden format
- **Multi-Tenant** — Complete tenant isolation with separate Vault paths
- **Audit Trail** — Creator/updater tracking on all operations

## gRPC Services

| Service | Endpoints | Purpose |
|---------|-----------|---------|
| WardenSecretService | Create, Get, GetPassword, List, Update, UpdatePassword, Delete, Move, Search, Versions, Restore | Secret lifecycle |
| WardenFolderService | Create, Get, List, Update, Delete, Move, GetTree | Folder hierarchy |
| WardenPermissionService | Grant, Revoke, List, Check, ListAccessible, GetEffective | Access control |
| WardenBitwardenTransferService | Export, Import, Validate | Bitwarden interop |
| WardenSystemService | Health, GetInfo, CheckVault | System status |

**Port:** 9300 (gRPC) with REST endpoints via gRPC-Gateway

## Permission Model

| Relation | Permissions |
|----------|------------|
| **Owner** | Read, Write, Delete, Share |
| **Editor** | Read, Write |
| **Viewer** | Read |
| **Sharer** | Read, Share |

Permissions inherit through the folder hierarchy. Supports user, role, and tenant-level grants with optional expiration.

## Vault Integration

- **Authentication**: AppRole with role_id/secret_id files
- **Engine**: KV v2 secrets engine
- **Path Structure**: `{mount_path}/{tenant_id}/{secret_id}`
- **Token Renewal**: Automatic lifecycle management

```yaml
warden:
  vault:
    address: "http://vault:8200"
    mount_path: "secret"
    role_id_file: "/vault-credentials/role_id"
    secret_id_file: "/vault-credentials/secret_id"
```

## Bitwarden Transfer

```bash
# Export secrets to Bitwarden JSON format
POST /v1/bitwarden/export

# Validate import before executing
POST /v1/bitwarden/validate

# Import from Bitwarden export
POST /v1/bitwarden/import
# Duplicate handling: SKIP, RENAME, or OVERWRITE
```

## Build

```bash
make build-server       # Build binary
make generate           # Generate Ent + Wire
make docker             # Build Docker image
make docker-buildx      # Multi-platform (amd64/arm64)
make test               # Run tests
make ent                # Regenerate Ent schemas
```

## Docker

```bash
docker run -p 9300:9300 ghcr.io/go-tangra/go-tangra-warden:latest
```

Runs as non-root user `warden` (UID 1000). Requires HashiCorp Vault and PostgreSQL/MySQL.

## Dependencies

- **Framework**: Kratos v2
- **ORM**: Ent (PostgreSQL, MySQL)
- **Secrets**: HashiCorp Vault API with AppRole auth
- **Cache**: Redis
- **Protobuf**: Buf
