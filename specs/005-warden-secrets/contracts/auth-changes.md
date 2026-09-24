# Changes to other services required by feature 005

## Auth service (`services/auth`)

Two member-level, read-only endpoints (added to `console.yaml`, registered at
the gateway as public routes like the rest of the console API; the module
authenticates with its session and answers only for the caller's tenant):

| Route | Purpose | Rules |
|-------|---------|-------|
| `GET /api/v1/users?q=<text>` | subject picker: public profiles (id, display_name, avatar_url, email) of tenant members matching name or email | ≤ 20 results, `q` ≥ 2 chars, same rate limit as the lookup (`profile.lookup_rate_per_minute`), never phone |
| `GET /api/v1/roles` | subject picker: `[{slug, display_name}]` of the tenant's roles | any signed-in member |

`pkg/authclient.Identity.Roles` already carries effective roles (direct and
through groups, feature 004); warden evaluates role grants against it.

- `auth.v1.Authorization/RegisterPermissions` accepts `builtin_grants`
  (`[{role, permissions[]}]`): the registrant's own permissions are granted to
  the named built-in roles of every tenant (idempotent; permissions outside the
  request and custom roles are refused). Warden calls it at start-up and every
  five minutes with the grants of contracts/manifest.md; the gateway keeps
  registering permissions from the manifest without grants.

## Gateway (`services/gateway`)

- Manifest route extension `client_address: true` (proto `Route.client_address`,
  schema `x-freya-client-address`): for such routes the dispatcher adds
  `X-Gateway-Client-Addr: <client ip>` to the forwarded request (dropped from
  inbound requests like every `X-Gateway-*` header). Used by warden's share
  open route for CIDR policies.
- No other gateway change; warden is an ordinary module.
