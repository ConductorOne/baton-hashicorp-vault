![Baton Logo](./docs/images/baton-logo.png)

# `baton-hashicorp-vault` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-hashicorp-vault.svg)](https://pkg.go.dev/github.com/conductorone/baton-hashicorp-vault) ![ci](https://github.com/conductorone/baton-hashicorp-vault/actions/workflows/ci.yaml/badge.svg)

`baton-hashicorp-vault` is a connector for built using the [Baton SDK](https://github.com/conductorone/baton-sdk).

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Getting Started

HashiCorp Vault is a tool that allows you to safely manage secrets. By secrets, we mean sensitive information like digital certificates, database credentials, passwords, and API encryption keys. Go to [https://portal.cloud.hashicorp.com/sign-up](https://portal.cloud.hashicorp.com/sign-up). Create an account and Sign in.

## Prerequisites

Host and credentials for your HashiCorp Vault instance. You can access the Hashicorp Vault web UI by starting the Vault server in dev mode with `vault server -dev` and navigating to `http://127.0.0.1:8200/ui` in your browser.
Check out their [documentation](https://developer.hashicorp.com/vault/install) for more tips on getting started.

The connector supports two authentication methods — use one or the other, not both:

- **Vault Token**: provide a `--vault-token` directly.
- **AppRole**: provide both `--role-id` and `--secret-id`. The connector will exchange them for a token via the [AppRole auth method](https://developer.hashicorp.com/vault/docs/auth/approle).

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-hashicorp-vault
baton-hashicorp-vault
baton resources
```

## docker

Using a Vault Token:
```
docker run --rm -v $(pwd):/out -e BATON_VAULT_HOST=<host> -e BATON_VAULT_TOKEN=<token> public.ecr.aws/conductorone/baton-hashicorp-vault:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

Using AppRole:
```
docker run --rm -v $(pwd):/out -e BATON_VAULT_HOST=<host> -e BATON_ROLE_ID=<role-id> -e BATON_SECRET_ID=<secret-id> public.ecr.aws/conductorone/baton-hashicorp-vault:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-hashicorp-vault/cmd/baton-hashicorp-vault@main

baton-hashicorp-vault

baton resources
```
## Running locally

Run the docker-compose file included in the connector for local testing.

By using docker compose, you can run the following commands to sync resources.

Using a Vault Token:
```
baton-hashicorp-vault --vault-host 'http://127.0.0.1:8200' --vault-token 'testtoken'
```

Using AppRole:
```
baton-hashicorp-vault --vault-host 'http://127.0.0.1:8200' --role-id '<role-id>' --secret-id '<secret-id>'
```

# Data Model

`baton-hashicorp-vault` will pull down information about the following resources:
- Users (userpass users, plus identity entities that log in through an OIDC/JWT auth mount)
- Groups
- Roles
- Entities
- Policies
- Secrets

### OIDC/JWT users and email

Vault has no native email attribute. OIDC/JWT users are identity entities with an alias on the auth mount, and they are synced as `user` resources (resource ID = entity ID; sync-only, policy grants/revokes are supported for userpass users only). When enabled, the connector reads the email from, in order: alias `metadata` (set by the OIDC role's `claim_mappings`, e.g. `{"email": "email"}`), alias `custom_metadata`, entity `metadata` (keys `email`, `email_address`, `mail`), then the alias name if it is a valid email address. If none apply the user is still synced without an email.

This is opt-in: set `--sync-oidc-users` (`BATON_SYNC_OIDC_USERS=true`). It requires `list` on `identity/entity/id` and `read` on `identity/entity/id/*` in the token's policy; without that access the sync fails with a permission error.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually
building spreadsheets. We welcome contributions, and ideas, no matter how
small&mdash;our goal is to make identity and permissions sprawl less painful for
everyone. If you have questions, problems, or ideas: Please open a GitHub Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-hashicorp-vault` Command Line Usage

```
baton-hashicorp-vault

Usage:
  baton-hashicorp-vault [flags]
  baton-hashicorp-vault [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --client-id string       The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string   The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string            The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                   help for baton-hashicorp-vault
      --log-format string      The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string       The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning           This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync         This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --ticketing              This must be set to enable ticketing support ($BATON_TICKETING)
      --vault-host string      required: Vault address or Host. Ex. http://127.0.0.1:8200 ($BATON_VAULT_HOST)
      --vault-token string     Vault token for direct authentication. Mutually exclusive with --role-id ($BATON_VAULT_TOKEN)
      --role-id string         AppRole role ID for Vault AppRole authentication. Mutually exclusive with --vault-token ($BATON_ROLE_ID)
      --secret-id string       AppRole secret ID for Vault AppRole authentication. Required when --role-id is set ($BATON_SECRET_ID)
      --sync-oidc-users        Sync OIDC/JWT identity entities as users. Needs list on identity/entity/id and read on identity/entity/id/*. ($BATON_SYNC_OIDC_USERS)
  -v, --version                version for baton-hashicorp-vault

Use "baton-hashicorp-vault [command] --help" for more information about a command.
```
