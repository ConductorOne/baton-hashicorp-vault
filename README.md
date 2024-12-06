![Baton Logo](./docs/images/baton-logo.png)

# `baton-freshservice` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-freshservice.svg)](https://pkg.go.dev/github.com/conductorone/baton-freshservice) ![main ci](https://github.com/conductorone/baton-freshservice/actions/workflows/main.yaml/badge.svg)

`baton-hashicorp-vault` is a connector for built using the [Baton SDK](https://github.com/conductorone/baton-sdk).

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Getting Started

HashiCorp Vault is a tool that allows you to safely manage secrets. By secrets, we mean sensitive information like digital certificates, database credentials, passwords, and API encryption keys. Go to [https://portal.cloud.hashicorp.com/sign-up](https://portal.cloud.hashicorp.com/sign-up). Create an account and Sign in. 

## Prerequisites

Host and token for your HashiCorp account. You can access the Hashicorp Vault web UI by starting the Vault server in dev mode with `vault server -dev` and navigating to `http://127.0.0.1:8200/ui` in your browser. 
Check out their [documentation](https://developer.hashicorp.com/vault/install) for more tips on getting started.

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-hashicorp-vault
baton-hashicorp-vault
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_VAULT_HOST=<host> -e BATON_VAULT_TOKEN=<token> -e BATON_USERNAME=username ghcr.io/conductorone/baton-hashicorp-vault:latest -f "/out/sync.c1z"
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

By using docker compose, you can run the following command to sync resources.
```
 baton-hashicorp-vault --vault-host 'http://127.0.0.1:8200' --vault-token 'testtoken
```

# Data Model

`baton-hashicorp-vault` will pull down information about the following resources:
- Users
- Groups
- Roles
- Entities
- Policies
- Secrets

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
  -v, --version                version for baton-hashicorp-vault
      --x-vault-host string    required: Vault Host ($BATON_X_VAULT_HOST)
      --x-vault-token string   required: Vault Token ($BATON_X_VAULT_TOKEN)

Use "baton-hashicorp-vault [command] --help" for more information about a command.
```
