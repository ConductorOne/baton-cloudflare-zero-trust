# `baton-cloudflare-zero-trust` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-cloudflare-zero-trust.svg)](https://pkg.go.dev/github.com/conductorone/baton-cloudflare-zero-trust) ![ci](https://github.com/conductorone/baton-cloudflare-zero-trust/actions/workflows/ci.yaml/badge.svg)

`baton-cloudflare-zero-trust` is a connector for Cloudflare Zero Trust built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It communicates with the Cloudflare API to sync data about users, access groups and roles in your Cloudflare Zero Trust organization.
Check out [Baton](https://github.com/conductorone/baton) to learn more about the project in general.

# Getting Started

## Prerequisites

- Access to the Cloudflare Zero Trust dashboard.
- Account ID.
- One of the following credential sets:
  - API token. Create one in the Cloudflare dashboard under User Profile -> API Tokens -> Create Token.
  - Global API key and the email used to log in to the Cloudflare dashboard. To get the API key, go to User Profile -> API Tokens -> View button of Global API Key.

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-cloudflare-zero-trust

BATON_ACCOUNT_ID=cloudflareAccountId BATON_API_TOKEN=cloudflareApiToken baton-cloudflare-zero-trust
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_ACCOUNT_ID=cloudflareAccountId -e BATON_API_TOKEN=cloudflareApiToken public.ecr.aws/conductorone/baton-cloudflare-zero-trust:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-cloudflare-zero-trust/cmd/baton-cloudflare-zero-trust@main

BATON_ACCOUNT_ID=cloudflareAccountId BATON_API_TOKEN=cloudflareApiToken baton-cloudflare-zero-trust
baton resources
```

# Data Model

`baton-cloudflare-zero-trust` will pull down information about the following Cloudflare Zero Trust resources:

- Users
- Access Groups
- Roles

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually
building spreadsheets. We welcome contributions, and ideas, no matter how
small&mdash;our goal is to make identity and permissions sprawl less painful for
everyone. If you have questions, problems, or ideas: Please open a GitHub Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-cloudflare-zero-trust` Command Line Usage

```
baton-cloudflare-zero-trust

Usage:
  baton-cloudflare-zero-trust [flags]
  baton-cloudflare-zero-trust [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --account-id string      required: Cloudflare account ID ($BATON_ACCOUNT_ID)
      --api-key string         Cloudflare API key ($BATON_API_KEY)
      --api-token string       Cloudflare API token ($BATON_API_TOKEN)
      --client-id string       The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string   The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --email string           Cloudflare account email ($BATON_EMAIL)
  -f, --file string            The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                   help for baton-cloudflare-zero-trust
      --log-format string      The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string       The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning           This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --skip-full-sync         This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --ticketing              This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                version for baton-cloudflare-zero-trust

Use "baton-cloudflare-zero-trust [command] --help" for more information about a command.
```
