# Hostwatch MCP

[Hostwatch](https://gethostwatch.com) exposes a remote MCP server at **https://gethostwatch.com/mcp**. This public repository contains the Codex plugin, a Go bridge for local MCP clients, connection metadata, icon, and usage guide. Every connection belongs to a signed-in Hostwatch user and organization. The Hostwatch control plane and node agent source are maintained separately.

## Install the Codex plugin

```sh
codex plugin marketplace add sergii-ziborov/hostwatch-mcp
codex plugin add hostwatch@hostwatch
codex mcp login hostwatch
```

Sign in with email, password and the configured second factor, or scan the one-time QR code with an already signed-in Hostwatch iPhone app. Review the requested organization and permissions on the consent screen. Start a new Codex chat after installation to load the plugin. The [plugin guide](plugins/hostwatch/README.md) explains scopes and revocation.

## Connect a local MCP client with the Go app

Use the Go app when an MCP client accepts a local stdio command but cannot complete remote OAuth on its own. Install [Go 1.24 or later](https://go.dev/dl/), then run:

```sh
go install github.com/sergii-ziborov/hostwatch-mcp/cmd/hostwatch-mcp@latest
hostwatch-mcp login
```

`login` opens the **Hostwatch** authorization page. Sign in to your Hostwatch account directly or approve its QR code with your signed-in Hostwatch app, then review the organization and requested access. The Go app receives a short-lived OAuth authorization code on a temporary loopback callback; it never asks for an API key or node-agent credential. To request write access as an organization owner, use `hostwatch-mcp login --write`. Hostwatch still asks for explicit confirmation for each write operation.

Configure your MCP client to launch the app over stdio. For example, in a client that supports `mcpServers`:

```json
{
  "mcpServers": {
    "hostwatch": {
      "command": "hostwatch-mcp",
      "args": ["serve"]
    }
  }
}
```

If your MCP client cannot find the installed executable, use the absolute path from `go env GOPATH` followed by `/bin/hostwatch-mcp`. Run `hostwatch-mcp status` to inspect the local connection and `hostwatch-mcp logout` to revoke it. `login --no-browser` prints the Hostwatch URL for manual opening and accepts the final callback URL. See [the connection guide](docs/mcp.md#go-stdio-bridge) for details.

Clients with native Streamable HTTP and OAuth support can connect straight to `https://gethostwatch.com/mcp`. The Go app is a client-side bridge to that same Hostwatch account, not an independent infrastructure agent. The server is [listed in the official MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.sergii-ziborov%2Fhostwatch&version=latest).

## What it can do

`search` discovers read and write operations; `execute` runs a named operation. Monitoring covers sites, TLS certificates, traffic, suspicious requests, HTTP errors, Docker and Podman workloads, storage, data services, jobs, and node health. Two resources describe the operation catalog, and two prompts guide incident and TLS reviews. See [docs/mcp.md](docs/mcp.md) for the operation list and security model.

Hostwatch requires OAuth authorization code with PKCE. Read and write scopes are separate, writes are restricted to owners and require per-action confirmation, and tokens can be revoked. API keys and agent credentials are not requested by the plugin or Go app.

For security reports, see [SECURITY.md](SECURITY.md). The plugin files are subject to [LICENSE](LICENSE); the hosted service is governed by the [Hostwatch terms](https://gethostwatch.com/terms).
