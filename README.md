# Hostwatch MCP

[Hostwatch](https://gethostwatch.com) exposes a remote MCP server at **https://gethostwatch.com/mcp**. This public repository contains the Codex plugin, connection metadata, icon, and usage guide. The Hostwatch control plane and agent source are maintained separately. Installing the plugin does not grant access to infrastructure; each user signs in to a Hostwatch organization through OAuth.

## Install the Codex plugin

```sh
codex plugin marketplace add sergii-ziborov/hostwatch-mcp
codex plugin add hostwatch@hostwatch
codex mcp login hostwatch
```

Sign in with email, password and the configured second factor, or scan the one-time QR code with an already signed-in Hostwatch iPhone app. Review the requested organization and permissions on the consent screen. Start a new Codex chat after installation to load the plugin. The [plugin guide](plugins/hostwatch/README.md) explains scopes and revocation.

Other MCP clients can use the Streamable HTTP URL directly. The server is [listed in the official MCP Registry](https://registry.modelcontextprotocol.io/v0.1/servers?search=io.github.sergii-ziborov%2Fhostwatch&version=latest).

## What it can do

`search` discovers read and write operations; `execute` runs a named operation. Monitoring covers sites, TLS certificates, traffic, suspicious requests, HTTP errors, Docker and Podman workloads, storage, data services, jobs, and node health. Two resources describe the operation catalog, and two prompts guide incident and TLS reviews. See [docs/mcp.md](docs/mcp.md) for the operation list and security model.

Hostwatch requires OAuth authorization code with PKCE. Read and write scopes are separate, writes are restricted to owners and require per-action confirmation, and tokens can be revoked. API keys and agent credentials are not requested by this plugin.

For security reports, see [SECURITY.md](SECURITY.md). The plugin files are subject to [LICENSE](LICENSE); the hosted service is governed by the [Hostwatch terms](https://gethostwatch.com/terms).
