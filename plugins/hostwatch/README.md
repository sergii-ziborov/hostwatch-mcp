# Hostwatch plugin for Codex

This public plugin connects Codex to the [Hostwatch remote MCP server](https://gethostwatch.com/mcp). It supplies a searchable infrastructure operation catalog, live monitoring tools, resources, and investigation prompts. No API key or local server process is required; access to infrastructure still requires a Hostwatch account.

## Install

Add the public marketplace, then install the plugin:

```sh
codex plugin marketplace add sergii-ziborov/hostwatch-mcp
codex plugin add hostwatch@hostwatch
codex mcp login hostwatch
```

Start a new Codex chat after installation so the MCP tools and skill load.

## Sign in

When Codex connects, Hostwatch opens an OAuth authorization page. Choose **Use signed-in iPhone** to scan the QR code in the Hostwatch iPhone app and approve the matching six-digit code. Or choose **Email & password** and complete authenticator or signed-in-app verification if prompted. Review the client name, callback and requested permissions before allowing access. The resulting OAuth tokens are held by the MCP client, not entered into the plugin configuration.

Read access covers monitoring. Owner-approved write access is requested separately and each change requires `confirm: true`. Revoke the connection in **Hostwatch → Organization → Connected MCP clients**. See [the MCP guide](../../docs/mcp.md) for available operations and security details.

The plugin files are subject to the [repository license](../../LICENSE); the hosted service is governed by the [Hostwatch terms](https://gethostwatch.com/terms).
