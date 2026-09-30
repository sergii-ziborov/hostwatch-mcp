# Hostwatch remote MCP

The remote MCP URL is `https://gethostwatch.com/mcp`. It uses Streamable HTTP and OAuth authorization code with PKCE S256. Hostwatch supports direct email/password sign-in with the configured second factor, or a one-time QR code approved from an already signed-in Hostwatch iPhone app. No API key is required.

The server advertises OAuth metadata at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`. Clients can register through `/oauth/register`, receive authorization through `/oauth/authorize`, exchange and refresh tokens through `/oauth/token`, and revoke tokens through `/oauth/revoke`. Access tokens expire after one hour; refresh tokens rotate. The user can revoke a connected client in Hostwatch under **Organization → Connected MCP clients**.

`search` returns allowlisted operation names and required access levels. `execute` runs one operation. Read operations include `overview`, `sites`, `site_details`, `tls_site`, `data_services`, `network_ports`, `storage`, `cleanup_preview`, `projects`, `jobs`, `traffic`, `sources`, `threats`, `errors`, `error_context`, `traffic_guard`, `mcp_governance`, `runtimes`, `workloads`, `applications`, `peers`, and `links`. Set `nodeId` to select a non-primary node.

Write operations are `renew_tls`, `site_action`, and `job_action`. They require the owner's `hostwatch:write` scope, the node's governance policy, and `confirm: true` for the call. Successful changes are audited. The remote MCP does not expose arbitrary API routes, environment exports, or secret values.

Resources `hostwatch://guide` and `hostwatch://operations` describe safe use and the catalog. The prompts `investigate_incident` and `review_tls` provide read-only workflows. For example, call `search` with `{"query":"tls"}`, then `execute` with `{"operation":"tls_site","args":{"id":"my-site"}}`.
