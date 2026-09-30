# Hostwatch remote MCP

The remote MCP URL is `https://gethostwatch.com/mcp`. It uses Streamable HTTP and OAuth authorization code with PKCE S256. Hostwatch supports direct email/password sign-in with the configured second factor, or a one-time QR code approved from an already signed-in Hostwatch iPhone app. No API key is required.

## Go stdio bridge

The public `hostwatch-mcp` Go executable is for MCP clients that need a local stdio server. It is a bridge to the hosted MCP and uses the **same Hostwatch user account, organization, roles, scopes, audit trail, and restrictions** as a direct remote connection. It does not inspect the local machine, Docker, Podman, or SSH credentials.

Install with `go install github.com/sergii-ziborov/hostwatch-mcp/cmd/hostwatch-mcp@latest` (Go 1.24+). Run `hostwatch-mcp login`; the browser shows Hostwatch's direct and QR sign-in choices and consent. `--write` requests the separate write scope, and `--no-browser` lets you open the printed URL manually. After login, point the MCP client's stdio configuration at `hostwatch-mcp serve`. The executable sends JSON-RPC requests to the remote `/mcp` endpoint with the account's bearer token and refreshes the token as needed. Its stdout contains only MCP messages while serving; login and status are separate commands.

The OAuth session is stored in an owner-only file under the operating system's user configuration directory (`hostwatch-mcp/session.json`), and can be relocated with `HOSTWATCH_SESSION_FILE`. For a self-hosted Hostwatch installation, set `HOSTWATCH_ORIGIN` to its bare HTTPS origin for both login and serve. HTTP is accepted only for loopback development. `hostwatch-mcp status` reports the origin, scope, and expiry without printing tokens. `hostwatch-mcp logout` revokes both tokens and deletes the local session. The Hostwatch account owner can also revoke the connection from **Organization → Connected MCP clients**.

The remote server remains the source of all operations and authorization decisions. The Go app has no node-agent token and cannot bypass organization membership, owner-only writes, node governance, or per-action confirmation.

## Node.js/npm stdio bridge

The package in this repository also provides `hostwatch-mcp-node` for Node.js 22+. Install it with `npm install -g github:sergii-ziborov/hostwatch-mcp#v1.1.0`, then run `hostwatch-mcp-node login`. Use `hostwatch-mcp-node serve` as the MCP client's stdio command. `login --write` requests the owner-only write scope; `login --no-browser` prints the authorization URL and accepts the callback URL pasted back into the terminal. `status`, `logout`, `HOSTWATCH_ORIGIN`, and `HOSTWATCH_NODE_SESSION_FILE` are supported. The Node bridge stores a separate owner-only OAuth session, named **Hostwatch npm MCP** in Hostwatch's connected-client list.

The Node and Go bridges both reach the hosted `/mcp` endpoint through the signed-in user's OAuth grant. Neither runs a second local agent or reads the monitored node directly. The Node implementation uses built-in HTTP, crypto, and filesystem APIs; compiling Go to WASM would still require a Node host for those operations and would add a distribution layer without changing the security model.

The server advertises OAuth metadata at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`. Clients can register through `/oauth/register`, receive authorization through `/oauth/authorize`, exchange and refresh tokens through `/oauth/token`, and revoke tokens through `/oauth/revoke`. Access tokens expire after one hour; refresh tokens rotate. The user can revoke a connected client in Hostwatch under **Organization → Connected MCP clients**.

`search` returns allowlisted operation names and required access levels. `execute` runs one operation. Read operations include `overview`, `sites`, `site_details`, `tls_site`, `data_services`, `network_ports`, `storage`, `cleanup_preview`, `projects`, `jobs`, `traffic`, `sources`, `threats`, `errors`, `error_context`, `traffic_guard`, `mcp_governance`, `runtimes`, `workloads`, `applications`, `peers`, and `links`. Set `nodeId` to select a non-primary node.

Write operations are `renew_tls`, `site_action`, and `job_action`. They require the owner's `hostwatch:write` scope, the node's governance policy, and `confirm: true` for the call. Successful changes are audited. The remote MCP does not expose arbitrary API routes, environment exports, or secret values.

Resources `hostwatch://guide` and `hostwatch://operations` describe safe use and the catalog. The prompts `investigate_incident` and `review_tls` provide read-only workflows. For example, call `search` with `{"query":"tls"}`, then `execute` with `{"operation":"tls_site","args":{"id":"my-site"}}`.
