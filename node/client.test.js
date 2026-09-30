import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { PassThrough } from 'node:stream';
import { mkdtemp, readFile, stat, chmod } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { HostwatchClient } from './client.js';

async function listen(server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${server.address().port}`;
}

test('account login, PKCE, stdio forwarding, refresh and logout', async t => {
  let origin;
  let redirectURI;
  let challenge;
  let refreshes = 0;
  let revocations = 0;
  let mcpCalls = 0;
  const server = createServer(async (req, res) => {
    if (req.url === '/.well-known/oauth-authorization-server') {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ issuer: origin, authorization_endpoint: `${origin}/oauth/authorize`, registration_endpoint: `${origin}/oauth/register`, token_endpoint: `${origin}/oauth/token`, revocation_endpoint: `${origin}/oauth/revoke` }));
    } else if (req.url === '/oauth/register') {
      const data = JSON.parse(await readBody(req));
      redirectURI = data.redirect_uris[0];
      assert.equal(data.client_name, 'Hostwatch npm MCP');
      res.writeHead(201, { 'Content-Type': 'application/json' }).end(JSON.stringify({ client_id: 'test-client' }));
    } else if (req.url === '/oauth/token') {
      const form = new URLSearchParams(await readBody(req));
      assert.equal(form.get('client_id'), 'test-client');
      assert.equal(form.get('resource'), `${origin}/mcp`);
      if (form.get('grant_type') === 'authorization_code') {
        assert.equal(form.get('redirect_uri'), redirectURI);
        assert.equal(form.get('code'), 'test-code');
        assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'), challenge);
        res.end(JSON.stringify({ access_token: 'access-one', refresh_token: 'refresh-one', token_type: 'Bearer', scope: 'hostwatch:read', expires_in: 3600 }));
      } else {
        assert.equal(form.get('refresh_token'), 'refresh-one');
        refreshes++;
        res.end(JSON.stringify({ access_token: 'access-two', refresh_token: 'refresh-two', token_type: 'Bearer', scope: 'hostwatch:read', expires_in: 3600 }));
      }
    } else if (req.url === '/oauth/revoke') {
      const form = new URLSearchParams(await readBody(req));
      assert.equal(form.get('client_id'), 'test-client');
      revocations++;
      res.end('{}');
    } else if (req.url === '/mcp') {
      mcpCalls++;
      if (req.headers.authorization === 'Bearer access-one') {
        res.writeHead(401).end(); return;
      }
      assert.equal(req.headers.authorization, 'Bearer access-two');
      const message = JSON.parse(await readBody(req));
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ jsonrpc: '2.0', id: message.id, result: { tools: [{ name: 'search' }] } }));
    } else {
      res.writeHead(404).end();
    }
  });
  origin = await listen(server);
  t.after(() => server.close());
  const directory = await mkdtemp(join(tmpdir(), 'hostwatch-node-test-'));
  const client = new HostwatchClient({ origin, sessionFile: join(directory, 'private', 'session.json') });
  client.browser = async raw => {
    const authorization = new URL(raw);
    assert.equal(authorization.searchParams.get('scope'), 'hostwatch:read');
    assert.equal(authorization.searchParams.get('code_challenge_method'), 'S256');
    challenge = authorization.searchParams.get('code_challenge');
    assert.equal(authorization.searchParams.get('redirect_uri'), redirectURI);
    const callback = new URL(redirectURI);
    callback.searchParams.set('state', 'bad-state');
    assert.equal((await fetch(callback)).status, 400);
    callback.searchParams.set('state', authorization.searchParams.get('state'));
    callback.searchParams.set('iss', origin);
    callback.searchParams.set('code', 'test-code');
    assert.equal((await fetch(callback)).status, 200);
  };
  const loginOutput = new PassThrough();
  let loginText = '';
  loginOutput.on('data', chunk => { loginText += chunk; });
  await client.login({ output: loginOutput });
  assert.match(loginText, /Connected to your Hostwatch account/);
  assert.equal((await stat(client.sessionFile)).mode & 0o777, 0o600);
  const input = new PassThrough();
  const output = new PassThrough();
  let text = '';
  output.on('data', chunk => { text += chunk; });
  const serving = client.serve(input, output);
  input.end('{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n');
  await serving;
  assert.match(text, /"name":"search"/);
  assert.equal(mcpCalls, 2);
  assert.equal(refreshes, 1);
  assert.equal(JSON.parse(await readFile(client.sessionFile, 'utf8')).refreshToken, 'refresh-two');
  await client.logout();
  assert.equal(revocations, 2);
  await assert.rejects(() => client.load(), /Not connected/);
});

test('rejects unsafe session, mismatched origin and HTTP outside loopback', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'hostwatch-node-test-'));
  const client = new HostwatchClient({ sessionFile: join(directory, 'session.json') });
  await client.save({ origin: 'https://other.example', clientId: 'c', accessToken: 'a', refreshToken: 'r', expiresAt: Date.now() + 60_000 });
  await assert.rejects(() => client.load(), /another origin/);
  await chmod(client.sessionFile, 0o644);
  await assert.rejects(() => client.load(), /owner-only/);
  assert.throws(() => new HostwatchClient({ origin: 'http://gethostwatch.com' }), /HTTPS origin/);
});

test('modern MCP headers and SSE replies are forwarded', async t => {
  let origin;
  let seen;
  const server = createServer(async (req, res) => {
    if (req.url !== '/mcp') { res.writeHead(404).end(); return; }
    seen = { headers: req.headers, body: JSON.parse(await readBody(req)) };
    res.writeHead(200, { 'Content-Type': 'text/event-stream' });
    res.end('event: message\ndata: {"jsonrpc":"2.0","id":2,"result":{"content":[]}}\n\n');
  });
  origin = await listen(server);
  t.after(() => server.close());
  const directory = await mkdtemp(join(tmpdir(), 'hostwatch-node-test-'));
  const client = new HostwatchClient({ origin, sessionFile: join(directory, 'private', 'session.json') });
  await client.save({ origin, clientId: 'c', accessToken: 'a', refreshToken: 'r', scope: 'hostwatch:read', expiresAt: Date.now() + 3600_000 });
  const replies = await client.forward(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'search' } }), '2026-07-28');
  assert.equal(replies.length, 1);
  assert.equal(JSON.parse(replies[0]).result.content.length, 0);
  assert.equal(seen.headers.authorization, 'Bearer a');
  assert.equal(seen.headers['mcp-protocol-version'], '2026-07-28');
  assert.equal(seen.headers['mcp-method'], 'tools/call');
  assert.equal(seen.headers['mcp-name'], 'search');
});

async function readBody(req) {
  let data = '';
  for await (const chunk of req) data += chunk;
  return data;
}
