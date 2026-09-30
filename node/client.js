import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createInterface } from 'node:readline';
import { homedir, platform } from 'node:os';
import { dirname, join } from 'node:path';
import { mkdir, lstat, open, readFile, rename, rm } from 'node:fs/promises';

export const version = '1.1.0';
const maxMessage = 2 * 1024 * 1024;
const random = () => randomBytes(32).toString('base64url');

function loopback(host) {
  return host === 'localhost' || host === '127.0.0.1' || host === '[::1]';
}

function defaultSessionFile() {
  const system = platform();
  const base = system === 'darwin' ? join(homedir(), 'Library', 'Application Support')
    : system === 'win32' ? process.env.APPDATA || join(homedir(), 'AppData', 'Roaming')
    : process.env.XDG_CONFIG_HOME || join(homedir(), '.config');
  return join(base, 'hostwatch-mcp-node', 'session.json');
}

function sameOrigin(endpoint, origin) {
  const url = new URL(endpoint);
  if (url.origin !== origin || url.username || url.password) throw new Error('Hostwatch OAuth endpoint origin mismatch');
  return url.href;
}

function assertOwnerOnly(stat, label) {
  if (platform() !== 'win32' && (stat.mode & 0o077) !== 0) throw new Error(`${label} must be owner-only`);
}

export class HostwatchClient {
  constructor({ origin = process.env.HOSTWATCH_ORIGIN || 'https://gethostwatch.com', sessionFile = process.env.HOSTWATCH_NODE_SESSION_FILE || defaultSessionFile(), fetcher = fetch, browser = openBrowser } = {}) {
    const parsed = new URL(origin);
    if (parsed.username || parsed.password || parsed.search || parsed.hash || (parsed.pathname !== '/' && parsed.pathname !== '') || (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback(parsed.hostname)))) {
      throw new Error('HOSTWATCH_ORIGIN must be a bare HTTPS origin (HTTP only on loopback)');
    }
    this.origin = parsed.origin;
    this.sessionFile = sessionFile;
    this.fetcher = fetcher;
    this.browser = browser;
  }

  async request(url, init = {}) {
    const response = await this.fetcher(url, { redirect: 'manual', signal: AbortSignal.timeout(70_000), ...init });
    if (response.status >= 300 && response.status < 400) throw new Error('Unexpected Hostwatch redirect');
    return response;
  }

  async metadata() {
    const response = await this.request(`${this.origin}/.well-known/oauth-authorization-server`, { headers: { Accept: 'application/json' } });
    if (!response.ok) throw new Error(`Hostwatch OAuth metadata HTTP ${response.status}`);
    const metadata = JSON.parse(await readLimited(response, 1024 * 1024));
    if (metadata.issuer !== this.origin) throw new Error('Hostwatch OAuth issuer mismatch');
    for (const key of ['authorization_endpoint', 'token_endpoint', 'registration_endpoint', 'revocation_endpoint']) sameOrigin(metadata[key], this.origin);
    return metadata;
  }

  async save(session) {
    const dir = dirname(this.sessionFile);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    const directory = await lstat(dir);
    if (!directory.isDirectory()) throw new Error('Hostwatch session directory is not a directory');
    assertOwnerOnly(directory, 'Hostwatch session directory');
    try {
      const current = await lstat(this.sessionFile);
      if (!current.isFile()) throw new Error('Hostwatch session path is not a regular file');
      assertOwnerOnly(current, 'Hostwatch session file');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    const temp = join(dir, `.session-${random()}`);
    const file = await open(temp, 'wx', 0o600);
    try {
      await file.writeFile(`${JSON.stringify(session)}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
    try {
      await rename(temp, this.sessionFile);
    } finally {
      await rm(temp, { force: true });
    }
  }

  async load() {
    let stat;
    try {
      stat = await lstat(this.sessionFile);
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error('Not connected; run hostwatch-mcp-node login');
      throw error;
    }
    if (!stat.isFile()) throw new Error('Hostwatch session path is not a regular file');
    assertOwnerOnly(stat, 'Hostwatch session file');
    if (stat.size > 1024 * 1024) throw new Error('Hostwatch session file is too large');
    const session = JSON.parse(await readFile(this.sessionFile, 'utf8'));
    if (session.origin !== this.origin || !session.clientId || !session.accessToken || !session.refreshToken || !Number.isFinite(session.expiresAt)) {
      throw new Error('Hostwatch session is incomplete or belongs to another origin; run login');
    }
    return session;
  }

  async form(endpoint, values) {
    const response = await this.request(endpoint, {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(values),
    });
    if (!response.ok) throw new Error(`Hostwatch OAuth HTTP ${response.status}`);
    return JSON.parse(await readLimited(response, 1024 * 1024));
  }

  tokenSession(previous, token) {
    if (!token.access_token || !token.refresh_token || token.token_type?.toLowerCase() !== 'bearer' || !(token.expires_in > 0)) {
      throw new Error('Hostwatch returned an incomplete OAuth token response');
    }
    return {
      origin: this.origin, clientId: previous.clientId,
      accessToken: token.access_token, refreshToken: token.refresh_token,
      scope: token.scope || '', expiresAt: Date.now() + token.expires_in * 1000,
    };
  }

  async login({ write = false, noBrowser = false, input = process.stdin, output = process.stdout } = {}) {
    const metadata = await this.metadata();
    const nonce = random();
    const state = random();
    const verifier = random();
    const callbackPath = `/callback/${nonce}`;
    let acceptCallback;
    const callbackPromise = new Promise(resolve => { acceptCallback = resolve; });
    const server = createServer((req, res) => {
      const requestURL = new URL(req.url, 'http://127.0.0.1');
      if (req.method !== 'GET' || requestURL.pathname !== callbackPath) {
        res.writeHead(404).end(); return;
      }
      const received = Buffer.from(requestURL.searchParams.get('state') || '');
      const expected = Buffer.from(state);
      if (received.length !== expected.length || !timingSafeEqual(received, expected)) {
        res.writeHead(400).end('OAuth state mismatch'); return;
      }
      acceptCallback(requestURL);
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' }).end('Hostwatch authorization received. Return to the terminal.\n');
    });
    await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
    const redirectURI = `http://127.0.0.1:${server.address().port}${callbackPath}`;
    try {
      const registration = await this.request(metadata.registration_endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ client_name: 'Hostwatch npm MCP', redirect_uris: [redirectURI], token_endpoint_auth_method: 'none' }),
      });
      if (!registration.ok) throw new Error(`Hostwatch registration HTTP ${registration.status}`);
      const { client_id: clientId } = JSON.parse(await readLimited(registration, 1024 * 1024));
      if (!clientId) throw new Error('Hostwatch did not return an OAuth client ID');
      const authURL = new URL(metadata.authorization_endpoint);
      authURL.search = new URLSearchParams({
        response_type: 'code', client_id: clientId, redirect_uri: redirectURI,
        code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
        state, scope: write ? 'hostwatch:read hostwatch:write' : 'hostwatch:read', resource: `${this.origin}/mcp`,
      }).toString();
      output.write(`Open this Hostwatch authorization URL and choose QR or direct sign-in:\n${authURL.href}\n`);
      if (!noBrowser) {
        try { await this.browser(authURL.href); }
        catch { output.write('Browser did not open automatically; open the URL above manually.\n'); }
      }
      let callback;
      if (noBrowser) {
        output.write('Paste the full callback URL after approving the connection:\n');
        const line = await firstLine(input);
        callback = new URL(line.trim());
        if (`${callback.origin}${callback.pathname}` !== redirectURI) throw new Error('Callback URL does not match this sign-in request');
      } else {
        callback = await withTimeout(callbackPromise, 5 * 60_000);
      }
      const received = Buffer.from(callback.searchParams.get('state') || '');
      const expected = Buffer.from(state);
      if (received.length !== expected.length || !timingSafeEqual(received, expected)) throw new Error('OAuth state mismatch');
      if (callback.searchParams.get('iss') && callback.searchParams.get('iss') !== this.origin) throw new Error('OAuth issuer mismatch');
      if (callback.searchParams.has('error')) throw new Error(`Hostwatch authorization denied: ${callback.searchParams.get('error')}`);
      const code = callback.searchParams.get('code');
      if (!code) throw new Error('Hostwatch did not return an authorization code');
      const token = await this.form(metadata.token_endpoint, {
        grant_type: 'authorization_code', client_id: clientId, redirect_uri: redirectURI,
        code, code_verifier: verifier, resource: `${this.origin}/mcp`,
      });
      await this.save(this.tokenSession({ clientId }, token));
      output.write('Connected to your Hostwatch account. MCP access is ready.\n');
    } finally {
      server.close();
    }
  }

  async refresh(session) {
    const metadata = await this.metadata();
    let token;
    try {
      token = await this.form(metadata.token_endpoint, {
        grant_type: 'refresh_token', client_id: session.clientId,
        refresh_token: session.refreshToken, resource: `${this.origin}/mcp`,
      });
    } catch (error) {
      const current = await this.load().catch(() => null);
      if (current?.clientId === session.clientId && current.refreshToken !== session.refreshToken && current.expiresAt - Date.now() >= 60_000) return current;
      throw new Error(`Hostwatch session expired; run login: ${error.message}`);
    }
    const next = this.tokenSession(session, token);
    await this.save(next);
    return next;
  }

  async activeSession() {
    const session = await this.load();
    return session.expiresAt - Date.now() < 60_000 ? this.refresh(session) : session;
  }

  async logout() {
    const session = await this.load();
    const metadata = await this.metadata();
    for (const token of [session.refreshToken, session.accessToken]) {
      await this.form(metadata.revocation_endpoint, { client_id: session.clientId, token });
    }
    await rm(this.sessionFile);
  }

  async forward(message, version) {
    const envelope = JSON.parse(message);
    let session = await this.activeSession();
    for (let attempt = 0; attempt < 2; attempt++) {
      const headers = {
        'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
        Authorization: `Bearer ${session.accessToken}`, 'MCP-Protocol-Version': version,
      };
      if (version === '2026-07-28') {
        headers['Mcp-Method'] = envelope.method;
        if (envelope.params?.name) headers['Mcp-Name'] = envelope.params.name;
      }
      const response = await this.request(`${this.origin}/mcp`, { method: 'POST', headers, body: JSON.stringify(envelope) });
      if (response.status === 401 && attempt === 0) {
        session = await this.refresh(session);
        continue;
      }
      if (response.status === 202 || response.status === 204) return [];
      if (!response.ok) throw new Error(`Hostwatch MCP HTTP ${response.status}`);
      const body = await readLimited(response, maxMessage);
      if (response.headers.get('content-type')?.includes('text/event-stream')) return parseSSE(body);
      return body.trim() ? [JSON.stringify(JSON.parse(body))] : [];
    }
    throw new Error('Hostwatch session expired; run login');
  }

  async serve(input = process.stdin, output = process.stdout) {
    await this.activeSession();
    let protocolVersion = '2025-06-18';
    let capabilities = {};
    let clientInfo = { name: 'hostwatch-npm-mcp', version };
    const lines = createInterface({ input, crlfDelay: Infinity });
    for await (const line of lines) {
      if (!line.trim()) continue;
      if (Buffer.byteLength(line) > maxMessage) continue;
      let request;
      try { request = JSON.parse(line); }
      catch { continue; }
      if (!request || typeof request.method !== 'string') continue;
      if (request.method === 'initialize') {
        protocolVersion = request.params?.protocolVersion || protocolVersion;
        capabilities = request.params?.capabilities || capabilities;
        clientInfo = request.params?.clientInfo || clientInfo;
      }
      if (protocolVersion === '2026-07-28') {
        if (!request.params || typeof request.params !== 'object' || Array.isArray(request.params)) request.params = {};
        if (!request.params._meta || typeof request.params._meta !== 'object' || Array.isArray(request.params._meta)) request.params._meta = {};
        Object.assign(request.params._meta, {
          'io.modelcontextprotocol/protocolVersion': protocolVersion,
          'io.modelcontextprotocol/clientCapabilities': capabilities,
          'io.modelcontextprotocol/clientInfo': clientInfo,
        });
      }
      try {
        const replies = await this.forward(JSON.stringify(request), protocolVersion);
        if (request.method === 'initialize' && replies.length) {
          const negotiated = JSON.parse(replies[0]).result?.protocolVersion;
          if (negotiated) protocolVersion = negotiated;
        }
        for (const reply of replies) output.write(`${reply}\n`);
      } catch (error) {
        if (request.id !== undefined) output.write(`${JSON.stringify({ jsonrpc: '2.0', id: request.id, error: { code: -32000, message: error.message } })}\n`);
      }
    }
  }
}

function parseSSE(body) {
  const replies = [];
  let data = [];
  for (const line of `${body}\n\n`.split(/\r?\n/)) {
    if (line === '') {
      if (data.length) {
        const joined = data.join('\n');
        if (joined !== '[DONE]') replies.push(JSON.stringify(JSON.parse(joined)));
      }
      data = [];
    } else if (line.startsWith('data:')) {
      data.push(line.slice(5).trimStart());
    }
  }
  return replies;
}

function firstLine(input) {
  return new Promise((resolve, reject) => {
    const lines = createInterface({ input, crlfDelay: Infinity });
    lines.once('line', line => { lines.close(); resolve(line); });
    lines.once('close', () => reject(new Error('No callback URL supplied')));
  });
}

function withTimeout(promise, duration) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Hostwatch sign-in timed out')), duration); }),
  ]).finally(() => clearTimeout(timer));
}

async function readLimited(response, limit) {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw new Error('Hostwatch response is too large');
      chunks.push(Buffer.from(value));
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString('utf8');
}

function openBrowser(url) {
  const system = platform();
  const command = system === 'darwin' ? 'open' : system === 'win32' ? 'rundll32' : 'xdg-open';
  const args = system === 'win32' ? ['url.dll,FileProtocolHandler', url] : [url];
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' });
    child.once('error', reject);
    child.once('spawn', () => { child.unref(); resolve(); });
  });
}
