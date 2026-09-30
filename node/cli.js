#!/usr/bin/env node

import { HostwatchClient, version } from './client.js';

const usage = `Hostwatch MCP npm bridge: connect an MCP client to your Hostwatch account.

Usage:
  hostwatch-mcp-node login [--write] [--no-browser]
  hostwatch-mcp-node serve
  hostwatch-mcp-node status
  hostwatch-mcp-node logout
  hostwatch-mcp-node version

Run login once, then configure your MCP client to launch "hostwatch-mcp-node serve".
Login opens Hostwatch in your browser for direct or QR sign-in.
Read access is the default. --write requests owner-approved write access.

Environment:
  HOSTWATCH_ORIGIN             Hostwatch HTTPS origin (default https://gethostwatch.com)
  HOSTWATCH_NODE_SESSION_FILE  Local OAuth session path (default user config directory)
`;

export async function run(args, { input = process.stdin, output = process.stdout } = {}) {
  const command = args[0];
  if (!command || ['help', '--help', '-h'].includes(command)) { output.write(usage); return; }
  if (command === 'version') { output.write(`hostwatch-mcp-node ${version}\n`); return; }
  const client = new HostwatchClient();
  switch (command) {
    case 'login': {
      const unknown = args.slice(1).filter(arg => !['--write', '--no-browser'].includes(arg));
      if (unknown.length) throw new Error(`Unknown login option: ${unknown[0]}`);
      await client.login({ write: args.includes('--write'), noBrowser: args.includes('--no-browser'), input, output });
      break;
    }
    case 'serve':
      if (args.length !== 1) throw new Error('serve takes no arguments');
      await client.serve(input, output);
      break;
    case 'status': {
      if (args.length !== 1) throw new Error('status takes no arguments');
      const session = await client.load();
      output.write(`Connected to ${session.origin}\nScopes: ${session.scope}\n`);
      output.write(session.expiresAt <= Date.now() ? 'Access token expired; it will refresh on the next request.\n' : `Access token expires: ${new Date(session.expiresAt).toLocaleString()}\n`);
      break;
    }
    case 'logout':
      if (args.length !== 1) throw new Error('logout takes no arguments');
      await client.logout();
      output.write('Hostwatch connection revoked.\n');
      break;
    default: throw new Error(`Unknown command ${command}; use --help`);
  }
}

run(process.argv.slice(2)).catch(error => {
  process.stderr.write(`hostwatch-mcp-node: ${error.message}\n`);
  process.exitCode = 1;
});
