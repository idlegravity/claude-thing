// The daemon binds loopback, but every page open in the user's browser can
// still reach it. Only loopback pages and native clients (no Origin) may in —
// a foreign page must not be able to open /ws and answer a permission.

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

process.env.CLAUDE_THING_PORT = String(20000 + Math.floor(Math.random() * 20000));
const { PORT } = await import('../src/config.js');
const { createHttpServer, isTrustedRequest } = await import('../src/http-server.js');
const { createHub } = await import('../src/hub.js');
const { WebSocket } = await import('ws');

const HOST = `127.0.0.1:${PORT}`;

test('native clients with no Origin are trusted', () => {
  assert.equal(isTrustedRequest({ host: '127.0.0.1:8790' }), true);
  assert.equal(isTrustedRequest({ host: 'localhost:8790' }), true);
  assert.equal(isTrustedRequest({ host: '[::1]:8790' }), true);
});

test('loopback pages are trusted, including the vite dev server', () => {
  assert.equal(isTrustedRequest({ host: '127.0.0.1:8790', origin: 'http://127.0.0.1:8790' }), true);
  assert.equal(isTrustedRequest({ host: 'localhost:5273', origin: 'http://localhost:5273' }), true);
});

test('a foreign page is refused', () => {
  assert.equal(isTrustedRequest({ host: '127.0.0.1:8790', origin: 'https://evil.example' }), false);
  assert.equal(isTrustedRequest({ host: '127.0.0.1:8790', origin: 'null' }), false);
  assert.equal(isTrustedRequest({ host: '127.0.0.1:8790', origin: 'http://127.0.0.1.evil.example' }), false);
});

test('a rebound hostname is refused even with no Origin', () => {
  assert.equal(isTrustedRequest({ host: 'evil.example:8790' }), false);
  assert.equal(isTrustedRequest({}), false);
});

let server;
before(async () => {
  const hub = createHub({});
  hub.setMethods({ 'claude.ping': async () => ({ ok: true }) });
  server = await createHttpServer({
    hub,
    store: { count: () => 0 },
    permissionBridge: { pendingCount: () => 0 },
    sources: { status: () => ({}), hooksInstalled: () => false, onHookEvent() {} },
  });
});
after(() => new Promise((r) => server.close(r)));

function openWs(headers) {
  return new Promise((resolve) => {
    const ws = new WebSocket(`ws://${HOST}/ws`, { headers });
    ws.once('open', () => { ws.close(); resolve('open'); });
    ws.once('unexpected-response', (_req, res) => resolve(res.statusCode));
    ws.once('error', () => resolve('error'));
  });
}

test('the socket opens for a native client and a loopback page', async () => {
  assert.equal(await openWs({}), 'open');
  assert.equal(await openWs({ Origin: `http://${HOST}` }), 'open');
});

test('the socket is refused for a foreign page', async () => {
  assert.equal(await openWs({ Origin: 'https://evil.example' }), 403);
});

test('a foreign page cannot post a hook event', async () => {
  const res = await fetch(`http://${HOST}/hook/Stop`, {
    method: 'POST',
    headers: { Origin: 'https://evil.example', 'Content-Type': 'text/plain' },
    body: '{}',
  });
  assert.equal(res.status, 403);
  const ok = await fetch(`http://${HOST}/hook/Stop`, { method: 'POST', body: '{}' });
  assert.equal(ok.status, 200);
});
