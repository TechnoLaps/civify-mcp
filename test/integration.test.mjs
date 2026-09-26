import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const root = path.resolve(import.meta.dirname || path.dirname(new URL(import.meta.url).pathname.replace(/^\/(\w:)/, '$1')), '..');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'regression', version: '1' } } };
const headers = { 'content-type': 'application/json', accept: 'application/json, text/event-stream' };
async function freePort() {
  const server = http.createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port;
}
async function start(env) {
  const port = Number(env.PORT || await freePort());
  const child = spawn(process.execPath, ['dist/index.js'], { cwd: root, env: { ...process.env, CIVIFY_MCP_PUBLIC_URL: '', ...env, PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'] });
  let logs = ''; child.stderr.on('data', chunk => logs += chunk); child.stdout.on('data', chunk => logs += chunk);
  for (let i = 0; i < 600; i++) {
    if (child.exitCode !== null) throw new Error(logs);
    try { if ((await fetch(`http://127.0.0.1:${port}/health`)).ok) return { url: `http://127.0.0.1:${port}`, logs: () => logs, stop: async () => { if (child.exitCode === null) { child.kill(); await once(child, 'exit'); } } }; } catch {}
    await delay(50);
  }
  child.kill(); throw new Error(`Server did not start: ${logs}`);
}
async function rpc(server, body, extra = {}, route = '/mcp') {
  const response = await fetch(server.url + route, { method: 'POST', headers: { ...headers, ...extra }, body: JSON.stringify(body) });
  const raw = await response.text();
  const text = raw.startsWith('event:') ? raw.split('\n').find(line => line.startsWith('data: '))?.slice(6) : raw;
  return { response, data: text ? JSON.parse(text) : undefined };
}
let rpcId = 100;
const call = (server, name, args = {}, auth = {}, route) => rpc(server, { jsonrpc: '2.0', id: rpcId++, method: 'tools/call', params: { name, arguments: args } }, auth, route);

test('transport, backend contracts, account isolation and OAuth regression', { timeout: 120000 }, async t => {
  const requests = [];
  const handoffs = new Map();
  let failPdf = false;
  const mock = http.createServer(async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString();
    requests.push({ url: req.url, key: req.headers['x-api-key'], body, authorization: req.headers.authorization, requestId: req.headers['x-request-id'], tool: req.headers['x-civify-mcp-tool'], contentType: req.headers['content-type'] });
    if (failPdf && req.url.includes('generate-pdf')) { res.statusCode = 503; res.end('renderer down'); return; }
    if (req.url.includes('generate-pdf') || req.url.endsWith('/mask')) { res.end('%PDF-fixture'); return; }
    res.setHeader('content-type', 'application/json');
    if (req.url === '/mcp/account-link/exchange') {
      const input = JSON.parse(body), pending = handoffs.get(input.code);
      if (!pending || pending.transaction !== input.transaction || pending.challenge !== createHash('sha256').update(input.verifier).digest('base64url')) {
        res.statusCode = 400; res.end('{}'); return;
      }
      handoffs.delete(input.code);
      res.end(JSON.stringify({ apiKey: 'cv-fy-oauth-user', expiresAt: Date.now() + 30 * 86400_000 })); return;
    }
    if (req.headers['x-api-key'] === 'cv-fy-invalid') { res.statusCode = 401; res.end(JSON.stringify({ secret: 'upstream-private-error' })); return; }
    if (req.url.endsWith('/user/profile')) res.end(JSON.stringify({ user: req.headers['x-api-key'] }));
    else if (req.url.endsWith('/parse')) res.end(JSON.stringify({ success: true, resumeData: { personalInfo: { fullName: 'Fixture' }, sections: [] } }));
    else if (req.url.endsWith('/score')) res.end(JSON.stringify({ success: true, data: { overallScore: 85 } }));
    else if (req.url.endsWith('/tailor')) res.end(JSON.stringify({ success: true, tailoredCv: { personalInfo: { fullName: 'Candidate مرشح', phone: null, summary: 'A tailored summary.' }, sections: [] }, atsScore: { overallScore: 90 } }));
    else res.end(JSON.stringify({ success: true }));
  });
  mock.listen(0, '127.0.0.1'); await once(mock, 'listening');
  t.after(() => new Promise(resolve => mock.close(resolve)));
  const backend = `http://127.0.0.1:${mock.address().port}`;
  const env = { CIVIFY_API_URL: backend, CIVIFY_FRONTEND_URL: backend, NO_PROXY: '127.0.0.1,localhost', no_proxy: '127.0.0.1,localhost' };
  const server = await start(env); t.after(server.stop);
  let sid;
  await t.test('initialize, sessionless tools/list and actionable unauthenticated call', async () => {
    const initialized = await rpc(server, init); assert.equal(initialized.response.status, 200);
    sid = initialized.response.headers.get('mcp-session-id'); assert.ok(sid);
    assert.match(initialized.data.result.instructions, /civify_get_started/);
    const listed = await rpc(server, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    assert.equal(listed.data.result.tools.length, 18);
    assert.ok(listed.data.result.tools.every(tool => tool.outputSchema && tool.annotations));
    for (const tool of listed.data.result.tools.filter(tool => ['civify_parse_cv', 'civify_score_ats', 'civify_tailor_cv', 'civify_mask_pii'].includes(tool.name))) {
      assert.deepEqual(tool._meta['openai/fileParams'], ['file']);
      assert.deepEqual(tool.inputSchema.properties.file.required, ['download_url', 'file_id']);
      assert.deepEqual(Object.keys(tool.inputSchema.properties.file.properties).sort(), ['download_url', 'file_id', 'file_name', 'mime_type']);
    }
    const failed = await call(server, 'civify_parse_cv', { resume_text: 'fixture' });
    assert.equal(failed.response.status, 200); assert.equal(failed.data.result.isError, true);
    assert.equal(failed.data.result.structuredContent.data.error.code, 'UNAUTHENTICATED');
  });
  await t.test('per-request credentials work, isolation and scoring unwrap', async () => {
    const auth = { 'x-api-key': 'cv-fy-alice' };
    const parsed = await call(server, 'civify_parse_cv', { resume_text: 'private-resume-fixture', language: 'en' }, auth);
    assert.equal(parsed.data.result.structuredContent.data.resumeData.personalInfo.fullName, 'Fixture');
    await call(server, 'civify_score_ats', { resume_text: 'fixture' }, auth);
    const score = requests.findLast(r => r.url.endsWith('/score'));
    assert.deepEqual(JSON.parse(score.body), { resumeData: { personalInfo: { fullName: 'Fixture' }, sections: [] } });
    const [alice, bob, anonymous] = await Promise.all([
      call(server, 'civify_get_account', {}, { 'x-api-key': 'cv-fy-alice', 'mcp-session-id': sid }),
      call(server, 'civify_get_account', {}, { 'x-api-key': 'cv-fy-bob', 'mcp-session-id': sid }),
      call(server, 'civify_get_account', {}, { 'mcp-session-id': sid }),
    ]);
    assert.equal(alice.data.result.structuredContent.data.user, 'cv-fy-alice');
    assert.equal(bob.data.result.structuredContent.data.user, 'cv-fy-bob');
    assert.equal(anonymous.data.result.isError, true);
    const before = requests.length;
    const unavailable = await call(server, 'civify_parse_cv', { file: { file_id: 'file-real', download_url: 'https://127.0.0.1/private' } }, auth);
    assert.equal(unavailable.data.result.isError, true); assert.equal(requests.length, before);
    const ambiguous = await call(server, 'civify_parse_cv', { resume_text: 'one', file_base64: Buffer.from('two').toString('base64') }, auth);
    assert.equal(ambiguous.data.result.isError, true); assert.equal(requests.length, before);
  });
  await t.test('legacy SSE consumes parsed POST bodies and root uses correct transport', async () => {
    const client = new Client({ name: 'sse-test', version: '1' });
    await client.connect(new SSEClientTransport(new URL(server.url + '/sse')));
    assert.equal((await client.listTools()).tools.length, 18);
    await client.close();
    const controller = new AbortController();
    const response = await fetch(server.url + '/', { headers: { accept: 'text/event-stream', 'mcp-session-id': sid }, signal: controller.signal });
    assert.equal(response.status, 200); controller.abort();
    const unknown = await rpc(server, init, { 'mcp-session-id': 'expired' }); assert.equal(unknown.response.status, 404);
  });
  await t.test('remote PDFs return bytes; files, invalid inputs and secrets are contained', async () => {
    const pdf = await call(server, 'civify_generate_pdf', { resume_data: { personalInfo: {}, sections: [] } });
    assert.equal(Buffer.from(pdf.data.result.structuredContent.data.pdf_base64, 'base64').toString(), '%PDF-fixture');
    const bad = await call(server, 'civify_generate_pdf', { resume_data: {}, output_path: 'forbidden.pdf' });
    assert.equal(bad.data.result.isError, true);
    const invalid = await call(server, 'civify_parse_cv', { resume_text: 123 }, { 'x-api-key': 'cv-fy-alice' });
    assert.equal(invalid.data.result.isError, true);
    const rejected = await call(server, 'civify_get_account', {}, { 'x-api-key': 'cv-fy-invalid' });
    assert.ok(!JSON.stringify(rejected).includes('upstream-private-error'));
    assert.ok(!server.logs().includes('private-resume-fixture')); assert.ok(!server.logs().includes('cv-fy-alice'));
    const malformed = await fetch(server.url + '/mcp', { method: 'POST', headers, body: '{' });
    assert.equal(malformed.status, 400); assert.equal((await malformed.json()).error.code, -32700);
  });
  await t.test('stdio tool logging does not corrupt stdout protocol', async () => {
    const client = new Client({ name: 'stdio-test', version: '1' });
    const transport = new StdioClientTransport({ command: process.execPath, args: ['dist/index.js'], cwd: root, env: { ...process.env, PORT: '', TRANSPORT: '', ...env }, stderr: 'pipe' });
    transport.stderr?.on('data', () => {});
    await client.connect(transport);
    const result = await client.callTool({ name: 'civify_get_started', arguments: {} });
    assert.ok(result.structuredContent.data.workflow); await client.close();
  });

  const directory = await mkdtemp(path.join(tmpdir(), 'civify-oauth-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const port = await freePort(); const origin = `http://127.0.0.1:${port}`;
  const oauthEnv = { ...env, PORT: String(port), CIVIFY_MCP_PUBLIC_URL: origin, CIVIFY_OAUTH_STORE_KEY: randomBytes(32).toString('base64'), CIVIFY_OAUTH_STORE_PATH: path.join(directory, 'oauth.enc') };
  let secured = await start(oauthEnv); t.after(() => secured.stop());
  let tokens, registration;
  async function tokenRequest(body) {
    return fetch(origin + '/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: registration.client_id, ...body }) });
  }
  await t.test('OAuth discovery, consent, PKCE, replay protection and request authentication', async () => {
    const metadata = await (await fetch(origin + '/.well-known/oauth-protected-resource/mcp')).json();
    assert.equal(metadata.resource, origin + '/mcp');
    const listed = await rpc(secured, { jsonrpc: '2.0', id: 3, method: 'tools/list' });
    assert.equal(listed.data.result.tools.length, 13);
    assert.ok(!listed.data.result.tools.some(tool => tool.name === 'civify_login'));
    const unauth = await call(secured, 'civify_get_account');
    assert.equal(unauth.response.status, 401); assert.match(unauth.response.headers.get('www-authenticate'), /oauth-protected-resource\/mcp/);
    const initialized = await rpc(secured, init); assert.equal(initialized.response.headers.get('mcp-session-id'), null);
    registration = await (await fetch(origin + '/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ client_name: 'Test agent', redirect_uris: ['https://client.example/callback'], token_endpoint_auth_method: 'none', grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'] }) })).json();
    assert.ok(registration.client_id);
    const verifier = randomBytes(32).toString('base64url');
    const query = new URLSearchParams({ client_id: registration.client_id, response_type: 'code', redirect_uri: 'https://client.example/callback', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', state: 'test-state', resource: origin + '/mcp', scope: 'civify:tools' });
    const consent = await fetch(origin + '/authorize?' + query, { redirect: 'manual' });
    assert.equal(consent.status, 302);
    const destination = new URL(consent.headers.get('location'));
    assert.equal(destination.origin + destination.pathname, 'https://civify.cv/en/mcp/connect');
    assert.deepEqual([...destination.searchParams.keys()], ['transaction']);
    const transaction = destination.searchParams.get('transaction');
    const cookie = consent.headers.get('set-cookie').split(';')[0];
    const handoff = await (await fetch(origin + '/oauth/transactions/' + transaction)).json();
    assert.equal(handoff.clientName, 'Test agent');
    assert.equal(handoff.verifier, undefined); assert.equal(handoff.csrf, undefined);
    const backendCode = randomBytes(32).toString('base64url');
    handoffs.set(backendCode, handoff);
    const completion = origin + '/oauth/complete?' + new URLSearchParams({ transaction, code: backendCode });
    const rejectedCsrf = await fetch(completion, { redirect: 'manual' });
    assert.equal(rejectedCsrf.status, 400);
    const otherConsent = await fetch(origin + '/authorize?' + query, { redirect: 'manual' });
    const otherCookie = otherConsent.headers.get('set-cookie').split(';')[0];
    assert.equal((await fetch(completion, { redirect: 'manual', headers: { cookie: otherCookie } })).status, 400);
    const cancelled = await fetch(origin + '/oauth/complete?' + new URLSearchParams({ transaction: new URL(otherConsent.headers.get('location')).searchParams.get('transaction'), error: 'access_denied' }), { redirect: 'manual', headers: { cookie: otherCookie } });
    assert.equal(new URL(cancelled.headers.get('location')).searchParams.get('error'), 'access_denied');
    const linked = await fetch(completion, { redirect: 'manual', headers: { cookie } });
    assert.equal(linked.status, 302);
    assert.equal((await fetch(completion, { redirect: 'manual', headers: { cookie } })).status, 400);
    assert.equal((await fetch(origin + '/oauth/transactions/' + transaction)).status, 404);
    assert.equal(handoffs.size, 0);
    const redirect = new URL(linked.headers.get('location')); assert.equal(redirect.searchParams.get('state'), 'test-state');
    const grant = { grant_type: 'authorization_code', code: redirect.searchParams.get('code'), code_verifier: verifier, redirect_uri: 'https://client.example/callback', resource: origin + '/mcp' };
    assert.equal((await tokenRequest({ ...grant, code_verifier: 'wrong' })).status, 400);
    assert.equal((await tokenRequest({ ...grant, redirect_uri: 'https://wrong.example/callback' })).status, 400);
    assert.equal((await tokenRequest({ ...grant, resource: 'https://wrong.example/mcp' })).status, 400);
    tokens = await (await tokenRequest(grant)).json(); assert.ok(tokens.access_token);
    assert.equal((await tokenRequest(grant)).status, 400);
    const account = await call(secured, 'civify_get_account', {}, { authorization: `Bearer ${tokens.access_token}` });
    assert.equal(account.data.result.structuredContent.data.user, 'cv-fy-oauth-user');
    const override = await call(secured, 'civify_get_account', { api_key: 'cv-fy-other-user' }, { authorization: `Bearer ${tokens.access_token}` });
    assert.equal(override.data.result.isError, true);
    assert.equal((await call(secured, 'civify_get_account', {}, { authorization: 'Bearer invalid' })).response.status, 401);
    assert.equal((await call(secured, 'civify_get_account', {}, { 'x-api-key': 'cv-fy-oauth-user' })).response.status, 401);
    const encrypted = await readFile(oauthEnv.CIVIFY_OAUTH_STORE_PATH, 'utf8');
    assert.ok(!encrypted.includes('cv-fy-oauth-user')); assert.ok(!secured.logs().includes('cv-fy-oauth-user'));
    assert.ok(!secured.logs().includes(backendCode));
  });
  await t.test('SDK hosted workflow: attached resume text to tailoring, scoring, downloadable PDF and tracking', async () => {
    const client = new Client({ name: 'cross-client-workflow', version: '1' });
    await client.connect(new StreamableHTTPClientTransport(new URL(origin + '/mcp'), { requestInit: { headers: { authorization: `Bearer ${tokens.access_token}` } } }));
    t.after(() => client.close());
    await client.listTools(); // SDK validates structured results against discovered output schemas.
    const before = requests.filter(item => item.url.endsWith('/parse')).length;
    const result = await client.callTool({ name: 'civify_tailor_cv', arguments: { resume_text: 'Candidate مرشح\nFull CV attachment text\nExperience: TypeScript', job_description: 'TypeScript developer', language: 'en' } });
    assert.equal(result.isError, undefined);
    assert.equal(requests.filter(item => item.url.endsWith('/parse')).length, before, 'Tailoring should not add a separate parse request');
    assert.match(requests.findLast(item => item.url.endsWith('/tailor')).body, /Candidate مرشح/);
    assert.ok(result.structuredContent.data.document.download_url, 'Tailoring delivers the finished PDF by default');
    const tailRequest = requests.findLast(item => item.url.endsWith('/tailor'));
    const exportRequest = requests.findLast(item => item.url.includes('generate-pdf'));
    assert.equal(tailRequest.requestId, result.structuredContent.data.request_id);
    assert.equal(exportRequest.requestId, tailRequest.requestId);
    assert.equal(tailRequest.tool, 'civify_tailor_cv');
    const resume = result.structuredContent.data.tailoredCv;
    const scored = await client.callTool({ name: 'civify_score_ats', arguments: { resume_data: resume } });
    assert.equal(scored.isError, undefined);
    const pdf = await client.callTool({ name: 'civify_generate_pdf', arguments: { resume_data: resume, filename: 'cv-مرشح' } });
    assert.equal(pdf.isError, undefined); assert.equal(pdf.structuredContent.data.pdf_base64, undefined);
    const link = pdf.content.find(item => item.type === 'resource_link'); assert.ok(link);
    const downloaded = await fetch(link.uri); assert.equal(downloaded.headers.get('content-type'), 'application/pdf');
    assert.equal(await downloaded.text(), '%PDF-fixture'); assert.match(downloaded.headers.get('cache-control'), /no-store/);
    const masked = await client.callTool({ name: 'civify_mask_pii', arguments: { resume_text: 'Candidate contact details' } });
    assert.ok(masked.structuredContent.data.download_url);
    const tracked = await client.callTool({ name: 'civify_track_application', arguments: { company_name: 'Example', job_title: 'Developer' } });
    assert.equal(tracked.isError, undefined);
    assert.ok(!secured.logs().includes(new URL(link.uri).pathname));
    await client.close();
  });
  await t.test('structured tailoring skips parsing; export failure preserves paid result and retries export only', async () => {
    const auth = { authorization: `Bearer ${tokens.access_token}` };
    const resume = { personalInfo: { fullName: 'Fixture' }, sections: [] };
    const parseCount = requests.filter(item => item.url.endsWith('/parse')).length;
    failPdf = true;
    let result;
    try { result = await call(secured, 'civify_tailor_cv', { resume_data: resume, job_description: 'Developer' }, auth); }
    finally { failPdf = false; }
    assert.equal(result.data.result.isError, undefined);
    const data = result.data.result.structuredContent.data;
    assert.ok(data.tailoredCv);
    assert.equal(data.document.status, 'EXPORT_FAILED');
    assert.equal(data.document.retry_tool, 'civify_generate_pdf');
    const tailor = requests.findLast(item => item.url.endsWith('/tailor'));
    assert.match(tailor.contentType, /application\/json/);
    assert.deepEqual(JSON.parse(tailor.body).resumeData, resume);
    assert.equal(requests.filter(item => item.url.endsWith('/parse')).length, parseCount);
    const tailorCount = requests.filter(item => item.url.endsWith('/tailor')).length;
    const pdf = await call(secured, 'civify_generate_pdf', { resume_data: data.tailoredCv });
    assert.ok(pdf.data.result.structuredContent.data.download_url);
    assert.equal(requests.filter(item => item.url.endsWith('/tailor')).length, tailorCount);
    const count = requests.length;
    const ambiguous = await call(secured, 'civify_tailor_cv', { resume_data: resume, resume_text: 'duplicate', job_description: 'Developer' }, auth);
    assert.equal(ambiguous.data.result.isError, true);
    assert.equal(requests.length, count);
    const noExport = await call(secured, 'civify_tailor_cv', { resume_data: resume, job_description: 'Developer', export_pdf: false }, auth);
    assert.equal(noExport.data.result.structuredContent.data.document.status, 'NOT_REQUESTED');
    assert.ok(!secured.logs().includes('Candidate مرشح'));
  });
  await t.test('OAuth survives restart, binds resource, rotates refresh and revokes grant', async () => {
    assert.ok(tokens?.refresh_token);
    await secured.stop(); secured = await start(oauthEnv);
    assert.equal((await call(secured, 'civify_get_account', {}, { authorization: `Bearer ${tokens.access_token}` })).data.result.isError, undefined);
    assert.equal((await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, resource: 'https://other.example/mcp' })).status, 400);
    const refreshed = await (await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).json();
    assert.ok(refreshed.access_token);
    assert.equal((await tokenRequest({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token })).status, 400);
    const revoked = await fetch(origin + '/revoke', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ client_id: registration.client_id, token: refreshed.refresh_token }) });
    assert.equal(revoked.status, 200);
    assert.equal((await call(secured, 'civify_get_account', {}, { authorization: `Bearer ${refreshed.access_token}` })).response.status, 401);
  });
});
