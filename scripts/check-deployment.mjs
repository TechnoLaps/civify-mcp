// Read-only hosted readiness check. No CVs, paid AI calls or account mutations.
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const endpoint = new URL(process.argv[2] || 'https://mcp.civify.cv/mcp');
const client = new Client({ name: 'civify-deployment-check', version: '1.0.0' });
const checks = [];
async function get(path) {
  const response = await fetch(new URL(path, endpoint), { signal: AbortSignal.timeout(15000) });
  return { status: response.status, body: response.ok ? await response.json() : null };
}
try {
  const health = await get('/health');
  checks.push({ check: 'health', pass: health.status === 200, version: health.body?.version });
  checks.push({ check: 'hosted_oauth_enabled', pass: health.body?.authentication === 'oauth' });
  for (const path of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-authorization-server']) {
    const response = await get(path);
    checks.push({ check: path, pass: response.status === 200, http_status: response.status });
  }
  await client.connect(new StreamableHTTPClientTransport(endpoint));
  const { tools } = await client.listTools();
  checks.push({ check: 'hosted_tool_catalog', pass: tools.length === 13 && !tools.some(tool => tool.name === 'civify_login'), count: tools.length });
  const started = await client.callTool({ name: 'civify_get_started', arguments: {} }, undefined, { timeout: 15000 });
  const delivery = started.structuredContent?.data?.pdf_delivery || '';
  checks.push({ check: 'pdf_download_links_configured', pass: !started.isError && delivery.includes('download_url'), mode: delivery.includes('base64') ? 'base64' : delivery.includes('download_url') ? 'download_url' : 'unknown' });
} catch (error) {
  // Do not dump upstream bodies, headers or configuration values.
  checks.push({ check: 'protocol_connection', pass: false, error_type: error.name });
} finally {
  await client.close();
}
console.log(JSON.stringify({ checks, ready: checks.length > 0 && checks.every(check => check.pass) }, null, 2));
if (checks.some(check => !check.pass)) process.exitCode = 1;
