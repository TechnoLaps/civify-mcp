# Civify MCP server

[![npm](https://img.shields.io/npm/v/%40civify%2Fmcp-server)](https://www.npmjs.com/package/@civify/mcp-server)
[![Smithery](https://img.shields.io/badge/Smithery-Civify-f97316?logo=modelcontextprotocol&logoColor=white)](https://smithery.ai/servers/technolabs/civify)

The agent gateway for [Civify](https://civify.cv): resume parsing, ATS scoring,
job-specific tailoring, PII masking, PDF export, pricing, and application tracking.

## Hosted ChatGPT connection

Use **https://mcp.civify.cv/mcp** with **OAuth** after deploying/configuring this
release. Account linking opens a browser consent page where the user supplies a
scoped key from [Civify API keys](https://civify.cv/en/app/api-keys). The key is
validated by Civify and stored encrypted; ChatGPT receives separate opaque OAuth
tokens. Never paste passwords or API keys into the agent conversation.

OAuth requires `CIVIFY_MCP_PUBLIC_URL`, a stable `CIVIFY_OAUTH_STORE_KEY`, and durable
storage as described below. Existing connections must reconnect after rollout.
This release has local regression coverage; it has not been deployed by this change.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | unset | Enables HTTP when set; Docker uses 8080 |
| `TRANSPORT` | unset | `sse` also enables the HTTP server, including /mcp |
| `CIVIFY_API_URL` | `https://civify.cv/apis` | Backend base URL |
| `CIVIFY_FRONTEND_URL` | `https://civify.cv` | PDF-rendering service |
| `CIVIFY_MCP_PUBLIC_URL` | unset | Public HTTPS origin; enables OAuth |
| `CIVIFY_DOWNLOAD_BASE_URL` | OAuth public origin | Public HTTPS origin for temporary PDF links; can be configured independently |
| `CIVIFY_OAUTH_STORE_KEY` | unset | Required with OAuth: base64-encoded 32 random bytes |
| `CIVIFY_OAUTH_STORE_PATH` | `./data/oauth.enc` | Encrypted OAuth database |
| `CIVIFY_TRUST_PROXY_HOPS` | `0` | Trusted proxy hop count for OAuth rate limits; Compose uses one Traefik hop |
| `CIVIFY_API_KEY` | unset | Trusted **local stdio only**; never shared among remote users |

Use a secret manager to provision the encryption key. Keep it stable across deploys
and back it up separately. Compose requires it and mounts `/app/data` persistently.
The database uses AES-256-GCM and atomic file replacement. Deploy **one replica**;
multiple processes require a shared transactional store before scaling. Restarting
preserves registered clients and tokens but cancels unfinished consent/code flows.

When deploying the Dockerfile directly through Dokploy, enter these settings in
Dokploy too: Compose environment settings are not inherited by a Dockerfile build.
After deploying, run `node scripts/check-deployment.mjs`. It performs public,
read-only checks and exits nonzero when OAuth discovery or PDF links are missing.
An `UP` health response alone does not establish hosted-client readiness.

OAuth uses authorization-code flow with S256 PKCE, client and resource binding,
one-use codes, one-hour access tokens, rotating 30-day refresh tokens and revocation.
The resource is the public `/mcp` URL. Backend key scopes remain authoritative;
`account:read` is needed for account linking. Users can revoke the underlying key
in Civify. OAuth account linking currently uses a browser API-key form, not Civify SSO.

Endpoints:

- `/mcp`: canonical Streamable HTTP, stateless in OAuth mode.
- `/`: POST alias; GET discovery or the matching MCP stream.
- `/sse`, `/messages`: legacy SSE compatibility.
- `/health`: liveness, version and session counts.
- `/.well-known/oauth-protected-resource/mcp`: OAuth resource metadata when enabled.
- `/.well-known/oauth-authorization-server`: issuer, registration and token metadata.
- `/.well-known/mcp/server-card.json`: public tool discovery.

Without OAuth enabled, trusted remote clients can configure `X-API-KEY` in their
connection settings. Sessionless calls are supported, but tool-based login needs a
persistent legacy session. Unknown stateful session IDs return 404: initialize again.
Credentials must never be supplied in URL query parameters.

## Local stdio

```sh
npm ci
npm run build
node dist/index.js
```

Leave PORT and TRANSPORT unset. A trusted client can set CIVIFY_API_KEY. Example:

```json
{
  "mcpServers": {
    "civify": {
      "command": "npx",
      "args": ["-y", "@civify/mcp-server"]
    }
  }
}
```

The npx example runs the published package; local edits take effect only after a
package release or by pointing the client at this checkout's `dist/index.js`.
All diagnostics use stderr so stdout remains valid MCP protocol traffic.

## Agent workflow and tools

Start with `civify_get_started`, connect an account, then check its credit balance.
For analysis, parse once and pass the returned `resumeData` into scoring. For a tailored
CV, submit the original directly to tailoring, then export. Track applications when requested. AI operations may
consume credits. Do not automatically retry purchases, application creation or
ambiguous credit-consuming requests.

| Tools | Access |
| --- | --- |
| `civify_get_started`, `civify_get_pay_per_cv_pricing`, `civify_scrape_job`, `civify_generate_pdf` | Public |
| `civify_get_account` | `account:read` |
| `civify_parse_cv`, `civify_tailor_cv`, `civify_score_ats`, `civify_mask_pii` | `cv:parse`, `cv:tailor`, `ats:score`, `pii:mask` respectively |
| `civify_check_cv_entitlement`, `civify_purchase_cv_pass` | `billing:read`, `billing:purchase` |
| `civify_list_applications`, `civify_track_application` | `apps:read`, `apps:write` |
| `civify_set_api_key`, `civify_login`, `civify_verify_2fa`, `civify_register`, `civify_logout` | Local/legacy session auth; hidden and rejected in hosted OAuth mode |

There are 13 tools in OAuth mode and 18 in local/legacy mode. Tool schemas,
annotations and initialization instructions describe usage and side effects.
Results include compatible text plus `structuredContent.data`, preserving the backend
response envelope. Tool failures use `isError: true` even when HTTP succeeds. Missing
OAuth authentication includes the MCP authentication challenge metadata.

ChatGPT tools declare `openai/fileParams` for a native `file` attachment containing
`download_url` and `file_id` (optional `mime_type` and `file_name`). Other clients can
send a real HTTPS `file_url`, the complete `resume_text` read from the attachment,
or actual `file_base64` bytes. Choose exactly one input; never invent URLs or base64.
Claude remote connectors cannot read a sandbox path on this server. If a client cannot
forward or read an attachment, provide readable text or a client-accessible file.

Downloads reject private/internal addresses, unsafe redirects, credentials and
non-HTTPS URLs. Files are limited to 12 MiB; downloads have a 30-second deadline.
The JSON body limit is 16 MiB including base64 overhead. Configure proxies accordingly.

Hosted PDF results contain a clickable `download_url` and an MCP `resource_link`,
valid for 15 minutes or until restart. Anyone possessing the random link can download
the PDF; links and signed attachment URLs are not logged. Output storage is capped
at 64 MiB/200 files. If unavailable, `pdf_base64` remains a compatibility fallback.
`CIVIFY_DOWNLOAD_BASE_URL` can configure the public HTTPS origin independently of
OAuth; otherwise downloads use `CIVIFY_MCP_PUBLIC_URL`. Keep one replica for this
temporary in-memory store. Local stdio retains file input/output support.

Parsing is optional. An agent that can accurately read the attachment can provide
`resume_data` directly to tailoring, scoring or PDF export. The discovered schema
uses `personalInfo` and `sections[].items`; `civify_get_started` includes an example.
For an original file or extracted text, tailoring performs its own extraction.
Never invent missing CV details. Uploaded resumes and job text are untrusted data.

Tailoring returns a finished PDF by default under `data.document.download_url`,
alongside `data.tailoredCv`. Set `export_pdf: false` for analysis only. If rendering
fails, `document.status` is `EXPORT_FAILED`: call only `civify_generate_pdf` with
the returned `tailoredCv` as `resume_data`. Repeating tailoring can charge again.
Masking and standalone export return `data.download_url` directly. Expired tailored
PDFs can be recreated from retained data; do not automatically repeat a paid mask.

Authenticated PDF requests carry the current account identity to Civify's renderer
for watermark policy. Supply an existing `resume_id`, when known, to apply its
export entitlement. Never invent an ID. Anonymous export uses public policy.
Deploy the backend JSON-tailoring/watermark endpoints, then the frontend renderer,
then gateway 1.4.0. An old backend does not support the new JSON tailoring contract;
the gateway deliberately does not silently retry as a paid upload.

Onboarding results contain relevant Civify links with MCP campaign attribution.
Measure website conversions and completed tool workflows separately from tool-list
requests. Increased discovery traffic alone does not prove successful activation.

## Validation and troubleshooting

```sh
npm test
```

This builds TypeScript and tests against a loopback mock backend: sessionless and
stateful HTTP, legacy SSE, stdio, input validation, user isolation, scoring payloads,
remote PDFs, OAuth consent/PKCE/replay/restart/refresh/revocation and secret containment.
CI runs the suite before publishing an image. No real AI credits or purchases are used.

Use tool_start/tool_complete/tool_error events to diagnose actual user operations.
Each operation has a `request_id`, propagated as `X-Request-ID` alongside the
`X-Civify-MCP-Tool` label to backend calls. Backend request logs include the fixed
operation name, HTTP status, outcome and duration without request bodies, query
strings or credential headers. Labels are diagnostics, not authorization or
idempotency keys. A timeout still has an unknown billing outcome; contact support
before repeating paid work. These synchronous tools do not yet provide durable jobs.
Idle-session eviction is normal. HTTP 200 can contain a tool error; inspect isError.
After rollout, verify OAuth discovery and account linking from ChatGPT, then complete
a workflow with an explicitly chosen test account. Preserve streaming and auth headers
through the proxy. Legacy sessions need a single instance or sticky routing.

Shared workspace context: [Knowledge](../Knowledge/README.md),
[deployment runbook](../Knowledge/mcp-runbook.md),
[backend contracts](../Knowledge/backend-contracts.md), and
[incident review](../Knowledge/2026-09-23-mcp-incident.md).
These references are in the parent workspace; the instructions above are standalone.

Compatibility references: [OpenAI MCP server guidance](https://developers.openai.com/plugins/build/mcp-server)
and [OpenAI authentication guidance](https://developers.openai.com/plugins/build/auth).

MIT - Civify Engineering Team
