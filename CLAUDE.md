# Civify MCP

In the shared Civify workspace, start at `../Knowledge/README.md`, then read
`../Knowledge/mcp-runbook.md` and the relevant backend contract reference.
The main backend is `../civify/`; Production is deployed, while its current checkout
may be an older main branch. Use targeted Production source reads.

Implementation: `src/index.ts` holds tool dispatch/transports; `src/oauth.ts` holds
OAuth consent, token lifecycle and encrypted single-replica storage. Run `npm test`;
tests use a local mock backend. Keep shared Knowledge current after verified changes.
See README.md for standalone installation and deployment instructions.

Hosted account linking uses Civify web sign-in at /en/mcp/connect, not an API-key
form. /oauth/transactions/:id exposes only public request metadata; /oauth/complete
requires its browser cookie and exchanges a 60-second backend code with a private
S256 verifier. Backend /mcp/account-link and frontend consent must deploy first.
See ../Knowledge/2026-09-25-account-linking.md for service-specific settings/tests.
