# Civify MCP

In the shared Civify workspace, start at `../Knowledge/README.md`, then read
`../Knowledge/mcp-runbook.md` and the relevant backend contract reference.
The main backend is `../civify/`; Production is deployed, while its current checkout
may be an older main branch. Use targeted Production source reads.

Implementation: `src/index.ts` holds tool dispatch/transports; `src/oauth.ts` holds
OAuth consent, token lifecycle and encrypted single-replica storage. Run `npm test`;
tests use a local mock backend. Keep shared Knowledge current after verified changes.
See README.md for standalone installation and deployment instructions.
