import { writeFileSync } from 'node:fs';
import { advertisedTools } from '../dist/index.js';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { version } = require('../package.json');
if (!process.argv[2]) throw new Error('Pass the destination server-card.json path. Run npm run build first.');
writeFileSync(process.argv[2], JSON.stringify({
  serverInfo: { name: 'Civify MCP Server', version, description: 'Resume attachment processing, ATS scoring, tailoring, PDF downloads and application tracking.' },
  authentication: { required: false, description: 'Public discovery and onboarding. Private tools require browser OAuth account linking.' },
  configSchema: { type: 'object', properties: {} },
  tools: advertisedTools({ remote: true, oauth: true }), resources: [], prompts: [],
}, null, 2) + '\n');
