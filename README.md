# Civify Model Context Protocol (MCP) Server

[![npm version](https://img.shields.io/npm/v/@civify/mcp-server.svg)](https://www.npmjs.com/package/@civify/mcp-server)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Official [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for the **[Civify Career Platform](https://civify.cv)**. 

Connects autonomous AI agents (Claude Desktop, Cursor, OpenCode, Qwen CLI, custom agents) directly to Civify's AI resume parsing, ATS scoring, resume tailoring, PII redaction, and application tracking engines.

---

## ⚡ Quick Start

You do not need to install this package manually. AI clients can run it directly using `npx`:

```bash
npx -y @civify/mcp-server
```

### 1. Get your Civify API Key
1. Sign in to your account at [https://civify.cv](https://civify.cv).
2. Go to **Settings $\to$ API Keys** (`https://civify.cv/settings/api-keys`).
3. Create an active API key (`cv-fy-...`).

---

## 🛠️ Client Configuration

### Claude Desktop
Edit your `claude_desktop_config.json`:
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "civify": {
      "command": "npx",
      "args": ["-y", "@civify/mcp-server"],
      "env": {
        "CIVIFY_API_KEY": "cv-fy-your-api-key-here"
      }
    }
  }
}
```

### Cursor
Add to your project's `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "civify": {
      "command": "npx",
      "args": ["-y", "@civify/mcp-server"],
      "env": {
        "CIVIFY_API_KEY": "cv-fy-your-api-key-here"
      }
    }
  }
}
```

### OpenCode / CLI Agents
Add to your `opencode.json` or run directly:
```bash
CIVIFY_API_KEY="cv-fy-..." npx -y @civify/mcp-server
```

---

## 🧰 Available MCP Tools

| Tool | Description | Key Arguments |
| :--- | :--- | :--- |
| `civify_parse_cv` | Parses a PDF, DOCX, or image resume into structured JSON | `file_path`, `language` |
| `civify_tailor_cv` | Optimizes CV bullet points & keywords against a target JD | `file_path`, `job_description`, `job_title`, `generate_cover_letter` |
| `civify_score_ats` | Calculates general 0–100 ATS compatibility score | `resume_id` |
| `civify_mask_pii` | Sanitizes personal contact info for blind applications | `file_path` |
| `civify_scrape_job` | Extracts clean job requirements from LinkedIn/Greenhouse URLs | `url` |
| `civify_track_application` | Adds a job application to the user's Civify Kanban tracker | `company_name`, `job_title`, `status`, `job_url` |
| `civify_get_account` | Checks token balance, subscription tier, and CV credits | *(none)* |
| `civify_get_pay_per_cv_pricing` | Retrieves localized single CV unlock pricing (USD & EGP) | *(none)* |

---

## ⚙️ Environment Variables

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `CIVIFY_API_KEY` | **Yes** | `""` | Your Civify developer API key (`cv-fy-...`) |
| `CIVIFY_API_URL` | No | `https://civify.cv/apis` | Civify backend API base URL |

---

## 🚀 How to Publish to npm

### Step 1: Login to npm
Ensure you have an active npm account and are logged in via CLI:
```bash
npm login
```

### Step 2: Build the Package
```bash
npm run build
```

### Step 3: Publish to npm
Since the package is scoped (`@civify`), publish with public access:
```bash
npm publish --access public
```

*(If you prefer an unscoped name like `civify-mcp`, update `"name": "civify-mcp"` in `package.json` before publishing).*

---

## 🌐 How to Deploy Remote SSE Server (Docker / Cloud)

For cloud agents that connect via Server-Sent Events (`sse`), you can deploy this server as a standalone HTTP service:

### Dockerfile
```dockerfile
FROM node:22-alpine
WORKDIR /app
COPY package*.json tsconfig.json ./
RUN npm ci
COPY src/ ./src/
RUN npm run build
EXPOSE 8080
CMD ["node", "dist/index.js"]
```

---

## 🌟 Registry Listings (Driving Agent Traffic)

1. **Smithery**: Add your repo URL on [https://smithery.ai](https://smithery.ai) for 1-click install.
2. **Glama**: Submit to [https://glama.ai/mcp/servers](https://glama.ai/mcp/servers).
3. **PulseMCP**: List in the curated registry at [https://pulsemcp.com](https://pulsemcp.com).

---

## 📄 License
MIT © Civify Team
