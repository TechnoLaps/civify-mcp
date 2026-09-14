# Civify Model Context Protocol (MCP) Server

[![npm version](https://img.shields.io/npm/v/@civify/mcp-server.svg)](https://www.npmjs.com/package/@civify/mcp-server)
[![smithery badge](https://smithery.ai/badge/technolabs/civify)](https://smithery.ai/servers/technolabs/civify)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Official [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for the **[Civify Career Platform](https://civify.cv)**. 

Enables autonomous AI agents (Claude Desktop, Cursor, OpenCode, Qwen CLI, LibreChat, and custom agents) to directly interact with Civify's AI resume parsing, ATS scoring, resume tailoring, PII redaction, Pay-Per-CV monetization, and job application tracking engines.

---

## ⚡ Quick Start & Connection Options

### Option A: Hosted Remote — Streamable HTTP (Recommended — Zero Install)
Connect directly to Civify's managed cloud MCP server using the new Streamable HTTP transport:

- **Streamable HTTP URL:** `https://mcp.civify.cv/mcp`
- **Legacy SSE URL:** `https://mcp.civify.cv/sse`
- **Healthcheck:** `https://mcp.civify.cv/health`

#### Claude Desktop (Custom Connector)
Add a custom connector with URL `https://mcp.civify.cv/mcp` — no config needed, authentication happens interactively in chat.

#### Claude Desktop / MCP Client Config
```json
{
  "mcpServers": {
    "civify": {
      "url": "https://mcp.civify.cv/mcp"
    }
  }
}
```

#### Legacy SSE (Smithery, older clients)
```json
{
  "mcpServers": {
    "civify": {
      "url": "https://mcp.civify.cv/sse"
    }
  }
}
```

---

### Option B: Local Command (npx / stdio)
Run locally using Node.js without pre-installing:

```bash
npx -y @civify/mcp-server
```

#### Claude Desktop Configuration
Edit your `claude_desktop_config.json`:
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

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

#### Cursor Configuration
Add to your project's `.cursor/mcp.json`:

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

#### OpenCode / Agent CLI
```bash
npx -y @civify/mcp-server
```

---

## 🔐 Dynamic Multi-User Authentication

No hardcoded or static API key is required at startup. The MCP server supports interactive, per-session authentication out of the box:

1. **Sign In (`civify_login`):** Users can authenticate with their Civify email/username and password. The agent automatically retrieves a session key (with 2FA support via `civify_verify_2fa`).
2. **Register (`civify_register`):** New users can create an account directly through the agent conversation.
3. **Direct API Key (`civify_set_api_key`):** Users who already hold a developer key (`cv-fy-...`) can provide it at any point in the chat or configure `CIVIFY_API_KEY` in client settings.

---

## 🧰 Available Tools (17 Tools)

### 1. Authentication & Profile
| Tool | Description | Auth Required? |
| :--- | :--- | :---: |
| `civify_set_api_key` | Set or activate an existing Civify API key (`cv-fy-...`) for this session | No |
| `civify_login` | Sign in with email/username and password; auto-provisions session key | No |
| `civify_verify_2fa` | Complete two-factor authentication using the 6-digit email OTP | No |
| `civify_register` | Register a new Civify account | No |
| `civify_logout` | Clear active credentials and reset session state | No |
| `civify_get_account` | Get profile, active plan, remaining AI tokens, and CV pass credits | Yes |

### 2. Monetization & Pay-Per-CV
| Tool | Description | Auth Required? |
| :--- | :--- | :---: |
| `civify_get_pay_per_cv_pricing` | Get localized Pay-Per-CV pricing (USD & EGP regional rates) | **Public (No)** |
| `civify_purchase_cv_pass` | Purchase single CV pass or 3-pack (Card or Mobile Wallet) | Yes |
| `civify_check_cv_entitlement` | Verify if a CV has an active 30-day unwatermarked pass and edit rights | Yes |

### 3. Job Intelligence & Resume AI
| Tool | Description | Auth Required? |
| :--- | :--- | :---: |
| `civify_scrape_job` | Scrape and extract requirements from job URLs (LinkedIn, Greenhouse, etc.) | **Public (No)** |
| `civify_parse_cv` | Parse a PDF/DOCX/image resume into structured JSON schema | Yes |
| `civify_tailor_cv` | Tailor bullet points against a target job description + cover letter generation | Yes |
| `civify_score_ats` | Calculate ATS score and structural audit (document or JSON) | Yes |
| `civify_mask_pii` | Redact sensitive personal contact information, export anonymized PDF | Yes |
| `civify_generate_pdf` | Render high-fidelity PDF from structured resume data | No |

### 4. Application Tracking (Kanban)
| Tool | Description | Auth Required? |
| :--- | :--- | :---: |
| `civify_track_application` | Add a job application to the candidate's Kanban board | Yes |
| `civify_list_applications` | List all tracked job applications with status and dates | Yes |

---

## ⚙️ Optional Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `CIVIFY_API_KEY` | *(None)* | Pre-seeds a default API key for the session. Can also be set interactively via `civify_set_api_key` or `civify_login`. |

---

## 🌟 Registry Listings

- **Smithery:** [https://smithery.ai/servers/technolabs/civify](https://smithery.ai/servers/technolabs/civify)
- **Glama:** List on [https://glama.ai/mcp/servers](https://glama.ai/mcp/servers).
- **PulseMCP:** Listed in the curated registry at [https://pulsemcp.com](https://pulsemcp.com).

---

## 📄 License
MIT © [Civify Team](https://civify.cv)
