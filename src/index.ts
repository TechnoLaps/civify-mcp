#!/usr/bin/env node

/**
 * Civify Model Context Protocol (MCP) Server
 * Supports triple transport:
 * 1. Stdio (Local desktop/CLI agents: Claude Desktop, Cursor, OpenCode)
 * 2. Remote SSE (Legacy cloud deployments and Smithery registry)
 * 3. Streamable HTTP (New MCP standard — Claude Desktop connectors, modern agents)
 *
 * Dynamic Multi-User Authentication:
 * No static/global API key required.
 * Supports:
 * - Direct API key input (civify_set_api_key)
 * - User registration (civify_register)
 * - User login (civify_login) with 2FA verification (civify_verify_2fa)
 * - Auto-provisioning API key via backend token exchange (identical to Chrome extension flow)
 * - Complete end-to-end flow: Scraping -> Parsing -> ATS Scoring -> Tailoring -> PII Masking -> PDF Export -> Pay-Per-CV -> Tracking
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
  isInitializeRequest,
} from "@modelcontextprotocol/sdk/types.js";
import { randomUUID } from "node:crypto";
import axios, { AxiosInstance } from "axios";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import FormData from "form-data";
import express from "express";
import cors from "cors";
import dns from "node:dns";
import { lookup as osLookup } from "node:dns";
import http from "node:http";
import https from "node:https";

// ─── DNS Hardening for Docker/Alpine ──────────────────────────────
// Alpine's musl libc has unreliable DNS (EAI_AGAIN on civify.cv).
// 1. Prefer IPv4 to avoid AAAA timeouts
// 2. Set explicit DNS servers via env
// 3. Force Axios to use Node.js resolver (dns.resolve4) which respects setServers(),
//    instead of OS getaddrinfo which doesn't.
try {
  dns.setDefaultResultOrder("ipv4first");
} catch (_) {}

if (process.env.DNS_SERVERS) {
  try {
    dns.setServers(process.env.DNS_SERVERS.split(",").map((s) => s.trim()));
  } catch (e) {
    console.error("[DNS] Failed to set custom DNS servers:", e);
  }
}

// Custom lookup: try Node.js dns.resolve4 first (uses setServers), fall back to OS getaddrinfo
const customLookup = (
  hostname: string,
  optionsOrCallback: any,
  maybeCallback?: any
) => {
  // Handle both (hostname, callback) and (hostname, options, callback) signatures
  const callback = typeof optionsOrCallback === "function" ? optionsOrCallback : maybeCallback;
  if (typeof callback !== "function") return;

  dns.resolve4(hostname, (err, addresses) => {
    if (!err && addresses && addresses.length > 0) {
      console.log(`[DNS] Resolved ${hostname} → ${addresses[0]} via dns.resolve4`);
      callback(null, addresses[0], 4);
    } else {
      // Fallback to OS resolver (getaddrinfo)
      osLookup(hostname, { family: 4 }, (err2: any, address: string, family: number) => {
        if (!err2 && address) {
          console.log(`[DNS] Resolved ${hostname} → ${address} via OS fallback`);
          callback(null, address, family || 4);
        } else {
          // Both failed — propagate error clearly
          const finalErr = err2 || err || Object.assign(new Error(`DNS resolution failed for ${hostname}`), { code: "EAI_AGAIN" });
          console.error(`[DNS] BOTH resolvers failed for ${hostname}:`, finalErr.message);
          callback(finalErr, "", 4);
        }
      });
    }
  });
};

// Apply custom DNS lookup to all HTTP/HTTPS requests (Axios uses these agents)
const httpAgent = new http.Agent({ lookup: customLookup as any });
const httpsAgent = new https.Agent({ lookup: customLookup as any });

// Set as Axios defaults so bare axios.post/get (auth endpoints) also use custom DNS
axios.defaults.httpAgent = httpAgent;
axios.defaults.httpsAgent = httpsAgent;

// Startup DNS diagnostic — verify resolution before serving
dns.resolve4("civify.cv", (err, addresses) => {
  if (err) {
    console.error(`[DNS] ⚠️  Startup probe FAILED for civify.cv: ${err.message} (code: ${err.code})`);
    console.error(`[DNS] Configured servers: ${dns.getServers().join(", ")}`);
  } else {
    console.log(`[DNS] ✅ Startup probe OK: civify.cv → ${addresses.join(", ")} (servers: ${dns.getServers().join(", ")})`);
  }
});

const CIVIFY_BASE_URL = process.env.CIVIFY_API_URL || "https://civify.cv/apis";
const CIVIFY_FRONTEND_URL = process.env.CIVIFY_FRONTEND_URL || "https://civify.cv";
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : null;
const IS_SSE = process.argv.includes("--sse") || process.env.TRANSPORT === "sse" || PORT !== null;
const SERVER_VERSION = "1.3.0";

/**
 * Session Authentication State
 * Maintained per connection (CLI stdio or per-session SSE)
 */
export interface SessionAuthState {
  apiKey?: string;
  accessToken?: string;
  refreshToken?: string;
  pending2faUsername?: string;
  userProfile?: any;
}

const getApiClient = (sessionAuth: SessionAuthState, overrideKey?: string): AxiosInstance => {
  const effectiveKey = overrideKey || sessionAuth.apiKey;
  const headers: Record<string, string> = {
    "User-Agent": `Civify-MCP-Server/${SERVER_VERSION}`,
    Accept: "application/json",
  };
  if (effectiveKey) {
    headers["X-API-KEY"] = effectiveKey;
  }
  if (sessionAuth.accessToken) {
    headers["Authorization"] = `Bearer ${sessionAuth.accessToken}`;
  }
  return axios.create({
    baseURL: CIVIFY_BASE_URL,
    timeout: 90000,
    headers,
    httpAgent,
    httpsAgent,
  });
};

const ensureAuthenticated = (sessionAuth: SessionAuthState, overrideKey?: string): string => {
  const key = overrideKey || sessionAuth.apiKey;
  if (!key) {
    throw new Error(
      "UNAUTHENTICATED: No active Civify credentials found for this session.\n" +
      "To authenticate, please perform one of the following:\n" +
      "1. Sign in with your Civify account using the 'civify_login' tool (email & password).\n" +
      "2. Provide your existing API key using the 'civify_set_api_key' tool (starts with 'cv-fy-').\n" +
      "3. If you do not have an account yet, create one using the 'civify_register' tool."
    );
  }
  return key;
};

const renderProgressBar = (score: number): string => {
  const totalBlocks = 10;
  const filled = Math.round((Math.max(0, Math.min(100, score)) / 100) * totalBlocks);
  return "█".repeat(filled) + "░".repeat(totalBlocks - filled);
};

const getScoreTier = (score: number): string => {
  if (score >= 80) return "🟢 Excellent Match";
  if (score >= 65) return "🟡 Good Potential";
  return "🔴 Needs Optimization";
};

const formatAtsScoreMarkdown = (raw: any): string => {
  const data = raw?.data || raw;
  const overall = Number(data?.overall || 0);
  const keywordMatch = Number(data?.keywordMatch || 0);
  const skillsMatch = Number(data?.skillsMatch || 0);
  const missingKeywords: string[] = Array.isArray(data?.missingKeywords) ? data.missingKeywords : [];
  const suggestions: string[] = Array.isArray(data?.suggestions) ? data.suggestions : [];

  let md = `## 🎯 ATS Compatibility Score: ${overall}/100 [${renderProgressBar(overall)}] ${getScoreTier(overall)}\n\n`;
  md += `| Evaluation Metric | Score | Assessment |\n`;
  md += `| :--- | :---: | :--- |\n`;
  md += `| **Overall ATS Compatibility** | **${overall}/100** | ${getScoreTier(overall)} |\n`;
  md += `| **Keyword Match Rate** | ${keywordMatch}/100 | ${keywordMatch >= 75 ? "🟢 High Keyword Density" : "🟡 Gaps Detected"} |\n`;
  md += `| **Skills Alignment** | ${skillsMatch}/100 | ${skillsMatch >= 75 ? "🟢 Strong Fit" : "🟡 Gaps Detected"} |\n\n`;

  if (missingKeywords.length > 0) {
    md += `### ⚠️ Missing Keywords from Target Job\n`;
    md += missingKeywords.map((k) => `\`${k}\``).join(" • ") + `\n\n`;
  }

  if (suggestions.length > 0) {
    md += `### 💡 Optimization Suggestions\n`;
    suggestions.forEach((s, idx) => {
      md += `${idx + 1}. ${s}\n`;
    });
    md += `\n`;
  }

  md += `### 🚀 Recommended Next Actions\n`;
  md += `- **Tailor CV**: Run \`civify_tailor_cv\` with target job description to automatically fix keyword gaps.\n`;
  md += `- **Export PDF**: Run \`civify_generate_pdf\` to export an ATS-compliant PDF.\n`;

  return md;
};

const formatTailorCvMarkdown = (raw: any, jobTitle?: string, companyName?: string): string => {
  const data = raw?.data || raw;
  const ats = data?.atsScore;
  const origAts = data?.originalAtsScore;
  const overall = ats?.overall != null ? Number(ats.overall) : null;
  const origOverall = origAts?.overall != null ? Number(origAts.overall) : null;
  const changes: string[] = Array.isArray(data?.changes) ? data.changes : [];
  const warnings: string[] = Array.isArray(data?.validationWarnings) ? data.validationWarnings : [];
  const missingKeywords: string[] = Array.isArray(ats?.missingKeywords) ? ats.missingKeywords : [];

  let headerTitle = "## 🚀 Resume Tailoring Report";
  if (jobTitle || companyName) {
    headerTitle += ` for ${[jobTitle, companyName].filter(Boolean).join(" @ ")}`;
  }

  let md = `${headerTitle}\n\n`;

  if (overall != null) {
    let scoreLine = `**Tailored ATS Match:** ${overall}/100 [${renderProgressBar(overall)}] ${getScoreTier(overall)}`;
    if (origOverall != null) {
      const diff = overall - origOverall;
      scoreLine += ` (improved from ${origOverall}/100 ${diff >= 0 ? `⬆️ +${diff}` : `⬇️ ${diff}`})`;
    }
    md += `${scoreLine}\n\n`;
  }

  if (changes.length > 0) {
    md += `### 📝 Key Improvements Applied (${changes.length})\n`;
    changes.forEach((c, idx) => {
      md += `${idx + 1}. ${c}\n`;
    });
    md += `\n`;
  }

  if (missingKeywords.length > 0) {
    md += `### ⚠️ Remaining Keyword Gaps\n`;
    md += missingKeywords.map((k) => `\`${k}\``).join(" • ") + `\n\n`;
  }

  if (warnings.length > 0) {
    md += `### ⚠️ Verification Warnings\n`;
    warnings.forEach((w) => {
      md += `- ${w}\n`;
    });
    md += `\n`;
  }

  if (data?.coverLetter) {
    md += `### ✉️ Tailored Cover Letter Generated\n`;
    md += `*(Cover letter text is available in the structured response below)*\n\n`;
  }

  md += `### 🎯 Next Steps\n`;
  md += `1. **Render & Export**: Use \`civify_generate_pdf\` with the tailored resume data to export high-res PDF.\n`;
  if (companyName || jobTitle) {
    md += `2. **Track Application**: Use \`civify_track_application\` with company="${companyName || ""}", role="${jobTitle || ""}", status="APPLIED".\n`;
  }

  return md;
};

const TOOLS: Tool[] = [
  // ─── Authentication & Profile ──────────────────────────────────
  {
    name: "civify_set_api_key",
    title: "Set Civify API Key",
    description: "Set or switch the active Civify API key for this agent session. Validates the key with the server immediately.",
    inputSchema: {
      type: "object",
      properties: {
        api_key: {
          type: "string",
          description: "Civify API key (starts with 'cv-fy-').",
        },
      },
      required: ["api_key"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Authentication status (AUTHENTICATED)" },
        message: { type: "string", description: "Confirmation message" },
        user: {
          type: "object",
          description: "Authenticated user profile details",
          properties: {
            id: { type: "string", description: "User ID" },
            email: { type: "string", description: "User email address" },
            username: { type: "string", description: "User account username" },
            subscriptionTier: { type: "string", description: "Subscription tier level" },
          },
        },
      },
      required: ["status", "message"],
    },
    annotations: {
      title: "Set Civify API Key",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "civify_login",
    title: "Sign In to Civify",
    description: "Sign in to Civify with email/username and password. Automatically exchanges JWT tokens for a personal API key and activates it for the session (same flow as Civify Chrome Extension).",
    inputSchema: {
      type: "object",
      properties: {
        identifier: {
          type: "string",
          description: "User's email address or username.",
        },
        password: {
          type: "string",
          description: "Account password.",
        },
      },
      required: ["identifier", "password"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Authentication status (AUTHENTICATED or 2FA_REQUIRED)" },
        message: { type: "string", description: "Status message" },
        apiKeyPreview: { type: "string", description: "Masked preview of the auto-generated API key" },
        username: { type: "string", description: "Username for pending 2FA verification" },
        action_required: { type: "string", description: "Next action required if 2FA is needed" },
        user: {
          type: "object",
          description: "User profile information",
          properties: {
            id: { type: "string", description: "User ID" },
            email: { type: "string", description: "User email" },
            username: { type: "string", description: "User username" },
          },
        },
      },
      required: ["status", "message"],
    },
    annotations: {
      title: "Sign In to Civify",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "civify_verify_2fa",
    title: "Verify 2FA Code",
    description: "Complete two-factor authentication (2FA) by submitting the OTP code sent to the user's email after login.",
    inputSchema: {
      type: "object",
      properties: {
        code: {
          type: "string",
          description: "6-digit OTP code received via email.",
        },
        username: {
          type: "string",
          description: "Username or email (optional if login was called in this session).",
        },
      },
      required: ["code"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Authentication status (AUTHENTICATED)" },
        message: { type: "string", description: "Status confirmation message" },
        apiKeyPreview: { type: "string", description: "Masked preview of the provisioned API key" },
        user: {
          type: "object",
          description: "Authenticated user profile",
          properties: {
            id: { type: "string", description: "User ID" },
            email: { type: "string", description: "User email" },
            username: { type: "string", description: "User username" },
          },
        },
      },
      required: ["status", "message"],
    },
    annotations: {
      title: "Verify 2FA Code",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "civify_register",
    title: "Register Civify Account",
    description: "Register a brand-new Civify account. If auto-verification is active, immediately provisions an API key for the session.",
    inputSchema: {
      type: "object",
      properties: {
        email: {
          type: "string",
          description: "User's email address.",
        },
        password: {
          type: "string",
          description: "Account password (min 8 characters).",
        },
        username: {
          type: "string",
          description: "Unique username for the account.",
        },
        referral_code: {
          type: "string",
          description: "Optional referral code.",
        },
      },
      required: ["email", "password", "username"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Registration status (AUTHENTICATED or REGISTERED_VERIFICATION_REQUIRED)" },
        message: { type: "string", description: "Status message" },
        apiKeyPreview: { type: "string", description: "Masked preview of API key if auto-verified" },
        action_required: { type: "string", description: "Next step required if email verification link was sent" },
      },
      required: ["status", "message"],
    },
    annotations: {
      title: "Register Civify Account",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "civify_logout",
    title: "Log Out of Civify",
    description: "Log out and clear active authentication credentials from this session.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Status code (LOGGED_OUT)" },
        message: { type: "string", description: "Confirmation message" },
      },
      required: ["status", "message"],
    },
    annotations: {
      title: "Log Out of Civify",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "civify_get_account",
    title: "Get Account Profile & Quotas",
    description: "Get current authenticated user account profile, subscription tier, remaining AI token balance, and CV credits.",
    inputSchema: {
      type: "object",
      properties: {
        api_key: {
          type: "string",
          description: "Optional API key override for this call.",
        },
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "User ID" },
        username: { type: "string", description: "Username" },
        email: { type: "string", description: "Account email address" },
        subscriptionTier: { type: "string", description: "Subscription plan (FREE, PRO, PREMIUM, ENTERPRISE)" },
        aiTokensBalance: { type: "number", description: "Remaining AI token balance" },
        creditsBalance: { type: "number", description: "Remaining CV credits balance" },
      },
    },
    annotations: {
      title: "Get Account Profile & Quotas",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },

  // ─── Monetization & Pay-Per-CV ─────────────────────────────────
  {
    name: "civify_get_pay_per_cv_pricing",
    title: "Get Pay-Per-CV Pricing",
    description: "Get public localized Pay-Per-CV pricing (USD base price, converted EGP regional pricing, exchange rates, and entitlement details). Public, no auth required.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    outputSchema: {
      type: "object",
      properties: {
        currency: { type: "string", description: "Default base currency (USD)" },
        regionalCurrency: { type: "string", description: "Localized currency detected from GeoIP (e.g. EGP)" },
        exchangeRate: { type: "number", description: "Current currency exchange rate applied" },
        products: {
          type: "array",
          description: "Available Pay-Per-CV packages",
          items: {
            type: "object",
            properties: {
              id: { type: "string", description: "Product ID (PAY_PER_CV_SINGLE or PAY_PER_CV_PACK3)" },
              name: { type: "string", description: "Product display name" },
              priceUsd: { type: "number", description: "Base price in USD" },
              priceRegional: { type: "number", description: "Converted regional price in localized currency" },
              features: {
                type: "array",
                items: { type: "string" },
                description: "List of included package features and benefits",
              },
            },
            required: ["id", "priceUsd"],
          },
        },
      },
      required: ["currency", "products"],
    },
    annotations: {
      title: "Get Pay-Per-CV Pricing",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "civify_purchase_cv_pass",
    title: "Initiate Pay-Per-CV Purchase",
    description: "Initiate checkout for a Pay-Per-CV unlock pass (single CV or 3-pack). Returns payment URL, invoice ID, and amount.",
    inputSchema: {
      type: "object",
      properties: {
        product_id: {
          type: "string",
          enum: ["PAY_PER_CV_SINGLE", "PAY_PER_CV_PACK3"],
          default: "PAY_PER_CV_SINGLE",
          description: "Product to purchase: 'PAY_PER_CV_SINGLE' ($2.99 / ~150 EGP) or 'PAY_PER_CV_PACK3' ($6.99 / ~350 EGP).",
        },
        resume_id: {
          type: "string",
          description: "Optional resume ID to immediately bind the single-pass entitlement to.",
        },
        gateway: {
          type: "string",
          description: "Payment gateway ('paymob', 'fawaterak', 'dodo'). Auto-resolved by region if omitted.",
        },
        method: {
          type: "string",
          enum: ["CARD", "WALLET"],
          default: "CARD",
          description: "Payment method: 'CARD' or 'WALLET'.",
        },
        phone_number: {
          type: "string",
          description: "Mobile wallet number (required for Egyptian mobile wallets like Vodafone Cash).",
        },
        promo_code: {
          type: "string",
          description: "Optional discount promo code.",
        },
        api_key: {
          type: "string",
          description: "Optional API key override.",
        },
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        invoiceId: { type: "string", description: "Unique transaction invoice reference" },
        paymentUrl: { type: "string", description: "Direct checkout or payment redirect URL" },
        amount: { type: "number", description: "Total charge amount" },
        currency: { type: "string", description: "Charge currency code (USD or EGP)" },
        gateway: { type: "string", description: "Assigned payment gateway (paymob, fawaterak, dodo)" },
        status: { type: "string", description: "Initial order status (PENDING)" },
      },
      required: ["invoiceId", "paymentUrl"],
    },
    annotations: {
      title: "Initiate Pay-Per-CV Purchase",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
  },
  {
    name: "civify_check_cv_entitlement",
    title: "Check Resume Pass Entitlement",
    description: "Check if a specific resume currently has an active 30-day unwatermarked pass and unlimited edits.",
    inputSchema: {
      type: "object",
      properties: {
        resume_id: {
          type: "string",
          description: "Resume UUID or ID.",
        },
        api_key: {
          type: "string",
          description: "Optional API key override.",
        },
      },
      required: ["resume_id"],
    },
    outputSchema: {
      type: "object",
      properties: {
        resumeId: { type: "string", description: "ID of the checked resume" },
        hasActivePass: { type: "boolean", description: "Whether the resume has an active 30-day unwatermarked pass" },
        expiresAt: { type: "string", description: "ISO timestamp when the active pass expires" },
        canDownloadUnwatermarked: { type: "boolean", description: "Permission to export PDF without watermark" },
        unlimitedEditsRemainingDays: { type: "number", description: "Remaining days of unlimited editing" },
      },
      required: ["resumeId", "hasActivePass"],
    },
    annotations: {
      title: "Check Resume Pass Entitlement",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },

  // ─── Job Intelligence & Scraping ──────────────────────────────
  {
    name: "civify_scrape_job",
    title: "Scrape Job Description URL",
    description: "Scrape and extract structured job description, company name, requirements, and responsibilities from a job URL (LinkedIn, Greenhouse, Lever, Ashby, Wuzzuf, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "The URL of the job posting.",
        },
        api_key: {
          type: "string",
          description: "Optional API key override.",
        },
      },
      required: ["url"],
    },
    outputSchema: {
      type: "object",
      properties: {
        content: { type: "string", description: "Raw scraped job description text content" },
        title: { type: "string", description: "Extracted job title" },
        company: { type: "string", description: "Hiring organization or employer name" },
        location: { type: "string", description: "Job location or Remote status" },
        description: { type: "string", description: "Cleaned job description text" },
        requirements: {
          type: "array",
          items: { type: "string" },
          description: "Extracted job requirements and qualifications",
        },
        responsibilities: {
          type: "array",
          items: { type: "string" },
          description: "Extracted day-to-day duties and responsibilities",
        },
      },
    },
    annotations: {
      title: "Scrape Job Description URL",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
  },

  // ─── Resume AI Processing ──────────────────────────────────────
  {
    name: "civify_parse_cv",
    title: "Parse Resume Document",
    description: "Parse a resume document (PDF, DOCX, image) into structured JSON schema containing contact details, work experience, education, skills, and projects.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Local file path to the resume document (PDF, DOCX, image).",
        },
        file_base64: {
          type: "string",
          description: "Base64 encoded content of the resume document (for remote/browser agents).",
        },
        filename: {
          type: "string",
          description: "Filename when providing base64 (e.g., 'resume.pdf').",
          default: "resume.pdf",
        },
        language: {
          type: "string",
          description: "Language code (e.g. 'en', 'ar', 'auto'). Default is 'auto'.",
          default: "auto",
        },
        api_key: {
          type: "string",
          description: "Optional API key override.",
        },
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        success: { type: "boolean", description: "Whether the document was successfully parsed" },
        message: { type: "string", description: "Diagnostic or status message" },
        resumeData: {
          type: "object",
          description: "Parsed resume sections including contact, experience, education, skills, and projects",
        },
        contact: {
          type: "object",
          description: "Candidate contact information (name, email, phone, location, links)",
        },
        summary: { type: "string", description: "Professional summary statement" },
        experience: {
          type: "array",
          description: "Chronological employment history",
          items: { type: "object" },
        },
        education: {
          type: "array",
          description: "Academic degrees and certifications",
          items: { type: "object" },
        },
        skills: {
          type: "array",
          description: "Technical and domain skills extracted",
          items: { type: "string" },
        },
        projects: {
          type: "array",
          description: "Key projects and achievements",
          items: { type: "object" },
        },
        detectedLanguage: { type: "string", description: "Primary detected language code (e.g., 'en', 'ar')" },
      },
    },
    annotations: {
      title: "Parse Resume Document",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "civify_tailor_cv",
    title: "Tailor Resume to Job Description",
    description: "Tailor a candidate's resume against a target job description using AI. Generates optimized bullet points, highlights matching skills, provides ATS keyword audit, and creates an optional cover letter.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to resume document file to tailor.",
        },
        file_base64: {
          type: "string",
          description: "Base64 encoded resume file content.",
        },
        filename: {
          type: "string",
          description: "Filename when providing base64 content.",
          default: "resume.pdf",
        },
        job_description: {
          type: "string",
          description: "The full text of the job description to tailor against.",
        },
        job_title: {
          type: "string",
          description: "Target job title.",
        },
        company_name: {
          type: "string",
          description: "Target company name.",
        },
        language: {
          type: "string",
          description: "Language code (e.g., 'en', 'ar').",
        },
        generate_cover_letter: {
          type: "boolean",
          description: "Whether to generate a matching tailored cover letter.",
          default: false,
        },
        include_interview_questions: {
          type: "boolean",
          description: "Whether to generate matching interview prep questions.",
          default: false,
        },
        include_roadmap: {
          type: "boolean",
          description: "Whether to generate a preparation roadmap.",
          default: false,
        },
        api_key: {
          type: "string",
          description: "Optional API key override.",
        },
      },
      required: ["job_description"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Execution status" },
        tailoredCv: { type: "object", description: "Optimized resume document structure" },
        tailoredResume: { type: "object", description: "Optimized resume document structure" },
        atsScore: {
          type: "object",
          description: "Audit score for tailored version",
          properties: {
            overall: { type: "number", description: "Overall score 0-100" },
            keywordMatch: { type: "number", description: "Keyword match score 0-100" },
            skillsMatch: { type: "number", description: "Skills match score 0-100" },
            missingKeywords: { type: "array", items: { type: "string" }, description: "Keywords still missing" },
          },
        },
        originalAtsScore: {
          type: "object",
          description: "Original ATS score before tailoring for comparison",
        },
        changes: {
          type: "array",
          items: { type: "string" },
          description: "Summary list of bullet points and sections tailored",
        },
        validationWarnings: {
          type: "array",
          items: { type: "string" },
          description: "Validation warnings or alignment notes",
        },
        coverLetter: { type: "string", description: "Matching personalized cover letter text if requested" },
        interviewPrep: { type: "object", description: "Targeted interview preparation questions and talking points" },
        roadmap: { type: "object", description: "Targeted skill acquisition roadmap" },
      },
    },
    annotations: {
      title: "Tailor Resume to Job Description",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "civify_score_ats",
    title: "Score Resume ATS Compatibility",
    description: "Calculate ATS compatibility score and structural audit for a resume document (file path) or structured resume JSON without needing a job description.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to resume document to score (auto-parsed first).",
        },
        resume_data: {
          type: "object",
          description: "Structured resume JSON data.",
        },
        api_key: {
          type: "string",
          description: "Optional API key override.",
        },
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        success: { type: "boolean", description: "Operation success status" },
        message: { type: "string", description: "Status message" },
        data: {
          type: "object",
          description: "ATS score details containing overall, keywordMatch, skillsMatch, missingKeywords, and suggestions",
        },
        overall: { type: "number", description: "Overall ATS match score (0-100)" },
        keywordMatch: { type: "number", description: "Keyword density and match score (0-100)" },
        skillsMatch: { type: "number", description: "Skills section alignment score (0-100)" },
        missingKeywords: {
          type: "array",
          items: { type: "string" },
          description: "Important keywords missing from the resume",
        },
        suggestions: {
          type: "array",
          items: { type: "string" },
          description: "Actionable recommendations to improve ATS compatibility",
        },
      },
    },
    annotations: {
      title: "Score Resume ATS Compatibility",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "civify_mask_pii",
    title: "Mask Personally Identifiable Information",
    description: "Sanitize and redact sensitive PII (email, phone, physical address) from a CV document, exporting an anonymized PDF.",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to resume file to redact.",
        },
        file_base64: {
          type: "string",
          description: "Base64 encoded resume file.",
        },
        output_path: {
          type: "string",
          description: "Optional destination path to save the masked PDF.",
        },
        api_key: {
          type: "string",
          description: "Optional API key override.",
        },
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Redaction status (SUCCESS)" },
        message: { type: "string", description: "Details on the exported sanitized document" },
        path: { type: "string", description: "Filesystem path to saved masked PDF" },
        pdf_base64: { type: "string", description: "Base64 encoded masked PDF if saved to memory" },
      },
      required: ["status", "message"],
    },
    annotations: {
      title: "Mask Personally Identifiable Information",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
  {
    name: "civify_generate_pdf",
    title: "Render Resume PDF",
    description: "Render and generate a high-fidelity PDF from structured resume data using Civify's template engine.",
    inputSchema: {
      type: "object",
      properties: {
        resume_data: {
          type: "object",
          description: "Complete structured resume JSON.",
        },
        template: {
          type: "string",
          description: "Template design: 'modern', 'classic', 'minimal', 'executive'. Default is 'modern'.",
          default: "modern",
        },
        color: {
          type: "string",
          description: "Primary accent color in hex (e.g. '#2563eb' or '#000000').",
          default: "#000000",
        },
        filename: {
          type: "string",
          description: "Filename for the exported PDF.",
          default: "resume",
        },
        output_path: {
          type: "string",
          description: "Local file path to save the resulting PDF.",
        },
      },
      required: ["resume_data"],
    },
    outputSchema: {
      type: "object",
      properties: {
        status: { type: "string", description: "Export status (SUCCESS)" },
        message: { type: "string", description: "Confirmation message" },
        path: { type: "string", description: "Filesystem path to the exported PDF document" },
        pdf_base64: { type: "string", description: "Base64 encoded PDF document" },
      },
      required: ["status", "message"],
    },
    annotations: {
      title: "Render Resume PDF",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },

  // ─── Application Tracking (Kanban) ────────────────────────────
  {
    name: "civify_track_application",
    title: "Track Job Application",
    description: "Record a job application in the candidate's Civify Kanban tracker board.",
    inputSchema: {
      type: "object",
      properties: {
        company_name: { type: "string", description: "Name of the target company." },
        job_title: { type: "string", description: "Target role / job title." },
        job_url: { type: "string", description: "URL of the job posting." },
        status: {
          type: "string",
          enum: ["EVALUATED", "APPLIED", "INTERVIEW", "OFFER", "REJECTED"],
          default: "APPLIED",
          description: "Application lifecycle status.",
        },
        notes: { type: "string", description: "Notes, interview dates, or recruiter contacts." },
        api_key: { type: "string", description: "Optional API key override." },
      },
      required: ["company_name", "job_title"],
    },
    outputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Unique identifier for the tracked application" },
        companyName: { type: "string", description: "Company name" },
        jobTitle: { type: "string", description: "Job title" },
        status: { type: "string", description: "Kanban status (EVALUATED, APPLIED, INTERVIEW, OFFER, REJECTED)" },
        notes: { type: "string", description: "Candidate notes and timeline details" },
        createdAt: { type: "string", description: "Creation timestamp" },
      },
      required: ["id", "companyName", "jobTitle", "status"],
    },
    annotations: {
      title: "Track Job Application",
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
  },
  {
    name: "civify_list_applications",
    title: "List Tracked Job Applications",
    description: "List all tracked job applications from the candidate's Civify Kanban board.",
    inputSchema: {
      type: "object",
      properties: {
        api_key: { type: "string", description: "Optional API key override." },
      },
    },
    outputSchema: {
      type: "object",
      properties: {
        applications: {
          type: "array",
          description: "List of tracked applications",
          items: {
            type: "object",
            properties: {
              id: { type: "string", description: "Application ID" },
              companyName: { type: "string", description: "Target company" },
              jobTitle: { type: "string", description: "Job title" },
              jobUrl: { type: "string", description: "Job posting link" },
              status: { type: "string", description: "Current status" },
              notes: { type: "string", description: "Application notes" },
            },
            required: ["id", "companyName", "jobTitle", "status"],
          },
        },
        total: { type: "number", description: "Total count of tracked applications" },
      },
    },
    annotations: {
      title: "List Tracked Job Applications",
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  },
];

export const createMcpServer = (sessionAuth: SessionAuthState) => {
  const server = new Server(
    {
      name: "civify-mcp-server",
      version: SERVER_VERSION,
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const argApiKey = args?.api_key ? String(args.api_key).trim() : undefined;

    try {
      switch (name) {
        // ─── Set API Key ─────────────────────────────────────────
        case "civify_set_api_key": {
          const rawKey = String(args?.api_key || "").trim();
          if (!rawKey) {
            throw new Error("api_key parameter is required.");
          }

          const profileRes = await axios.get(`${CIVIFY_BASE_URL}/v1/external/cvs/user/profile`, {
            headers: { "X-API-KEY": rawKey, Accept: "application/json" },
          });

          sessionAuth.apiKey = rawKey;
          sessionAuth.userProfile = profileRes.data;

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "AUTHENTICATED",
                    message: "Civify API key validated and activated for this session.",
                    user: sessionAuth.userProfile,
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        // ─── Login (Email/Password + Auto-Provision Key) ──────────
        case "civify_login": {
          const identifier = String(args?.identifier || "").trim();
          const password = String(args?.password || "").trim();

          if (!identifier || !password) {
            throw new Error("Both identifier (email or username) and password are required.");
          }

          const isEmail = identifier.includes("@");
          const payload = isEmail ? { email: identifier, password } : { username: identifier, password };

          const loginRes = await axios.post(`${CIVIFY_BASE_URL}/auth/login`, payload, {
            headers: { "Content-Type": "application/json", Accept: "application/json" },
          });

          const loginData = loginRes.data;

          if (loginData.requires2FA) {
            sessionAuth.pending2faUsername = identifier;
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      status: "2FA_REQUIRED",
                      message: loginData.message || "2FA OTP sent to your email.",
                      username: identifier,
                      action_required: "Call 'civify_verify_2fa' with the OTP code sent to your email.",
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }

          const accessToken = loginData.accessToken;
          if (!accessToken) {
            throw new Error(`Login failed: ${loginData.message || "No access token returned."}`);
          }

          sessionAuth.accessToken = accessToken;
          sessionAuth.refreshToken = loginData.refreshToken;

          // Auto-generate API key using the JWT access token (Chrome extension parity)
          const keyRes = await axios.post(
            `${CIVIFY_BASE_URL}/api-keys/auto-generate`,
            {},
            {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                Accept: "application/json",
              },
            }
          );

          const rawKey = keyRes.data?.key;
          if (!rawKey) {
            throw new Error("Failed to auto-generate Civify API key for user session.");
          }

          sessionAuth.apiKey = rawKey;

          // Cache user profile
          try {
            const profileRes = await axios.get(`${CIVIFY_BASE_URL}/v1/external/cvs/user/profile`, {
              headers: { "X-API-KEY": rawKey, Accept: "application/json" },
            });
            sessionAuth.userProfile = profileRes.data;
          } catch (_) {}

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "AUTHENTICATED",
                    message: "Login successful! API key auto-generated and active for this session.",
                    apiKeyPreview: rawKey.substring(0, 8) + "..." + rawKey.substring(rawKey.length - 4),
                    user: sessionAuth.userProfile || { email: identifier },
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        // ─── Verify 2FA ──────────────────────────────────────────
        case "civify_verify_2fa": {
          const code = String(args?.code || "").trim();
          const username = String(args?.username || sessionAuth.pending2faUsername || "").trim();

          if (!code) throw new Error("Verification code is required.");
          if (!username) {
            throw new Error("Username or email is required. Please call civify_login first or provide the username parameter.");
          }

          const params = new URLSearchParams();
          params.append("username", username);
          params.append("code", code);

          const verifyRes = await axios.post(`${CIVIFY_BASE_URL}/auth/verify-otp`, params.toString(), {
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              Accept: "application/json",
            },
          });

          const verifyData = verifyRes.data;
          const accessToken = verifyData.accessToken;
          if (!accessToken) {
            throw new Error(`2FA verification failed: ${verifyData.message || "Invalid OTP code."}`);
          }

          sessionAuth.accessToken = accessToken;
          sessionAuth.refreshToken = verifyData.refreshToken;
          sessionAuth.pending2faUsername = undefined;

          // Auto-generate key
          const keyRes = await axios.post(
            `${CIVIFY_BASE_URL}/api-keys/auto-generate`,
            {},
            {
              headers: {
                Authorization: `Bearer ${accessToken}`,
                Accept: "application/json",
              },
            }
          );

          const rawKey = keyRes.data?.key;
          if (!rawKey) {
            throw new Error("Failed to auto-generate Civify API key after 2FA verification.");
          }
          sessionAuth.apiKey = rawKey;

          try {
            const profileRes = await axios.get(`${CIVIFY_BASE_URL}/v1/external/cvs/user/profile`, {
              headers: { "X-API-KEY": rawKey, Accept: "application/json" },
            });
            sessionAuth.userProfile = profileRes.data;
          } catch (_) {}

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "AUTHENTICATED",
                    message: "2FA verified! API key provisioned and active for this session.",
                    apiKeyPreview: rawKey ? rawKey.substring(0, 8) + "..." : undefined,
                    user: sessionAuth.userProfile || { username },
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        // ─── Register ────────────────────────────────────────────
        case "civify_register": {
          const email = String(args?.email || "").trim();
          const password = String(args?.password || "").trim();
          const username = String(args?.username || "").trim();
          const referralCode = args?.referral_code ? String(args.referral_code).trim() : undefined;

          if (!email || !password || !username) {
            throw new Error("Email, password, and username are all required.");
          }

          const regRes = await axios.post(
            `${CIVIFY_BASE_URL}/auth/register`,
            { email, password, username, referralCode },
            { headers: { "Content-Type": "application/json", Accept: "application/json" } }
          );

          const regData = regRes.data;

          // Try instant auto-login (if verification is disabled or auto-verified in backend)
          try {
            const autoLoginRes = await axios.post(
              `${CIVIFY_BASE_URL}/auth/login`,
              { email, password },
              { headers: { "Content-Type": "application/json", Accept: "application/json" } }
            );

            if (autoLoginRes.data?.accessToken) {
              const accessToken = autoLoginRes.data.accessToken;
              sessionAuth.accessToken = accessToken;
              const keyRes = await axios.post(
                `${CIVIFY_BASE_URL}/api-keys/auto-generate`,
                {},
                { headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" } }
              );
              if (keyRes.data?.key) {
                const autoKey = String(keyRes.data.key);
                sessionAuth.apiKey = autoKey;
                return {
                  content: [
                    {
                      type: "text",
                      text: JSON.stringify(
                        {
                          status: "AUTHENTICATED",
                          message: "Registration successful and account verified! API key provisioned and active.",
                          apiKeyPreview: autoKey.substring(0, 8) + "...",
                        },
                        null,
                        2
                      ),
                    },
                  ],
                };
              }
            }
          } catch (_) {
            // Auto-login failed, requires email verification
          }

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "REGISTERED_VERIFICATION_REQUIRED",
                    message: regData.message || "Registration successful! A verification link has been sent to your email.",
                    action_required: "Please check your inbox, click the verification link, and then call 'civify_login' to connect.",
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        // ─── Logout ──────────────────────────────────────────────
        case "civify_logout": {
          sessionAuth.apiKey = undefined;
          sessionAuth.accessToken = undefined;
          sessionAuth.refreshToken = undefined;
          sessionAuth.pending2faUsername = undefined;
          sessionAuth.userProfile = undefined;

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    status: "LOGGED_OUT",
                    message: "Active session credentials cleared.",
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        // ─── Get Account Profile ─────────────────────────────────
        case "civify_get_account": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);
          const res = await client.get("/v1/external/cvs/user/profile");
          sessionAuth.userProfile = res.data;
          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        // ─── Get Pay-Per-CV Pricing ──────────────────────────────
        case "civify_get_pay_per_cv_pricing": {
          const res = await axios.get(`${CIVIFY_BASE_URL}/v1/external/pay-per-cv/pricing`, {
            headers: { "User-Agent": `Civify-MCP-Server/${SERVER_VERSION}` },
          });
          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        // ─── Purchase Pay-Per-CV Pass ────────────────────────────
        case "civify_purchase_cv_pass": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);

          const res = await client.post("/v1/external/pay-per-cv/purchase", {
            productId: args?.product_id || "PAY_PER_CV_SINGLE",
            resumeId: args?.resume_id,
            gateway: args?.gateway,
            method: args?.method || "CARD",
            phoneNumber: args?.phone_number,
            promoCode: args?.promo_code,
          });

          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        // ─── Check CV Entitlement ────────────────────────────────
        case "civify_check_cv_entitlement": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const resumeId = String(args?.resume_id || "").trim();
          if (!resumeId) throw new Error("resume_id is required.");

          const client = getApiClient(sessionAuth, apiKey);
          const res = await client.get(`/v1/external/pay-per-cv/status?resumeId=${encodeURIComponent(resumeId)}`);
          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        // ─── Scrape Job ──────────────────────────────────────────
        case "civify_scrape_job": {
          const url = String(args?.url || "").trim();
          if (!url) throw new Error("url is required.");

          const client = getApiClient(sessionAuth, argApiKey);
          const res = await client.post("/v1/external/cvs/scrape-jd", { url });
          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        // ─── Parse CV ────────────────────────────────────────────
        case "civify_parse_cv": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);

          const form = new FormData();
          if (args?.file_path) {
            const filePath = String(args.file_path);
            if (!fs.existsSync(filePath)) {
              throw new Error(`File not found: ${filePath}`);
            }
            form.append("file", fs.createReadStream(filePath));
          } else if (args?.file_base64) {
            const buffer = Buffer.from(String(args.file_base64), "base64");
            form.append("file", buffer, { filename: String(args?.filename || "resume.pdf") });
          } else {
            throw new Error("Either file_path or file_base64 is required.");
          }

          if (args?.language) {
            form.append("language", String(args.language));
          }

          const res = await client.post("/v1/external/cvs/parse", form, {
            headers: form.getHeaders(),
          });
          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        // ─── Tailor CV ───────────────────────────────────────────
        case "civify_tailor_cv": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);

          const form = new FormData();
          if (args?.file_path) {
            const filePath = String(args.file_path);
            if (!fs.existsSync(filePath)) {
              throw new Error(`File not found: ${filePath}`);
            }
            form.append("file", fs.createReadStream(filePath));
          } else if (args?.file_base64) {
            const buffer = Buffer.from(String(args.file_base64), "base64");
            form.append("file", buffer, { filename: String(args?.filename || "resume.pdf") });
          } else {
            throw new Error("Either file_path or file_base64 is required to tailor CV.");
          }

          form.append("jobDescription", String(args?.job_description || ""));
          if (args?.job_title) form.append("jobTitle", String(args.job_title));
          if (args?.company_name) form.append("companyName", String(args.company_name));
          if (args?.language) form.append("language", String(args.language));
          if (args?.generate_cover_letter) form.append("generateCoverLetter", "true");
          if (args?.include_interview_questions) form.append("includeInterviewQuestions", "true");
          if (args?.include_roadmap) form.append("includeRoadmap", "true");

          const res = await client.post("/v1/external/cvs/tailor", form, {
            headers: form.getHeaders(),
          });
          const mdReport = formatTailorCvMarkdown(
            res.data,
            args?.job_title ? String(args.job_title) : undefined,
            args?.company_name ? String(args.company_name) : undefined
          );
          return {
            content: [
              { type: "text", text: mdReport },
              { type: "text", text: JSON.stringify(res.data, null, 2) },
            ],
          };
        }

        // ─── Score ATS ───────────────────────────────────────────
        case "civify_score_ats": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);

          let resumeData = args?.resume_data;
          if (!resumeData && args?.file_path) {
            const filePath = String(args.file_path);
            if (!fs.existsSync(filePath)) {
              throw new Error(`File not found: ${filePath}`);
            }
            const parseForm = new FormData();
            parseForm.append("file", fs.createReadStream(filePath));
            const parseRes = await client.post("/v1/external/cvs/parse", parseForm, {
              headers: parseForm.getHeaders(),
            });
            resumeData = parseRes.data?.data || parseRes.data;
          }

          if (!resumeData) {
            throw new Error("Either resume_data object or file_path document is required to calculate ATS score.");
          }

          const res = await client.post("/v1/external/cvs/score", { resumeData });
          const mdScore = formatAtsScoreMarkdown(res.data);
          return {
            content: [
              { type: "text", text: mdScore },
              { type: "text", text: JSON.stringify(res.data, null, 2) },
            ],
          };
        }

        // ─── Mask PII ────────────────────────────────────────────
        case "civify_mask_pii": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);

          const form = new FormData();
          let defaultOutName = "masked_cv.pdf";
          if (args?.file_path) {
            const filePath = String(args.file_path);
            if (!fs.existsSync(filePath)) {
              throw new Error(`File not found: ${filePath}`);
            }
            form.append("file", fs.createReadStream(filePath));
            defaultOutName = filePath.replace(/\.[^/.]+$/, "_masked.pdf");
          } else if (args?.file_base64) {
            const buffer = Buffer.from(String(args.file_base64), "base64");
            form.append("file", buffer, { filename: String(args?.filename || "resume.pdf") });
          } else {
            throw new Error("Either file_path or file_base64 is required.");
          }

          const res = await client.post("/v1/external/cvs/mask", form, {
            headers: form.getHeaders(),
            responseType: "arraybuffer",
          });

          const outPath = String(args?.output_path || defaultOutName);
          try {
            fs.writeFileSync(outPath, Buffer.from(res.data));
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      status: "SUCCESS",
                      message: `Sanitized masked PDF saved to ${outPath}`,
                      path: outPath,
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          } catch (_) {
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      status: "SUCCESS",
                      message: "Masked PDF generated successfully.",
                      pdf_base64: Buffer.from(res.data).toString("base64"),
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }
        }

        // ─── Generate PDF ────────────────────────────────────────
        case "civify_generate_pdf": {
          const resumeData = args?.resume_data;
          if (!resumeData) {
            throw new Error("resume_data is required.");
          }
          const template = String(args?.template || "modern");
          const color = String(args?.color || "#000000");
          const filename = String(args?.filename || "resume");

          const res = await axios.post(
            `${CIVIFY_FRONTEND_URL}/api/generate-pdf`,
            {
              resumeData,
              template,
              color,
              filename,
            },
            {
              responseType: "arraybuffer",
              timeout: 60000,
            }
          );

          const outPath = String(args?.output_path || `${filename}.pdf`);
          try {
            fs.writeFileSync(outPath, Buffer.from(res.data));
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      status: "SUCCESS",
                      message: `Generated PDF saved to ${outPath}`,
                      path: outPath,
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          } catch (_) {
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(
                    {
                      status: "SUCCESS",
                      message: "PDF generated successfully.",
                      pdf_base64: Buffer.from(res.data).toString("base64"),
                    },
                    null,
                    2
                  ),
                },
              ],
            };
          }
        }

        // ─── Track Application ───────────────────────────────────
        case "civify_track_application": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);

          const res = await client.post("/v1/external/job-applications", {
            companyName: args?.company_name,
            jobTitle: args?.job_title,
            jobUrl: args?.job_url,
            status: args?.status || "APPLIED",
            notes: args?.notes,
          });
          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        // ─── List Applications ───────────────────────────────────
        case "civify_list_applications": {
          const apiKey = ensureAuthenticated(sessionAuth, argApiKey);
          const client = getApiClient(sessionAuth, apiKey);

          const res = await client.get("/v1/external/job-applications");
          return {
            content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
          };
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (error: any) {
      const errorMsg = error?.response?.data
        ? typeof error.response.data === "string"
          ? error.response.data
          : JSON.stringify(error.response.data)
        : error.message;
      return {
        content: [{ type: "text", text: `Civify MCP Error: ${errorMsg}` }],
        isError: true,
      };
    }
  });

  return server;
};

// ─── CLI / Stdio Mode ────────────────────────────────────────────
async function runStdio() {
  const stdioSessionAuth: SessionAuthState = {
    apiKey: process.env.CIVIFY_API_KEY || undefined,
  };
  const server = createMcpServer(stdioSessionAuth);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Civify MCP Server running on stdio transport (dynamic auth enabled).");
}

// ─── Remote Server Mode (SSE + Streamable HTTP) ────────────────────
async function runSse(listenPort: number) {
  const app = express();
  app.use(cors({ origin: "*" }));
  app.use(express.json());

  // Legacy SSE transport sessions
  const sseTransports: Map<string, SSEServerTransport> = new Map();

  // Streamable HTTP transport sessions (new MCP standard)
  const streamableTransports: Map<string, StreamableHTTPServerTransport> = new Map();
  const streamableSessionAuths: Map<string, SessionAuthState> = new Map();
  const streamableLastActivity: Map<string, number> = new Map();

  // Periodic session TTL eviction (cleans up inactive sessions older than 2 hours)
  const SESSION_TTL_MS = 2 * 60 * 60 * 1000;
  const sessionCleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [sid, lastActive] of streamableLastActivity.entries()) {
      if (now - lastActive > SESSION_TTL_MS) {
        console.log(`[Streamable HTTP] Evicting idle session: ${sid}`);
        const transport = streamableTransports.get(sid);
        if (transport) {
          try {
            transport.close();
          } catch (_) {}
        }
        streamableTransports.delete(sid);
        streamableSessionAuths.delete(sid);
        streamableLastActivity.delete(sid);
      }
    }
  }, 15 * 60 * 1000);
  sessionCleanupTimer.unref();

  // Static Server Card for Smithery & MCP Registries (SEP-1649)
  const getServerCard = () => ({
    $schema: "https://modelcontextprotocol.io/schema/server-card.json",
    serverInfo: {
      name: "Civify MCP Server",
      version: SERVER_VERSION,
      description: "Official MCP server for Civify AI Career Platform (Resume Parsing, ATS Scoring, Tailoring, PII Masking, Kanban Applications, and Pay-Per-CV).",
    },
    authentication: {
      required: false,
      description: "Dynamic per-session authentication supported (civify_login, civify_register, or civify_set_api_key).",
    },
    configSchema: {
      type: "object",
      properties: {
        apiKey: {
          type: "string",
          description: "Optional Civify Developer API key (cv-fy-...). If omitted, you can authenticate interactively in chat.",
        },
      },
    },
    tools: TOOLS,
    resources: [],
    prompts: [],
  });

  app.get(["/.well-known/mcp/server-card.json", "/server-card.json"], (req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.json(getServerCard());
  });

  app.get("/health", (req, res) => {
    res.json({
      status: "UP",
      service: "civify-mcp-server",
      version: SERVER_VERSION,
      transports: ["sse", "streamable-http"],
      activeSessions: {
        sse: sseTransports.size,
        streamableHttp: streamableTransports.size,
      },
      timestamp: new Date().toISOString(),
    });
  });

  const handleSse = async (req: express.Request, res: express.Response) => {
    const initialKey =
      (req.headers["x-api-key"] as string) ||
      (req.headers["authorization"]?.replace(/^Bearer\s+/i, "") as string) ||
      (req.query.apiKey as string) ||
      undefined;

    const transport = new SSEServerTransport("/messages", res);
    const sessionId = transport.sessionId;

    const sessionAuth: SessionAuthState = {
      apiKey: initialKey,
    };
    sseTransports.set(sessionId, transport);

    transport.onclose = () => {
      sseTransports.delete(sessionId);
      console.log(`[SSE] Session closed: ${sessionId}`);
    };

    console.log(`[SSE] Session started: ${sessionId} (initial key: ${initialKey ? "provided" : "none"})`);
    const server = createMcpServer(sessionAuth);
    await server.connect(transport);
  };

  app.get("/sse", handleSse);

  // If a client (or Smithery) connects to root `/` expecting SSE, stream SSE; otherwise return JSON discovery info
  app.get("/", (req, res) => {
    if (req.headers.accept?.includes("text/event-stream") || req.query.transport === "sse") {
      return handleSse(req, res);
    }

    res.json({
      service: "Civify Model Context Protocol (MCP) Server",
      version: SERVER_VERSION,
      homepage: "https://civify.cv",
      docs: "https://civify.cv/mcp-docs",
      endpoints: {
        streamableHttp: "/mcp",
        sse: "/sse",
        messages: "/messages",
        health: "/health",
        serverCard: "/.well-known/mcp/server-card.json",
      },
      toolsCount: TOOLS.length,
      auth: "Dynamic per-session authentication supported (register, login, 2FA, or API key).",
    });
  });

  // ─── Legacy SSE POST handler (/messages, /sse, /) ──────────────
  app.post(["/messages", "/sse", "/"], async (req, res) => {
    const sessionId = String(req.query.sessionId || req.body?.sessionId || "");
    const transport = sseTransports.get(sessionId);

    if (!transport) {
      if (!sessionId) {
        res.status(400).json({ error: "Missing sessionId query parameter." });
      } else {
        res.status(404).json({ error: `Session not found: ${sessionId}` });
      }
      return;
    }

    await transport.handlePostMessage(req, res);
  });

  // ─── Streamable HTTP Transport (/mcp) ─────────────────────────────
  // New MCP standard — used by Claude Desktop connectors, modern agents.
  // Each initialize request creates a new per-session Server + Transport.
  app.post("/mcp", async (req, res) => {
    try {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;
      let transport: StreamableHTTPServerTransport | undefined;

      if (sessionId && streamableTransports.has(sessionId)) {
        // ── Reuse existing session ──
        transport = streamableTransports.get(sessionId)!;
        streamableLastActivity.set(sessionId, Date.now());
      } else if (sessionId && !streamableTransports.has(sessionId)) {
        // ── Expired or unknown session ID (RFC compliant 404 for reconnection/retry) ──
        res.status(404).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Session not found or expired. Please send an initialize request without mcp-session-id header.",
          },
          id: null,
        });
        return;
      } else if (!sessionId && isInitializeRequest(req.body)) {
        // ── New initialize request — create session ──
        const initialKey =
          (req.headers["x-api-key"] as string) ||
          (req.headers["authorization"]?.replace(/^Bearer\s+/i, "") as string) ||
          undefined;

        const sessionAuth: SessionAuthState = { apiKey: initialKey };

        transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          onsessioninitialized: (newSessionId) => {
            streamableTransports.set(newSessionId, transport!);
            streamableSessionAuths.set(newSessionId, sessionAuth);
            streamableLastActivity.set(newSessionId, Date.now());
            console.log(`[Streamable HTTP] Session initialized: ${newSessionId} (key: ${initialKey ? "provided" : "none"})`);
          },
        });

        transport.onclose = () => {
          const sid = transport!.sessionId;
          if (sid) {
            streamableTransports.delete(sid);
            streamableSessionAuths.delete(sid);
            streamableLastActivity.delete(sid);
            console.log(`[Streamable HTTP] Session closed: ${sid}`);
          }
        };

        // Create per-session MCP server with auth state
        const server = createMcpServer(sessionAuth);
        await server.connect(transport);

        // Handle the initialize request
        await transport.handleRequest(req, res, req.body);
        return;
      } else {
        // No session ID and not an initialize request
        res.status(400).json({
          jsonrpc: "2.0",
          error: {
            code: -32000,
            message: "Bad Request: No valid session ID provided. Send an initialize request first.",
          },
          id: null,
        });
        return;
      }

      // Handle subsequent requests on existing transport
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      console.error("[Streamable HTTP] Error handling request:", error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    }
  });

  // Streamable HTTP GET — used for SSE stream reconnection (server-initiated notifications)
  app.get("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (sessionId && streamableTransports.has(sessionId)) {
      const transport = streamableTransports.get(sessionId)!;
      streamableLastActivity.set(sessionId, Date.now());
      await transport.handleRequest(req, res);
    } else {
      res.status(405).set("Allow", "POST, DELETE").send("Method Not Allowed");
    }
  });

  // Streamable HTTP DELETE — session termination
  app.delete("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (sessionId && streamableTransports.has(sessionId)) {
      const transport = streamableTransports.get(sessionId)!;
      await transport.handleRequest(req, res);
      streamableTransports.delete(sessionId);
      streamableSessionAuths.delete(sessionId);
      streamableLastActivity.delete(sessionId);
      console.log(`[Streamable HTTP] Session terminated by client: ${sessionId}`);
    } else {
      res.status(404).json({ error: "Session not found" });
    }
  });

  app.listen(listenPort, "0.0.0.0", () => {
    console.log(`🚀 Civify MCP Server running on port ${listenPort}`);
    console.log(`🔗 SSE endpoint:            http://0.0.0.0:${listenPort}/sse`);
    console.log(`🔗 Streamable HTTP endpoint: http://0.0.0.0:${listenPort}/mcp`);
    console.log(`🩺 Healthcheck:              http://0.0.0.0:${listenPort}/health`);
    console.log(`📋 Server Card:              http://0.0.0.0:${listenPort}/.well-known/mcp/server-card.json`);
  });
}

const isMainModule = (): boolean => {
  if (!process.argv[1]) return false;
  try {
    const currentFilePath = fileURLToPath(import.meta.url);
    const invokedFilePath = path.resolve(process.argv[1]);
    return (
      currentFilePath === invokedFilePath ||
      invokedFilePath.endsWith("index.js") ||
      invokedFilePath.endsWith("civify-mcp")
    );
  } catch (_) {
    return false;
  }
};

// ─── Entrypoint ──────────────────────────────────────────────────
if (isMainModule()) {
  if (IS_SSE) {
    const effectivePort = PORT || 8080;
    runSse(effectivePort).catch((err) => {
      console.error("Fatal error starting Civify SSE server:", err);
      process.exit(1);
    });
  } else {
    runStdio().catch((err) => {
      console.error("Fatal error starting Civify Stdio server:", err);
      process.exit(1);
    });
  }
}
