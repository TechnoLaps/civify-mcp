#!/usr/bin/env node
"use strict";
/**
 * Civify Model Context Protocol (MCP) Server
 * Supports dual transport:
 * 1. Stdio (Local desktop/CLI agents: Claude Desktop, Cursor, OpenCode)
 * 2. Remote SSE (Cloud deployments: Dokploy / Docker behind Traefik at mcp.civify.cv)
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const index_js_1 = require("@modelcontextprotocol/sdk/server/index.js");
const stdio_js_1 = require("@modelcontextprotocol/sdk/server/stdio.js");
const sse_js_1 = require("@modelcontextprotocol/sdk/server/sse.js");
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const axios_1 = __importDefault(require("axios"));
const fs = __importStar(require("fs"));
const form_data_1 = __importDefault(require("form-data"));
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const CIVIFY_BASE_URL = process.env.CIVIFY_API_URL || "https://civify.cv/apis";
const CIVIFY_API_KEY = process.env.CIVIFY_API_KEY;
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : null;
const IS_SSE = process.argv.includes("--sse") || process.env.TRANSPORT === "sse" || PORT !== null;
const createApiClient = (apiKey) => {
    return axios_1.default.create({
        baseURL: CIVIFY_BASE_URL,
        timeout: 60000,
        headers: {
            "X-API-KEY": apiKey || CIVIFY_API_KEY || "",
            "User-Agent": "Civify-MCP-Server/1.0.0",
        },
    });
};
const TOOLS = [
    {
        name: "civify_get_account",
        description: "Get user account profile, subscription tier, remaining token balance, and CV credits.",
        inputSchema: {
            type: "object",
            properties: {},
        },
    },
    {
        name: "civify_parse_cv",
        description: "Parse a resume document (PDF, DOCX, image) into structured JSON schema containing contact details, work experience, education, skills, and projects.",
        inputSchema: {
            type: "object",
            properties: {
                file_path: {
                    type: "string",
                    description: "Absolute or relative file path to the resume document (PDF, DOCX, image).",
                },
                language: {
                    type: "string",
                    description: "Language code (e.g. 'en', 'ar', 'auto'). Default is 'auto'.",
                    default: "auto",
                },
            },
            required: ["file_path"],
        },
    },
    {
        name: "civify_tailor_cv",
        description: "Tailor a candidate's resume against a target job description. Optimizes bullet points, highlights matching skills, and generates an optional targeted cover letter.",
        inputSchema: {
            type: "object",
            properties: {
                file_path: {
                    type: "string",
                    description: "Path to resume document file to tailor.",
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
                generate_cover_letter: {
                    type: "boolean",
                    description: "Whether to generate a matching tailored cover letter.",
                    default: false,
                },
            },
            required: ["job_description"],
        },
    },
    {
        name: "civify_score_ats",
        description: "Calculate general ATS compatibility score and structural audit without needing a full JD.",
        inputSchema: {
            type: "object",
            properties: {
                resume_id: {
                    type: "string",
                    description: "UUID of an existing resume in Civify.",
                },
            },
            required: ["resume_id"],
        },
    },
    {
        name: "civify_mask_pii",
        description: "Upload a CV and produce a sanitized, PII-masked version (redacts email, phone, physical address).",
        inputSchema: {
            type: "object",
            properties: {
                file_path: {
                    type: "string",
                    description: "Path to resume file to redact.",
                },
            },
            required: ["file_path"],
        },
    },
    {
        name: "civify_scrape_job",
        description: "Scrape and extract structured job description, company name, requirements, and responsibilities from a job URL (LinkedIn, Greenhouse, Lever, Ashby, Wuzzuf).",
        inputSchema: {
            type: "object",
            properties: {
                url: {
                    type: "string",
                    description: "The URL of the job posting.",
                },
            },
            required: ["url"],
        },
    },
    {
        name: "civify_track_application",
        description: "Record a job application in the candidate's Civify Application Kanban tracker.",
        inputSchema: {
            type: "object",
            properties: {
                company_name: { type: "string" },
                job_title: { type: "string" },
                job_url: { type: "string" },
                status: {
                    type: "string",
                    enum: ["EVALUATED", "APPLIED", "INTERVIEW", "OFFER", "REJECTED"],
                    default: "APPLIED",
                },
                notes: { type: "string" },
            },
            required: ["company_name", "job_title"],
        },
    },
    {
        name: "civify_get_pay_per_cv_pricing",
        description: "Get localized Pay-Per-CV single unlock pricing (USD base and EGP regional pricing).",
        inputSchema: {
            type: "object",
            properties: {},
        },
    },
];
const createMcpServer = (clientApiKey) => {
    const client = createApiClient(clientApiKey);
    const server = new index_js_1.Server({
        name: "civify-mcp-server",
        version: "1.0.0",
    }, {
        capabilities: {
            tools: {},
        },
    });
    server.setRequestHandler(types_js_1.ListToolsRequestSchema, async () => {
        return { tools: TOOLS };
    });
    server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
        const { name, arguments: args } = request.params;
        try {
            switch (name) {
                case "civify_get_account": {
                    const res = await client.get("/v1/external/cvs/user/profile");
                    return {
                        content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                    };
                }
                case "civify_get_pay_per_cv_pricing": {
                    const res = await client.get("/v1/pay-per-cv/pricing");
                    return {
                        content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                    };
                }
                case "civify_parse_cv": {
                    const filePath = String(args?.file_path || "");
                    if (!fs.existsSync(filePath)) {
                        throw new Error(`File not found: ${filePath}`);
                    }
                    const form = new form_data_1.default();
                    form.append("file", fs.createReadStream(filePath));
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
                case "civify_tailor_cv": {
                    const form = new form_data_1.default();
                    if (args?.file_path) {
                        const filePath = String(args.file_path);
                        if (!fs.existsSync(filePath)) {
                            throw new Error(`File not found: ${filePath}`);
                        }
                        form.append("file", fs.createReadStream(filePath));
                    }
                    form.append("jobDescription", String(args?.job_description || ""));
                    if (args?.job_title)
                        form.append("jobTitle", String(args.job_title));
                    if (args?.company_name)
                        form.append("companyName", String(args.company_name));
                    if (args?.generate_cover_letter)
                        form.append("generateCoverLetter", "true");
                    const res = await client.post("/v1/external/cvs/tailor", form, {
                        headers: form.getHeaders(),
                    });
                    return {
                        content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                    };
                }
                case "civify_score_ats": {
                    const resumeId = String(args?.resume_id || "");
                    const res = await client.post(`/v1/cvs/score?resumeId=${resumeId}`);
                    return {
                        content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                    };
                }
                case "civify_mask_pii": {
                    const filePath = String(args?.file_path || "");
                    if (!fs.existsSync(filePath)) {
                        throw new Error(`File not found: ${filePath}`);
                    }
                    const form = new form_data_1.default();
                    form.append("file", fs.createReadStream(filePath));
                    const res = await client.post("/v1/external/cvs/mask", form, {
                        headers: form.getHeaders(),
                        responseType: "arraybuffer",
                    });
                    const outPath = filePath.replace(/\.[^/.]+$/, "_masked.pdf");
                    fs.writeFileSync(outPath, Buffer.from(res.data));
                    return {
                        content: [
                            {
                                type: "text",
                                text: JSON.stringify({
                                    status: "SUCCESS",
                                    message: `Sanitized masked PDF saved to ${outPath}`,
                                    path: outPath,
                                }, null, 2),
                            },
                        ],
                    };
                }
                case "civify_scrape_job": {
                    const url = String(args?.url || "");
                    const res = await client.post("/v1/job-applications/scrape-jd", { url });
                    return {
                        content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                    };
                }
                case "civify_track_application": {
                    const res = await client.post("/v1/job-applications", {
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
                default:
                    throw new Error(`Unknown tool: ${name}`);
            }
        }
        catch (error) {
            const errorMsg = error?.response?.data
                ? typeof error.response.data === "string"
                    ? error.response.data
                    : JSON.stringify(error.response.data)
                : error.message;
            return {
                content: [{ type: "text", text: `Civify API Error: ${errorMsg}` }],
                isError: true,
            };
        }
    });
    return server;
};
async function runStdio() {
    const server = createMcpServer();
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("Civify MCP Server running on stdio transport.");
}
async function runSse(listenPort) {
    const app = (0, express_1.default)();
    app.use((0, cors_1.default)({ origin: "*" }));
    // Map to store active SSE sessions
    const sseTransports = new Map();
    // Traefik / Dokploy healthcheck
    app.get("/health", (req, res) => {
        res.json({
            status: "UP",
            service: "civify-mcp-server",
            transport: "sse",
            activeSessions: sseTransports.size,
            timestamp: new Date().toISOString(),
        });
    });
    // Overview / Welcome
    app.get("/", (req, res) => {
        res.json({
            service: "Civify Model Context Protocol (MCP) Server",
            homepage: "https://civify.cv",
            docs: "https://civify.cv/developers/mcp",
            endpoints: {
                sse: "/sse",
                messages: "/messages",
                health: "/health",
            },
            toolsCount: TOOLS.length,
        });
    });
    // SSE connection endpoint
    app.get("/sse", async (req, res) => {
        const apiKey = req.headers["x-api-key"] || req.query.apiKey || CIVIFY_API_KEY;
        const server = createMcpServer(apiKey);
        const transport = new sse_js_1.SSEServerTransport("/messages", res);
        sseTransports.set(transport.sessionId, transport);
        transport.onclose = () => {
            sseTransports.delete(transport.sessionId);
            console.log(`[SSE] Session closed: ${transport.sessionId}`);
        };
        console.log(`[SSE] Session started: ${transport.sessionId}`);
        await server.connect(transport);
    });
    // Message receiver for active SSE sessions
    app.post("/messages", async (req, res) => {
        const sessionId = String(req.query.sessionId || "");
        const transport = sseTransports.get(sessionId);
        if (!transport) {
            res.status(404).json({ error: `Session not found: ${sessionId}` });
            return;
        }
        await transport.handlePostMessage(req, res);
    });
    app.listen(listenPort, "0.0.0.0", () => {
        console.log(`🚀 Civify Remote MCP Server running on port ${listenPort}`);
        console.log(`🔗 SSE endpoint: http://0.0.0.0:${listenPort}/sse`);
        console.log(`🩺 Healthcheck: http://0.0.0.0:${listenPort}/health`);
    });
}
// Entrypoint dispatch
if (IS_SSE) {
    const effectivePort = PORT || 8080;
    runSse(effectivePort).catch((err) => {
        console.error("Fatal error starting Civify SSE server:", err);
        process.exit(1);
    });
}
else {
    runStdio().catch((err) => {
        console.error("Fatal error starting Civify Stdio server:", err);
        process.exit(1);
    });
}
