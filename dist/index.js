#!/usr/bin/env node
"use strict";
/**
 * Civify Model Context Protocol (MCP) Server
 * Exposes AI resume parsing, ATS scoring, tailoring, PII masking,
 * and application tracking tools to AI agents (Claude, Cursor, OpenCode, Qwen).
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
const types_js_1 = require("@modelcontextprotocol/sdk/types.js");
const axios_1 = __importDefault(require("axios"));
const fs = __importStar(require("fs"));
const form_data_1 = __importDefault(require("form-data"));
const CIVIFY_BASE_URL = process.env.CIVIFY_API_URL || "https://civify.cv/apis";
const CIVIFY_API_KEY = process.env.CIVIFY_API_KEY;
if (!CIVIFY_API_KEY) {
    console.error("WARNING: CIVIFY_API_KEY environment variable is not set. Most tool calls will require authentication.");
}
const apiClient = axios_1.default.create({
    baseURL: CIVIFY_BASE_URL,
    timeout: 60000,
    headers: {
        "X-API-KEY": CIVIFY_API_KEY || "",
        "User-Agent": "Civify-MCP-Server/1.0.0",
    },
});
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
const server = new index_js_1.Server({
    name: "civify-mcp-server",
    version: "1.0.0",
}, {
    capabilities: {
        tools: {},
    },
});
// List available tools
server.setRequestHandler(types_js_1.ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
});
// Execute tool requests
server.setRequestHandler(types_js_1.CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
        switch (name) {
            case "civify_get_account": {
                const res = await apiClient.get("/v1/external/cvs/user/profile");
                return {
                    content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                };
            }
            case "civify_get_pay_per_cv_pricing": {
                const res = await apiClient.get("/v1/pay-per-cv/pricing");
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
                const res = await apiClient.post("/v1/external/cvs/parse", form, {
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
                const res = await apiClient.post("/v1/external/cvs/tailor", form, {
                    headers: form.getHeaders(),
                });
                return {
                    content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                };
            }
            case "civify_score_ats": {
                const resumeId = String(args?.resume_id || "");
                const res = await apiClient.post(`/v1/cvs/score?resumeId=${resumeId}`);
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
                const res = await apiClient.post("/v1/external/cvs/mask", form, {
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
                const res = await apiClient.post("/v1/job-applications/scrape-jd", { url });
                return {
                    content: [{ type: "text", text: JSON.stringify(res.data, null, 2) }],
                };
            }
            case "civify_track_application": {
                const res = await apiClient.post("/v1/job-applications", {
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
            ? (typeof error.response.data === "string" ? error.response.data : JSON.stringify(error.response.data))
            : error.message;
        return {
            content: [{ type: "text", text: `Civify API Error: ${errorMsg}` }],
            isError: true,
        };
    }
});
async function main() {
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    console.error("Civify MCP Server running on stdio transport.");
}
main().catch((err) => {
    console.error("Fatal error starting Civify MCP server:", err);
    process.exit(1);
});
