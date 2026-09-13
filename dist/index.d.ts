#!/usr/bin/env node
/**
 * Civify Model Context Protocol (MCP) Server
 * Supports dual transport:
 * 1. Stdio (Local desktop/CLI agents: Claude Desktop, Cursor, OpenCode)
 * 2. Remote SSE (Cloud deployments: Dokploy / Docker behind Traefik at mcp.civify.cv)
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
export declare const createMcpServer: (sessionAuth: SessionAuthState) => Server<{
    method: string;
    params?: {
        [x: string]: unknown;
        _meta?: {
            [x: string]: unknown;
            progressToken?: string | number | undefined;
            "io.modelcontextprotocol/related-task"?: {
                taskId: string;
            } | undefined;
        } | undefined;
    } | undefined;
}, {
    method: string;
    params?: {
        [x: string]: unknown;
        _meta?: {
            [x: string]: unknown;
            progressToken?: string | number | undefined;
            "io.modelcontextprotocol/related-task"?: {
                taskId: string;
            } | undefined;
        } | undefined;
    } | undefined;
}, {
    [x: string]: unknown;
    _meta?: {
        [x: string]: unknown;
        progressToken?: string | number | undefined;
        "io.modelcontextprotocol/related-task"?: {
            taskId: string;
        } | undefined;
    } | undefined;
}>;
