import type { Express } from "express";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
/** Short-lived capability links: whoever has the random URL can download it. */
export declare class PdfDownloads {
    private baseUrl;
    private now;
    private files;
    constructor(baseUrl: string, now?: () => number);
    private purge;
    publish(buffer: Buffer, filename: string): CallToolResult;
    install(app: Express): void;
}
