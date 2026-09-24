import axios from "axios";
import https from "node:https";
import dns from "node:dns";
import { BlockList, isIP } from "node:net";
import path from "node:path";
export const MAX_DOCUMENT_BYTES = 12 * 1024 * 1024;
export const FILE_SCHEMA = {
    type: "object", description: "A user-selected chat attachment supplied by the client. Never invent a download URL or file ID.",
    properties: { download_url: { type: "string" }, file_id: { type: "string" }, mime_type: { type: "string" }, file_name: { type: "string" } },
    required: ["download_url", "file_id"], additionalProperties: false,
};
const blocked = new BlockList();
for (const [address, prefix] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]])
    blocked.addSubnet(address, prefix);
const globalV6 = new BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");
blocked.addSubnet("2001::", 23, "ipv6");
blocked.addSubnet("2001:db8::", 32, "ipv6");
blocked.addSubnet("2002::", 16, "ipv6");
export function isPublicAddress(address) {
    const family = isIP(address);
    return family === 4 ? !blocked.check(address) : family === 6 && globalV6.check(address, "ipv6") && !blocked.check(address, "ipv6");
}
export function attachmentUrl(value) {
    let url;
    try {
        url = new URL(value);
    }
    catch {
        throw new Error("ATTACHMENT_UNAVAILABLE: Provide a real HTTPS attachment download URL or resume_text.");
    }
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (url.protocol !== "https:" || (url.port && url.port !== "443") || url.username || url.password || host === "localhost" || host.endsWith(".localhost") || (isIP(host) && !isPublicAddress(host))) {
        throw new Error("ATTACHMENT_UNAVAILABLE: Attachment URLs must use public HTTPS, without credentials. Local/sandbox paths are not download URLs.");
    }
    return url;
}
// DNS is checked at socket creation, and the exact checked address is used for
// the connection. Every redirect gets the same check; no credential forwarding.
export const publicLookup = (hostname, options, callback) => {
    dns.lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
        if (error || !addresses.length || addresses.some(item => !isPublicAddress(item.address))) {
            callback(new Error("Attachment host is unavailable or not public."), "", 4);
            return;
        }
        const all = typeof options === "object" && options.all;
        if (all)
            callback(null, addresses);
        else
            callback(null, addresses[0].address, addresses[0].family);
    });
};
const agent = new https.Agent({ lookup: publicLookup, keepAlive: false });
export async function downloadAttachment(value, request = axios.get) {
    let url = attachmentUrl(value);
    const signal = AbortSignal.timeout(30000);
    try {
        for (let redirects = 0; redirects <= 3; redirects++) {
            const response = await request(url.href, { httpsAgent: agent, proxy: false, maxRedirects: 0, responseType: "arraybuffer", maxContentLength: MAX_DOCUMENT_BYTES, timeout: 15000, signal, validateStatus: () => true, headers: { Accept: "application/pdf, application/vnd.openxmlformats-officedocument.wordprocessingml.document, image/*, text/plain" } });
            if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.location) {
                url = attachmentUrl(new URL(response.headers.location, url).href);
                continue;
            }
            if (response.status !== 200)
                throw new Error("Attachment download failed.");
            const buffer = Buffer.from(response.data);
            if (!buffer.length || buffer.length > MAX_DOCUMENT_BYTES)
                throw new Error("Attachment size exceeds limit.");
            return buffer;
        }
        throw new Error("Too many attachment redirects.");
    }
    catch {
        // Never expose signed URLs or download service error bodies in tool results.
        throw new Error("ATTACHMENT_UNAVAILABLE: Could not download this file within 30 seconds / 12 MiB. Ask the client for a fresh attachment link, or send readable resume_text. Do not repeatedly retry the same expired link.");
    }
}
export function decodeDocument(value) {
    const normalized = value.trim().replace(/^data:[^;,]+;base64,/i, "").replace(/\s/g, "");
    if (!normalized || normalized.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized) || normalized.length > Math.ceil(MAX_DOCUMENT_BYTES / 3) * 4)
        throw new Error("INVALID_DOCUMENT: file_base64 must contain a valid document of at most 12 MiB.");
    const buffer = Buffer.from(normalized, "base64");
    if (!buffer.length || buffer.length > MAX_DOCUMENT_BYTES || buffer.toString("base64") !== normalized)
        throw new Error("INVALID_DOCUMENT: Invalid or oversized base64 document.");
    return buffer;
}
export function documentMetadata(buffer, filename) {
    const type = buffer.subarray(0, 5).toString() === "%PDF-" ? ["pdf", "application/pdf"] : buffer[0] === 0x50 && buffer[1] === 0x4b ? ["docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"] : buffer[0] === 0x89 && buffer.subarray(1, 4).toString() === "PNG" ? ["png", "image/png"] : buffer[0] === 0xff && buffer[1] === 0xd8 ? ["jpg", "image/jpeg"] : ["txt", "text/plain"];
    // A missing optional ChatGPT file_name must not turn a DOCX/image into resume.pdf.
    const safe = filename ? path.basename(filename.replace(/\\/g, "/")).replace(/[\x00-\x1f<>:"/\\|?*]/g, "_") : `resume.${type[0]}`;
    if (buffer.subarray(0, 100).toString().trimStart().match(/^<(?:!doctype\s+html|html)/i))
        throw new Error("INVALID_DOCUMENT: The attachment link returned a web page. Supply the original file or resume_text.");
    return { filename: safe, contentType: type[1] };
}
