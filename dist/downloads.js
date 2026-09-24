import { randomBytes } from "node:crypto";
import { MAX_DOCUMENT_BYTES } from "./attachments.js";
/** Short-lived capability links: whoever has the random URL can download it. */
export class PdfDownloads {
    baseUrl;
    now;
    files = new Map();
    constructor(baseUrl, now = Date.now) {
        this.baseUrl = baseUrl;
        this.now = now;
        const url = new URL(baseUrl);
        if (url.username || url.password || url.search || url.hash || url.pathname !== "/" || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname))))
            throw new Error("CIVIFY_DOWNLOAD_BASE_URL must be an HTTPS origin (loopback HTTP for tests).");
    }
    purge() { for (const [id, item] of this.files)
        if (item.expires <= this.now())
            this.files.delete(id); }
    publish(buffer, filename) {
        this.purge();
        if (!buffer.length || buffer.length > MAX_DOCUMENT_BYTES || buffer.subarray(0, 5).toString() !== "%PDF-")
            throw new Error("INVALID_PDF: Renderer did not return a valid PDF within the 12 MiB limit.");
        if ([...this.files.values()].reduce((total, file) => total + file.buffer.length, 0) + buffer.length > 64 * 1024 * 1024 || this.files.size >= 200)
            throw new Error("DOWNLOAD_CAPACITY: Temporary download storage is full. Wait for existing links to expire before generating another PDF.");
        const id = randomBytes(32).toString("base64url");
        const expires = this.now() + 15 * 60_000;
        this.files.set(id, { buffer, filename, expires });
        const url = new URL(`/downloads/${id}`, this.baseUrl).href;
        const data = { status: "SUCCESS", filename, mime_type: "application/pdf", download_url: url, expires_at: new Date(expires).toISOString(), message: "Download this PDF now. The private link expires in 15 minutes or on server restart; anyone with the link can access it." };
        return { structuredContent: { data }, content: [{ type: "text", text: JSON.stringify(data) }, { type: "resource_link", uri: url, name: filename, mimeType: "application/pdf", size: buffer.length }] };
    }
    install(app) {
        const cleanup = setInterval(() => this.purge(), 60000);
        cleanup.unref();
        app.get("/downloads/:id", (req, res) => {
            this.purge();
            const item = this.files.get(String(req.params.id));
            res.set({ "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "X-Robots-Tag": "noindex, nofollow" });
            if (!item) {
                res.status(404).send("Download expired or unavailable. Generate a new PDF if needed.");
                return;
            }
            res.set("Content-Type", "application/pdf");
            res.set("Content-Disposition", `attachment; filename="resume.pdf"; filename*=UTF-8''${encodeURIComponent(item.filename)}`);
            res.send(item.buffer);
        });
    }
}
