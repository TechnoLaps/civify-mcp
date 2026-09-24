import { randomBytes, createHash, createCipheriv, createDecipheriv } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express from "express";
import axios from "axios";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { InvalidGrantError, InvalidTokenError, InvalidScopeError, InvalidTargetError, InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
const opaque = () => randomBytes(32).toString("base64url");
const hash = (value) => createHash("sha256").update(value).digest("hex");
const escapeHtml = (value) => value.replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SCOPE = "civify:tools";
/** Single-replica encrypted storage. Codes and browser transactions intentionally die on restart. */
export class CivifyOAuthProvider {
    issuer;
    apiUrl;
    storePath;
    key;
    db = { clients: {}, access: {}, refresh: {} };
    pending = new Map();
    codes = new Map();
    resource;
    constructor(issuer, apiUrl, storePath, key) {
        this.issuer = issuer;
        this.apiUrl = apiUrl;
        this.storePath = storePath;
        this.key = key;
        this.resource = new URL("/mcp", issuer);
        if (key.length !== 32)
            throw new Error("CIVIFY_OAUTH_STORE_KEY must encode exactly 32 random bytes as base64.");
        if (fs.existsSync(storePath)) {
            const encrypted = Buffer.from(fs.readFileSync(storePath, "utf8"), "base64");
            const decipher = createDecipheriv("aes-256-gcm", key, encrypted.subarray(0, 12));
            decipher.setAuthTag(encrypted.subarray(12, 28));
            this.db = JSON.parse(Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]).toString());
        }
    }
    save() {
        for (const entries of [this.db.access, this.db.refresh]) {
            for (const [id, grant] of Object.entries(entries))
                if (grant.expires <= Date.now())
                    delete entries[id];
        }
        fs.mkdirSync(path.dirname(this.storePath), { recursive: true, mode: 0o700 });
        const iv = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", this.key, iv);
        const data = Buffer.concat([cipher.update(JSON.stringify(this.db)), cipher.final()]);
        const temporary = `${this.storePath}.tmp`;
        fs.writeFileSync(temporary, Buffer.concat([iv, cipher.getAuthTag(), data]).toString("base64"), { mode: 0o600 });
        fs.renameSync(temporary, this.storePath);
    }
    get clientsStore() {
        return {
            getClient: (id) => Object.hasOwn(this.db.clients, id) ? this.db.clients[id] : undefined,
            registerClient: (client) => {
                if (Object.keys(this.db.clients).length >= 10000)
                    throw new InvalidClientMetadataError("Client capacity reached.");
                for (const uri of client.redirect_uris) {
                    const url = new URL(uri);
                    if (url.hash || url.username || url.password || (url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)))) {
                        throw new InvalidClientMetadataError("Redirect URIs require HTTPS (or loopback HTTP), without credentials or fragments.");
                    }
                }
                const registered = { ...client, client_id: opaque(), client_id_issued_at: Math.floor(Date.now() / 1000) };
                this.db.clients[registered.client_id] = registered;
                this.save();
                return registered;
            },
        };
    }
    checkResource(resource) {
        if (resource && resource.href !== this.resource.href)
            throw new InvalidTargetError("The resource must be this server's /mcp URL.");
    }
    checkScopes(scopes) {
        if (scopes?.some(s => s !== SCOPE))
            throw new InvalidScopeError("Only civify:tools is supported.");
    }
    async authorize(client, params, res) {
        this.checkResource(params.resource);
        this.checkScopes(params.scopes);
        for (const [id, pending] of this.pending)
            if (pending.expires <= Date.now())
                this.pending.delete(id);
        for (const [id, code] of this.codes)
            if (code.expires <= Date.now())
                this.codes.delete(id);
        if (this.pending.size >= 1000)
            throw new InvalidGrantError("Too many pending authorizations.");
        const id = opaque();
        const csrf = opaque();
        this.pending.set(id, { client, params, csrf, expires: Date.now() + 10 * 60_000 });
        res.cookie("civify_oauth", csrf, { httpOnly: true, secure: this.issuer.protocol === "https:", sameSite: "lax", path: "/oauth/consent", maxAge: 600_000 });
        res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" });
        res.type("html").send(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Connect Civify</title><h1>Connect your Civify account</h1><p>Client: <strong>${escapeHtml(client.client_name || client.client_id)}</strong></p><p>Return address: ${escapeHtml(params.redirectUri)}</p><p>This grants access to your profile, resumes, AI tools, applications and purchase initiation within your API key's permissions. AI operations can consume credits. Payments require checkout.</p><p>Create a dedicated, scoped API key in your <a href="https://civify.cv/en/app/api-keys" target="_blank" rel="noopener noreferrer">Civify account</a>. Enter it here, never in the agent conversation. Revoke the key in Civify to disconnect access.</p><form method="post" action="/oauth/consent"><input type="hidden" name="transaction" value="${id}"><input type="hidden" name="csrf" value="${csrf}"><label>Civify API key <input type="password" name="api_key" required autocomplete="off" maxlength="512"></label><button name="decision" value="allow">Connect Civify</button><button name="decision" value="deny" formnovalidate>Cancel</button></form></html>`);
    }
    consent = async (req, res) => {
        res.set("Cache-Control", "no-store");
        const id = String(req.body?.transaction || "");
        const pending = this.pending.get(id);
        const cookie = req.headers.cookie?.split(";").map(s => s.trim()).find(s => s.startsWith("civify_oauth="))?.slice(13);
        if (!pending || pending.expires <= Date.now() || req.body.csrf !== pending.csrf || cookie !== pending.csrf || req.get("origin") !== this.issuer.origin) {
            res.status(400).send("Authorization expired or invalid. Restart account linking from your MCP client.");
            return;
        }
        // Consume before awaiting the backend: one browser submission per authorization.
        this.pending.delete(id);
        const redirect = new URL(pending.params.redirectUri);
        if (pending.params.state !== undefined)
            redirect.searchParams.set("state", pending.params.state);
        if (req.body.decision !== "allow") {
            redirect.searchParams.set("error", "access_denied");
            res.redirect(redirect.href);
            return;
        }
        const apiKey = String(req.body.api_key || "").trim();
        try {
            if (!apiKey.startsWith("cv-fy-"))
                throw new Error("Invalid key");
            await axios.get(`${this.apiUrl}/v1/external/cvs/user/profile`, { headers: { "X-API-KEY": apiKey }, timeout: 15000, maxRedirects: 0 });
        }
        catch {
            res.status(400).send("Unable to validate the key. Check account:read permission and restart account linking.");
            return;
        }
        const code = opaque();
        this.codes.set(hash(code), { ...pending, apiKey, expires: Date.now() + 60_000 });
        redirect.searchParams.set("code", code);
        res.redirect(redirect.href);
    };
    getCode(client, code) {
        const value = this.codes.get(hash(code));
        if (!value || value.expires <= Date.now() || value.client.client_id !== client.client_id)
            throw new InvalidGrantError("Invalid or expired authorization code.");
        return value;
    }
    async challengeForAuthorizationCode(client, code) {
        return this.getCode(client, code).params.codeChallenge;
    }
    async exchangeAuthorizationCode(client, code, _verifier, redirectUri, resource) {
        this.checkResource(resource);
        const value = this.getCode(client, code);
        if (redirectUri !== value.params.redirectUri)
            throw new InvalidGrantError("Redirect URI mismatch.");
        this.codes.delete(hash(code));
        return this.issue(client.client_id, value.apiKey, opaque());
    }
    issue(clientId, apiKey, family) {
        const access = opaque(), refresh = opaque();
        this.db.access[hash(access)] = { clientId, apiKey, family, expires: Date.now() + 3600_000 };
        this.db.refresh[hash(refresh)] = { clientId, apiKey, family, expires: Date.now() + 30 * 86400_000 };
        this.save();
        return { access_token: access, token_type: "Bearer", expires_in: 3600, refresh_token: refresh, scope: SCOPE };
    }
    async exchangeRefreshToken(client, token, scopes, resource) {
        this.checkResource(resource);
        this.checkScopes(scopes);
        const grant = this.db.refresh[hash(token)];
        if (!grant || grant.expires <= Date.now() || grant.clientId !== client.client_id)
            throw new InvalidGrantError("Invalid refresh token; reconnect Civify.");
        delete this.db.refresh[hash(token)];
        return this.issue(grant.clientId, grant.apiKey, grant.family);
    }
    async verifyAccessToken(token) {
        const grant = this.db.access[hash(token)];
        if (!grant || grant.expires <= Date.now())
            throw new InvalidTokenError("Invalid or expired token; reconnect Civify.");
        return { token, clientId: grant.clientId, scopes: [SCOPE], expiresAt: Math.floor(grant.expires / 1000), resource: this.resource, extra: { apiKey: grant.apiKey } };
    }
    async revokeToken(client, request) {
        const grant = this.db.access[hash(request.token)] || this.db.refresh[hash(request.token)];
        if (!grant || grant.clientId !== client.client_id)
            return;
        for (const entries of [this.db.access, this.db.refresh])
            for (const [id, item] of Object.entries(entries))
                if (item.family === grant.family)
                    delete entries[id];
        this.save();
    }
}
export function installOAuth(app, apiUrl) {
    const publicUrl = process.env.CIVIFY_MCP_PUBLIC_URL;
    if (!publicUrl)
        return undefined;
    const issuer = new URL(publicUrl);
    if (issuer.pathname !== "/" || issuer.search || issuer.hash || issuer.username || issuer.password || (issuer.protocol !== "https:" && !(issuer.protocol === "http:" && ["localhost", "127.0.0.1"].includes(issuer.hostname))))
        throw new Error("CIVIFY_MCP_PUBLIC_URL must be an HTTPS origin (loopback HTTP is allowed for tests).");
    const provider = new CivifyOAuthProvider(issuer, apiUrl, process.env.CIVIFY_OAUTH_STORE_PATH || "./data/oauth.enc", Buffer.from(process.env.CIVIFY_OAUTH_STORE_KEY || "", "base64"));
    app.use(mcpAuthRouter({ provider, issuerUrl: issuer, resourceServerUrl: provider.resource, scopesSupported: [SCOPE], resourceName: "Civify" }));
    // Older remote clients discover metadata at the origin instead of /mcp.
    app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json({ resource: provider.resource.href, authorization_servers: [issuer.href], scopes_supported: [SCOPE] }));
    app.post("/oauth/consent", express.urlencoded({ extended: false, limit: "8kb" }), provider.consent);
    return provider;
}
