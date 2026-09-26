import { randomBytes, createHash, createCipheriv, createDecipheriv } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express, { type Response } from "express";
import axios from "axios";
import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { OAuthServerProvider, AuthorizationParams } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthClientInformationFull, OAuthTokens } from "@modelcontextprotocol/sdk/shared/auth.js";
import { InvalidGrantError, InvalidTokenError, InvalidScopeError, InvalidTargetError, InvalidClientMetadataError } from "@modelcontextprotocol/sdk/server/auth/errors.js";

const opaque = () => randomBytes(32).toString("base64url");
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
const SCOPE = "civify:tools";
type Grant = { clientId: string; apiKey: string; expires: number; family: string; authorizationExpires?: number };
type Pending = { client: OAuthClientInformationFull; params: AuthorizationParams; csrf: string; verifier: string; expires: number };
type Code = Pending & { apiKey: string; authorizationExpires: number };
type Database = { clients: Record<string, OAuthClientInformationFull>; access: Record<string, Grant>; refresh: Record<string, Grant> };

/** Single-replica encrypted storage. Codes and browser transactions intentionally die on restart. */
export class CivifyOAuthProvider implements OAuthServerProvider {
  private db: Database = { clients: {}, access: {}, refresh: {} };
  private pending = new Map<string, Pending>();
  private codes = new Map<string, Code>();
  readonly resource: URL;
  private connectUrl: URL;
  constructor(readonly issuer: URL, private apiUrl: string, private storePath: string, private key: Buffer) {
    this.resource = new URL("/mcp", issuer);
    this.connectUrl = new URL(process.env.CIVIFY_ACCOUNT_CONNECT_URL || "https://civify.cv/en/mcp/connect");
    if (this.connectUrl.username || this.connectUrl.password || this.connectUrl.hash ||
        (this.connectUrl.protocol !== "https:" && !(this.connectUrl.protocol === "http:" && ["localhost", "127.0.0.1"].includes(this.connectUrl.hostname)))) {
      throw new Error("CIVIFY_ACCOUNT_CONNECT_URL requires HTTPS (or loopback HTTP).");
    }
    if (key.length !== 32) throw new Error("CIVIFY_OAUTH_STORE_KEY must encode exactly 32 random bytes as base64.");
    if (fs.existsSync(storePath)) {
      const encrypted = Buffer.from(fs.readFileSync(storePath, "utf8"), "base64");
      const decipher = createDecipheriv("aes-256-gcm", key, encrypted.subarray(0, 12));
      decipher.setAuthTag(encrypted.subarray(12, 28));
      this.db = JSON.parse(Buffer.concat([decipher.update(encrypted.subarray(28)), decipher.final()]).toString());
    }
  }
  private save() {
    for (const entries of [this.db.access, this.db.refresh]) {
      for (const [id, grant] of Object.entries(entries)) if (grant.expires <= Date.now()) delete entries[id];
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
      getClient: (id: string) => Object.hasOwn(this.db.clients, id) ? this.db.clients[id] : undefined,
      registerClient: (client: Omit<OAuthClientInformationFull, "client_id" | "client_id_issued_at">) => {
        if (Object.keys(this.db.clients).length >= 10000) throw new InvalidClientMetadataError("Client capacity reached.");
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
  private checkResource(resource?: URL) {
    if (resource && resource.href !== this.resource.href) throw new InvalidTargetError("The resource must be this server's /mcp URL.");
  }
  private checkScopes(scopes?: string[]) {
    if (scopes?.some(s => s !== SCOPE)) throw new InvalidScopeError("Only civify:tools is supported.");
  }
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response) {
    this.checkResource(params.resource);
    this.checkScopes(params.scopes);
    for (const [id, pending] of this.pending) if (pending.expires <= Date.now()) this.pending.delete(id);
    for (const [id, code] of this.codes) if (code.expires <= Date.now()) this.codes.delete(id);
    if (this.pending.size >= 1000) throw new InvalidGrantError("Too many pending authorizations.");
    const id = opaque();
    const csrf = opaque();
    this.pending.set(id, { client, params, csrf, verifier: opaque(), expires: Date.now() + 10 * 60_000 });
    res.cookie(`civify_oauth_${id}`, csrf, { httpOnly: true, secure: this.issuer.protocol === "https:", sameSite: "lax", path: "/oauth/complete", maxAge: 600_000 });
    res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" });
    const destination = new URL(this.connectUrl);
    destination.searchParams.set("transaction", id);
    res.redirect(destination.href);
  }
  // Public, unguessable request handle. No user data, browser secret or verifier is exposed.
  transaction = (req: express.Request, res: express.Response) => {
    res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
    const id = String(req.params.id || "");
    const pending = this.pending.get(id);
    if (!pending || pending.expires <= Date.now()) { res.status(404).json({ error: "Authorization expired. Reconnect from your client." }); return; }
    res.json({ transaction: id, clientName: pending.client.client_name || "AI client", redirectUri: pending.params.redirectUri,
      challenge: createHash("sha256").update(pending.verifier).digest("base64url"), expiresAt: pending.expires });
  };
  complete = async (req: express.Request, res: express.Response) => {
    res.set({ "Cache-Control": "no-store", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY" });
    const id = typeof req.query.transaction === "string" ? req.query.transaction : "";
    const pending = this.pending.get(id);
    const cookieName = `civify_oauth_${id}=`;
    const cookie = req.headers.cookie?.split(";").map(s => s.trim()).find(s => s.startsWith(cookieName))?.slice(cookieName.length);
    if (!pending || pending.expires <= Date.now() || cookie !== pending.csrf) {
      res.status(400).send("Authorization expired or invalid. Restart account linking from your MCP client."); return;
    }
    // Consume before awaiting the backend: one browser submission per authorization.
    this.pending.delete(id);
    res.clearCookie(`civify_oauth_${id}`, { path: "/oauth/complete" });
    const redirect = new URL(pending.params.redirectUri);
    if (pending.params.state !== undefined) redirect.searchParams.set("state", pending.params.state);
    if (req.query.error === "access_denied") {
      redirect.searchParams.set("error", "access_denied"); res.redirect(redirect.href); return;
    }
    let apiKey: string;
    let authorizationExpires: number;
    try {
      if (typeof req.query.code !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(req.query.code)) throw new Error("Invalid code");
      const exchanged = await axios.post(`${this.apiUrl}/mcp/account-link/exchange`,
        { code: req.query.code, verifier: pending.verifier, transaction: id }, { timeout: 15000, maxRedirects: 0 });
      apiKey = exchanged.data.apiKey;
      if (typeof apiKey !== "string" || !apiKey.startsWith("cv-fy-")) throw new Error("Invalid grant");
      authorizationExpires = exchanged.data.expiresAt;
      if (!Number.isFinite(authorizationExpires) || authorizationExpires <= Date.now()) throw new Error("Expired grant");
    } catch {
      // Never log the upstream response: it may contain credentials.
      res.status(400).send("Unable to complete Civify account linking. Restart from your MCP client and sign in again."); return;
    }
    const code = opaque();
    this.codes.set(hash(code), { ...pending, apiKey, authorizationExpires, expires: Date.now() + 60_000 });
    redirect.searchParams.set("code", code);
    res.redirect(redirect.href);
  };
  private getCode(client: OAuthClientInformationFull, code: string) {
    const value = this.codes.get(hash(code));
    if (!value || value.expires <= Date.now() || value.client.client_id !== client.client_id) throw new InvalidGrantError("Invalid or expired authorization code.");
    return value;
  }
  async challengeForAuthorizationCode(client: OAuthClientInformationFull, code: string) {
    return this.getCode(client, code).params.codeChallenge;
  }
  async exchangeAuthorizationCode(client: OAuthClientInformationFull, code: string, _verifier?: string, redirectUri?: string, resource?: URL) {
    this.checkResource(resource);
    const value = this.getCode(client, code);
    if (redirectUri !== value.params.redirectUri) throw new InvalidGrantError("Redirect URI mismatch.");
    this.codes.delete(hash(code));
    return this.issue(client.client_id, value.apiKey, opaque(), value.authorizationExpires);
  }
  private issue(clientId: string, apiKey: string, family: string, authorizationExpires = Date.now() + 30 * 86400_000): OAuthTokens {
    if (authorizationExpires <= Date.now()) throw new InvalidGrantError("Account connection expired; reconnect Civify.");
    const access = opaque(), refresh = opaque();
    const expiresIn = Math.min(3600, Math.floor((authorizationExpires - Date.now()) / 1000));
    if (expiresIn < 1) throw new InvalidGrantError("Account connection expired; reconnect Civify.");
    this.db.access[hash(access)] = { clientId, apiKey, family, authorizationExpires, expires: Date.now() + expiresIn * 1000 };
    this.db.refresh[hash(refresh)] = { clientId, apiKey, family, authorizationExpires, expires: Math.min(Date.now() + 30 * 86400_000, authorizationExpires) };
    this.save();
    return { access_token: access, token_type: "Bearer", expires_in: expiresIn, refresh_token: refresh, scope: SCOPE };
  }
  async exchangeRefreshToken(client: OAuthClientInformationFull, token: string, scopes?: string[], resource?: URL) {
    this.checkResource(resource); this.checkScopes(scopes);
    const grant = this.db.refresh[hash(token)];
    if (!grant || grant.expires <= Date.now() || grant.clientId !== client.client_id) throw new InvalidGrantError("Invalid refresh token; reconnect Civify.");
    delete this.db.refresh[hash(token)];
    return this.issue(grant.clientId, grant.apiKey, grant.family, grant.authorizationExpires);
  }
  async verifyAccessToken(token: string) {
    const grant = this.db.access[hash(token)];
    if (!grant || grant.expires <= Date.now()) throw new InvalidTokenError("Invalid or expired token; reconnect Civify.");
    return { token, clientId: grant.clientId, scopes: [SCOPE], expiresAt: Math.floor(grant.expires / 1000), resource: this.resource, extra: { apiKey: grant.apiKey } };
  }
  async revokeToken(client: OAuthClientInformationFull, request: { token: string }) {
    const grant = this.db.access[hash(request.token)] || this.db.refresh[hash(request.token)];
    if (!grant || grant.clientId !== client.client_id) return;
    for (const entries of [this.db.access, this.db.refresh]) for (const [id, item] of Object.entries(entries)) if (item.family === grant.family) delete entries[id];
    this.save();
  }
}

export function installOAuth(app: express.Express, apiUrl: string) {
  const publicUrl = process.env.CIVIFY_MCP_PUBLIC_URL;
  if (!publicUrl) return undefined;
  const issuer = new URL(publicUrl);
  if (issuer.pathname !== "/" || issuer.search || issuer.hash || issuer.username || issuer.password || (issuer.protocol !== "https:" && !(issuer.protocol === "http:" && ["localhost", "127.0.0.1"].includes(issuer.hostname)))) throw new Error("CIVIFY_MCP_PUBLIC_URL must be an HTTPS origin (loopback HTTP is allowed for tests).");
  const provider = new CivifyOAuthProvider(issuer, apiUrl, process.env.CIVIFY_OAUTH_STORE_PATH || "./data/oauth.enc", Buffer.from(process.env.CIVIFY_OAUTH_STORE_KEY || "", "base64"));
  app.use(mcpAuthRouter({ provider, issuerUrl: issuer, resourceServerUrl: provider.resource, scopesSupported: [SCOPE], resourceName: "Civify" }));
  // Older remote clients discover metadata at the origin instead of /mcp.
  app.get("/.well-known/oauth-protected-resource", (_req, res) => res.json({ resource: provider.resource.href, authorization_servers: [issuer.href], scopes_supported: [SCOPE] }));
  app.get("/oauth/transactions/:id", provider.transaction);
  app.get("/oauth/complete", provider.complete);
  return provider;
}
