import { describe, it, expect, afterEach, vi } from "vitest";
import worker from "../src/index.js";

const SECRET = "test-shared-secret";
const PANEL = "https://panel.geograficas.shcdigital.net.ar";
const CLIENTES_URL = "https://clientes.shcdigital.net.ar";

function makeEnv() {
  const store = new Map();
  return {
    SESSIONS: {
      put: async (k, v, o) => store.set(k, { v, o }),
      get: async (k) => store.get(k)?.v ?? null,
      delete: async (k) => store.delete(k),
      _store: store,
    },
    SHARED_JWT_SECRET: SECRET,
    GITHUB_TOKEN: "gh-token-test",
    GITHUB_REPO: "shcdigital/geo-graficas-web",
    CONTENT_PATH: "src/content/recursos",
    PRICES_PATH: "src/data/prices.json",
    IMG_PATH: "public/img/recursos",
    PANEL_URL: PANEL,
    SITE_URL: "https://shcdigital.github.io/geo-graficas-web",
    CLIENTES_URL,
    TENANT_ID: "geo-graficas",
    APP_NAME: "Geo.Gráficas Admin",
  };
}

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

function b64url(obj) {
  return Buffer.from(JSON.stringify(obj)).toString("base64url");
}

async function signJWT(payload, secret = SECRET) {
  const enc = new TextEncoder();
  const full = { iss: CLIENTES_URL, jti: crypto.randomUUID(), ...payload };
  const head = b64url({ alg: "HS256", typ: "JWT" });
  const body = b64url(full);
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`${head}.${body}`));
  return `${head}.${body}.${Buffer.from(sig).toString("base64url")}`;
}

function req(path, { method = "GET", origin, body, cookie, contentType } = {}) {
  const headers = {};
  if (origin) headers["Origin"] = origin;
  if (cookie) headers["Cookie"] = cookie;
  if (body) headers["Content-Type"] = contentType ?? "application/json";
  return new Request(PANEL + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
}

const sessionKeys = (env) => [...env.SESSIONS._store.keys()].filter((k) => k.startsWith("session:"));

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("SSO /auth/sso (geo-graficas)", () => {
  it("rechaza si falta el token (400)", async () => {
    const res = await worker.fetch(req("/auth/sso"), makeEnv(), ctx);
    expect(res.status).toBe(400);
  });

  it("rechaza firma inválida (401)", async () => {
    const token = await signJWT({ sub: "a@b.c", tenant: "geo-graficas", aud: PANEL, exp: Math.floor(Date.now() / 1000) + 60 }, "otro-secreto");
    const res = await worker.fetch(req(`/auth/sso?token=${token}`), makeEnv(), ctx);
    expect(res.status).toBe(401);
  });

  it("rechaza token expirado (401)", async () => {
    const token = await signJWT({ sub: "a@b.c", tenant: "geo-graficas", aud: PANEL, exp: Math.floor(Date.now() / 1000) - 10 });
    const res = await worker.fetch(req(`/auth/sso?token=${token}`), makeEnv(), ctx);
    expect(res.status).toBe(401);
  });

  it("rechaza tenant incorrecto (403)", async () => {
    const token = await signJWT({ sub: "a@b.c", tenant: "shcdigital", aud: PANEL, exp: Math.floor(Date.now() / 1000) + 60 });
    const res = await worker.fetch(req(`/auth/sso?token=${token}`), makeEnv(), ctx);
    expect(res.status).toBe(403);
  });

  it("rechaza aud incorrecto (403)", async () => {
    const token = await signJWT({ sub: "a@b.c", tenant: "geo-graficas", aud: "https://evil.example", exp: Math.floor(Date.now() / 1000) + 60 });
    const res = await worker.fetch(req(`/auth/sso?token=${token}`), makeEnv(), ctx);
    expect(res.status).toBe(403);
  });

  it("rechaza iss incorrecto (403)", async () => {
    const token = await signJWT({ sub: "a@b.c", tenant: "geo-graficas", aud: PANEL, iss: "https://evil.example", exp: Math.floor(Date.now() / 1000) + 60 });
    const res = await worker.fetch(req(`/auth/sso?token=${token}`), makeEnv(), ctx);
    expect(res.status).toBe(403);
  });

  it("token válido crea sesión y cookie segura", async () => {
    const env = makeEnv();
    const token = await signJWT({ sub: "a@b.c", name: "Ana", tenant: "geo-graficas", aud: PANEL, exp: Math.floor(Date.now() / 1000) + 60 });
    const res = await worker.fetch(req(`/auth/sso?token=${token}`), env, ctx);
    expect(res.status).toBe(200);
    const cookie = res.headers.get("Set-Cookie");
    expect(cookie).toContain("gg_session=");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("Secure");
    expect(sessionKeys(env)).toHaveLength(1);
  });

  it("POST /auth/sso (form-encoded) abre sesión", async () => {
    const env = makeEnv();
    const token = await signJWT({ sub: "a@b.c", tenant: "geo-graficas", aud: PANEL, exp: Math.floor(Date.now() / 1000) + 60 });
    const request = new Request(PANEL + "/auth/sso", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token }).toString(),
    });
    const res = await worker.fetch(request, env, ctx);
    expect(res.status).toBe(200);
    expect(sessionKeys(env)).toHaveLength(1);
  });

  it("jti de un solo uso: reuso del mismo token → 401", async () => {
    const env = makeEnv();
    const token = await signJWT({ sub: "a@b.c", tenant: "geo-graficas", aud: PANEL, exp: Math.floor(Date.now() / 1000) + 60 });
    const first = await worker.fetch(req(`/auth/sso?token=${token}`), env, ctx);
    expect(first.status).toBe(200);
    const second = await worker.fetch(req(`/auth/sso?token=${token}`), env, ctx);
    expect(second.status).toBe(401);
  });
});

describe("Guard de mutaciones (anti-CSRF) geo-graficas", () => {
  const cases = [
    ["/api/recursos", "POST", { slug: "x" }],
    ["/api/recurso", "PUT", { slug: "x" }],
    ["/api/recurso", "DELETE", { slug: "x" }],
    ["/api/imagen", "POST", { slug: "x" }],
    ["/api/prices", "PUT", { categories: {} }],
    ["/api/mensaje", "POST", { text: "hola" }],
  ];
  it.each(cases)("%s %s sin Origin → 403", async (path, method, body) => {
    const res = await worker.fetch(req(path, { method, body }), makeEnv(), ctx);
    expect(res.status).toBe(403);
  });

  it.each(cases)("%s %s con Origin atacante → 403", async (path, method, body) => {
    const res = await worker.fetch(req(path, { method, origin: "https://evil.example", body }), makeEnv(), ctx);
    expect(res.status).toBe(403);
  });

  it("logout sin Origin → 403", async () => {
    const res = await worker.fetch(req("/auth/logout", { method: "POST" }), makeEnv(), ctx);
    expect(res.status).toBe(403);
  });

  it("logout GET (método viejo) → 404", async () => {
    const res = await worker.fetch(req("/auth/logout", { origin: PANEL }), makeEnv(), ctx);
    expect(res.status).toBe(404);
  });
});

describe("Sesión /auth/me geo-graficas", () => {
  it("sin sesión → authed:false", async () => {
    const res = await worker.fetch(req("/auth/me"), makeEnv(), ctx);
    const data = await res.json();
    expect(data.authed).toBe(false);
  });

  it("con sesión en KV → authed:true", async () => {
    const env = makeEnv();
    await env.SESSIONS.put("session:abc", JSON.stringify({ email: "x@y.z", name: "X" }));
    const res = await worker.fetch(req("/auth/me", { cookie: "gg_session=abc" }), env, ctx);
    const data = await res.json();
    expect(data.authed).toBe(true);
    expect(data.email).toBe("x@y.z");
  });
});

describe("Render geo-graficas", () => {
  it("GET / sirve SPA con placeholders y headers de seguridad", async () => {
    const res = await worker.fetch(new Request(PANEL + "/"), makeEnv(), ctx);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain(PANEL);
    expect(html).not.toContain("__WORKER_BASE__");
    expect(html).not.toContain("login-local");
    for (const h of ["strict-transport-security", "x-content-type-options", "referrer-policy", "x-robots-tag"]) {
      expect(res.headers.get(h)).toBeTruthy();
    }
  });

  it("CORS: origen atacante no se refleja", async () => {
    const res = await worker.fetch(new Request(PANEL + "/api/recursos", { headers: { Origin: "https://evil.example" } }), makeEnv(), ctx);
    expect(res.headers.get("Access-Control-Allow-Origin")).not.toBe("https://evil.example");
  });
});
