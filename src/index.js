// geo-graficas-admin · Cloudflare Worker
// Panel de administración de Geo.Gráficas.
// - Login: SSO vía clientes.shcdigital.net.ar (JWT firmado) o local (PBKDF2, hash en el repo)
// - Sesiones en Workers KV
// - CRUD de cuadernillos (.md) contra la API de GitLab
// Se sirve en: <admin del cliente> (ruta Cloudflare Workers) y también
// como página estática en GitLab Pages (apuntando a este Worker para la API).

// ---------- Secrets requeridos (wrangler secret put) ----------
// SHARED_JWT_SECRET (idéntico al del Worker SSO de clientes)
// GITLAB_TOKEN (token de proyecto con scope api) / GITLAB_PROJECT_ID

// Login local: hash PBKDF2-SHA256 (100000 iter) de la contraseña + salt.
// SOLO está el hash, nunca la contraseña en claro.
const LOCAL_USER = "admin";
const LOCAL_SALT_B64 = "j+fjQHoDnbMq0a5Dlhrj6A==";
const LOCAL_HASH_B64 = "UDJaznYt9Pv/+8Zbo1VzWhJ7xQVC0kX0uk6t0TxAZz0=";

import adminHtml from "./admin.txt?raw";

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };
const HTML_HEADERS = { "Content-Type": "text/html; charset=utf-8" };

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, origin) });
    }

    // Panel admin (SPA) en la raíz
    if (url.pathname === "/" || url.pathname === "/admin") {
      return new Response(renderAdmin(env, url), { headers: HTML_HEADERS });
    }

    // SSO: el Worker de clientes (clientes.shcdigital.net.ar) valida el login
    // y redirige acá con un JWT firmado. Este Worker solo valida y abre sesión.
    if (url.pathname === "/auth/sso" && request.method === "GET") {
      return await ssoLogin(request, env, ctx);
    }

    if (url.pathname === "/auth/logout") return await logout(request, env, origin);
    if (url.pathname === "/auth/me") return corsWrap(await me(request, env), env, origin);

    // Login local
    if (url.pathname === "/auth/login-local" && request.method === "POST") {
      return corsWrap(await loginLocal(request, env, origin), env, origin);
    }

    // API de cuadernillos (requiere sesión)
    if (url.pathname.startsWith("/api/")) {
      return corsWrap(await handleApi(request, env, ctx, url), env, origin);
    }

    return new Response("Not found", { status: 404 });
  },
};

function corsHeaders(env, origin) {
  const site = (env.SITE_URL || "").replace(/\/+$/, "");
  const match = site && origin && origin.replace(/\/+$/, "") === site;
  const allowOrigin = site ? (match ? origin : site) : origin;
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
  };
}

function corsWrap(res, env, origin) {
  const r = new Response(res.body, res);
  for (const k in corsHeaders(env, origin)) r.headers.set(k, corsHeaders(env, origin)[k]);
  return r;
}

// ---------- Login ----------
async function loginLocal(request, env, origin) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "Body inválido" }, 400); }
  const user = String(body.user || "").trim();
  const pass = String(body.pass || "");

  if (user !== LOCAL_USER) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  const salt = Uint8Array.from(atob(LOCAL_SALT_B64), (c) => c.charCodeAt(0));
  const expected = Uint8Array.from(atob(LOCAL_HASH_B64), (c) => c.charCodeAt(0));
  const derived = await pbkdf2(pass, salt);
  if (!constantTimeEqual(derived, expected)) return json({ error: "Usuario o contraseña incorrectos" }, 401);

  return makeSession(env, { email: `${LOCAL_USER}@local`, name: "Administrador local" }, origin);
}

function originOf(request) {
  return request.headers.get("Origin") || new URL(request.url).origin;
}

function makeSession(env, user, origin) {
  const sessionId = crypto.randomUUID();
  const cross = env.SITE_URL && (!origin || origin.replace(/\/+$/, "") !== (env.SITE_URL || "").replace(/\/+$/, ""));
  const sameSite = cross ? "None" : "Lax";
  const secure = cross ? "; Secure" : "";
  const cookie = `gg_session=${sessionId}; HttpOnly; Path=/; SameSite=${sameSite}${secure}; Max-Age=${60 * 60 * 12}`;
  return new Response(
    `<!doctype html><html><body><script>window.location.href = "/";</script></body></html>`,
    { headers: { "Content-Type": "text/html", "Set-Cookie": cookie } }
  );
}

async function logout(request, env, origin) {
  const sessionId = getSession(request);
  if (sessionId) await env.SESSIONS.delete(`session:${sessionId}`);
  const cross = env.SITE_URL && origin && origin.replace(/\/+$/, "") !== (env.SITE_URL || "").replace(/\/+$/, "");
  const sameSite = cross ? "None" : "Lax";
  const secure = cross ? "; Secure" : "";
  const cookie = `gg_session=; HttpOnly; Path=/; SameSite=${sameSite}${secure}; Max-Age=0`;
  return new Response(`<script>window.location.href = "/";</script>`, {
    headers: { "Content-Type": "text/html", "Set-Cookie": cookie },
  });
}

async function me(request, env) {
  const sessionId = getSession(request);
  if (!sessionId) return json({ authed: false });
  const data = await env.SESSIONS.get(`session:${sessionId}`);
  if (!data) return json({ authed: false });
  const user = JSON.parse(data);
  return json({ authed: true, email: user.email, name: user.name });
}

// ---------- SSO (login desde clientes.shcdigital.net.ar) ----------
// Quién lo emite: el Worker SSO (SHC Digital Clientes) con SHARED_JWT_SECRET.
// Este endpoint valida firma + exp + tenant y abre la sesión interna del panel.
async function ssoLogin(request, env, ctx) {
  const token = new URL(request.url).searchParams.get("token");
  if (!token) return new Response("Falta token", { status: 400, headers: HTML_HEADERS });

  const secret = env.SHARED_JWT_SECRET;
  if (!secret) return new Response("SSO no configurado (falta SHARED_JWT_SECRET)", { status: 503, headers: HTML_HEADERS });

  const payload = await verifyJWT(token, secret);
  if (!payload) return new Response("Token inválido o expirado", { status: 401, headers: HTML_HEADERS });

  // El token debe pertenecer a ESTE panel (claim "tenant" = id del cliente)
  const expected = env.TENANT_ID;
  if (expected && payload.tenant !== expected) {
    return new Response("Cliente no autorizado para este panel", { status: 403, headers: HTML_HEADERS });
  }

  const sessionId = crypto.randomUUID();
  const user = { email: payload.sub || "cliente@local", name: payload.name || payload.sub || "Cliente" };
  await env.SESSIONS.put(`session:${sessionId}`, JSON.stringify(user), { expirationTtl: 60 * 60 * 12 });

  const res = new Response(`<!doctype html><meta charset="utf-8"><script>window.location.href = "/";</script>`, {
    headers: { "Content-Type": "text/html; charset=utf-8", "Set-Cookie": sessionCookie(sessionId) },
  });
  return res;
}

async function verifyJWT(token, secret) {
  try {
    const [h, b, s] = token.split(".");
    if (!h || !b || !s) return null;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const data = enc.encode(`${h}.${b}`);
    const sig = b64urlDecode(s);
    const valid = await crypto.subtle.verify("HMAC", key, sig, data);
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(b)));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

function b64urlDecode(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(s.length / 4) * 4, "=");
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function sessionCookie(sessionId) {
  return `gg_session=${sessionId}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${60 * 60 * 12}`;
}

// ---------- API ----------
async function handleApi(request, env, ctx, url) {
  const sessionId = getSession(request);
  const session = sessionId ? JSON.parse((await env.SESSIONS.get(`session:${sessionId}`)) || "null") : null;
  if (!session) return json({ error: "No autenticado" }, 401);

  const [_, , resource] = url.pathname.split("/");

  if (resource === "recursos" && request.method === "GET") return json(await listRecursos(env));
  if (resource === "recurso" && request.method === "GET") {
    const slug = url.searchParams.get("slug");
    if (!slug) return json({ error: "Falta slug" }, 400);
    return json(await getRecurso(env, slug));
  }
  if (resource === "recurso" && (request.method === "POST" || request.method === "PUT")) {
    const body = await request.json();
    const res = await saveRecurso(env, body);
    return json(res, res.ok ? 200 : 400);
  }
  if (resource === "recurso" && request.method === "DELETE") {
    const body = await request.json();
    const res = await deleteRecurso(env, body);
    return json(res, res.ok ? 200 : 400);
  }
  return json({ error: "Ruta no encontrada" }, 404);
}

// ---------- GitLab API ----------
function glHeaders(env) {
  return { "PRIVATE-TOKEN": env.GITLAB_TOKEN, "Content-Type": "application/json" };
}

async function glFetch(env, path, opts = {}) {
  const url = `https://gitlab.com/api/v4${path}`;
  const res = await fetch(url, { ...opts, headers: { ...glHeaders(env), ...(opts.headers || {}) } });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { ok: res.ok, status: res.status, data };
}

async function listRecursos(env) {
  const path = encodeURIComponent(env.CONTENT_PATH);
  const res = await glFetch(env, `/projects/${env.GITLAB_PROJECT_ID}/repository/tree?path=${path}&ref=${env.DEFAULT_BRANCH}&per_page=100`);
  if (!res.ok) return { error: `GitLab: ${res.data?.message || res.status}` };
  const files = Array.isArray(res.data) ? res.data.filter((f) => f.type === "blob" && f.name.endsWith(".md")) : [];
  const slugify = (name) => name.replace(/\.md$/, "");
  return files.map((f) => ({ name: f.name, slug: slugify(f.name), size: f.size, path: f.path }));
}

async function getRecurso(env, slug) {
  const filePath = `${env.CONTENT_PATH}/${slug}.md`;
  const res = await glFetch(env, `/projects/${env.GITLAB_PROJECT_ID}/repository/files/${encodeURIComponent(filePath)}/raw?ref=${env.DEFAULT_BRANCH}`);
  if (!res.ok) return { error: `GitLab: ${res.data?.message || res.status}` };
  return { slug, content: res.data };
}

async function saveRecurso(env, { slug, content, message }) {
  const filePath = `${env.CONTENT_PATH}/${slug}.md`;
  const existing = await glFetch(env, `/projects/${env.GITLAB_PROJECT_ID}/repository/files/${encodeURIComponent(filePath)}?ref=${env.DEFAULT_BRANCH}`);
  const isUpdate = existing.ok;

  const body = {
    branch: env.DEFAULT_BRANCH,
    content,
    commit_message: message || (isUpdate ? `Actualizar ${slug}.md` : `Crear ${slug}.md`),
  };
  if (isUpdate) body.last_commit_id = existing.data?.last_commit_id;

  const res = await glFetch(env, `/projects/${env.GITLAB_PROJECT_ID}/repository/files/${encodeURIComponent(filePath)}`, {
    method: isUpdate ? "PUT" : "POST",
    body: JSON.stringify(body),
  });
  return { ok: res.ok, message: res.ok ? (isUpdate ? "Actualizado" : "Creado") : `GitLab: ${res.data?.message || res.status}` };
}

async function deleteRecurso(env, { slug, message }) {
  const filePath = `${env.CONTENT_PATH}/${slug}.md`;
  const res = await glFetch(env, `/projects/${env.GITLAB_PROJECT_ID}/repository/files/${encodeURIComponent(filePath)}`, {
    method: "DELETE",
    body: JSON.stringify({ branch: env.DEFAULT_BRANCH, commit_message: message || `Eliminar ${slug}.md` }),
  });
  return { ok: res.ok, message: res.ok ? "Eliminado" : `GitLab: ${res.data?.message || res.status}` };
}

// ---------- Utilidades ----------
function getSession(request) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(/(?:^|;\s*)gg_session=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : null;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

async function pbkdf2(password, salt) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return new Uint8Array(bits);
}

function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function renderAdmin(env, url) {
  const workerBase = url.origin;
  return adminHtml.replaceAll("__WORKER_BASE__", workerBase);
}
