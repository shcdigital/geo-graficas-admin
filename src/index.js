// geo-graficas-admin · Cloudflare Worker
// Panel de administración de Geo.Gráficas.
// - Login: Google OAuth2 (secrets) o local usuario/contraseña (PBKDF2, hash en el repo)
// - Sesiones en Workers KV
// - CRUD de cuadernillos (.md) contra la API de GitLab
// Se sirve en: admin.<tu-dominio>.com.ar (ruta Cloudflare Workers) y también
// como página estática en GitLab Pages (apuntando a este Worker para la API).

// ---------- Secrets requeridos (wrangler secret put) ----------
// GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET / GOOGLE_REDIRECT_URI
// GITLAB_TOKEN (token de proyecto con scope api) / GITLAB_PROJECT_ID

// Login local: hash PBKDF2-SHA256 (100000 iter) de la contraseña + salt.
// SOLO está el hash, nunca la contraseña en claro.
const LOCAL_USER = "admin";
const LOCAL_SALT_B64 = "j+fjQHoDnbMq0a5Dlhrj6A==";
const LOCAL_HASH_B64 = "UDJaznYt9Pv/+8Zbo1VzWhJ7xQVC0kX0uk6t0TxAZz0=";

import adminHtml from "./admin.html?raw";

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };
const HTML_HEADERS = { "Content-Type": "text/html; charset=utf-8" };
const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO = "https://www.googleapis.com/oauth2/v3/userinfo";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(env, origin) });
    }

    // Panel admin (SPA) en la raíz
    if (url.pathname === "/" || url.pathname === "/admin") {
      return new Response(renderAdmin(env, url), HTML_HEADERS);
    }

    // OAuth Google
    if (url.pathname === "/auth/login") return await redirectGoogle(env);
    if (url.pathname === "/auth/callback") return await handleCallback(request, env, ctx);
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
async function redirectGoogle(env) {
  const state = crypto.randomUUID();
  await env.SESSIONS.put(`state:${state}`, "1", { expirationTtl: 600 });
  const params = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID,
    redirect_uri: env.GOOGLE_REDIRECT_URI,
    response_type: "code",
    scope: "openid email profile",
    state,
    prompt: "select_account",
  });
  return Response.redirect(`${GOOGLE_AUTH}?${params}`, 302);
}

async function handleCallback(request, env, ctx) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const stored = await env.SESSIONS.get(`state:${state}`);
  if (!code || !stored) return new Response("Login inválido (state). Volvé a intentar.", { status: 400 });
  await env.SESSIONS.delete(`state:${state}`);

  const tokenResp = await fetch(GOOGLE_TOKEN, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      code,
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      redirect_uri: env.GOOGLE_REDIRECT_URI,
      grant_type: "authorization_code",
    }),
  });
  if (!tokenResp.ok) return new Response("Error obteniendo token de Google.", { status: 502 });
  const tokenData = await tokenResp.json();

  const userResp = await fetch(GOOGLE_USERINFO, { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
  const user = await userResp.json();

  const allowed = (env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase());
  if (!allowed.includes((user.email || "").toLowerCase())) {
    return new Response("Tu correo no tiene permiso para acceder al panel.", { status: 403 });
  }
  return makeSession(env, { email: user.email, name: user.name || user.email }, originOf(request));
}

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

  const base64 = btoa(unescape(encodeURIComponent(content)));
  const body = {
    branch: env.DEFAULT_BRANCH,
    content: base64,
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
