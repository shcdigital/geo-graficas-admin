// geo-graficas-admin · Cloudflare Worker
// Panel de administración de Geo.Gráficas.
// - Login: SSO vía clientes.shcdigital.net.ar (JWT firmado) o local (PBKDF2, hash en el repo)
// - Sesiones en Workers KV
// - CRUD de cuadernillos (.md) contra el repo geo-graficas-web (GitHub API)
// Se sirve en: <admin del cliente> (ruta Cloudflare Workers) y también
// como página estática en GitHub Pages (apuntando a este Worker para la API).

// ---------- Secrets requeridos (wrangler secret put) ----------
// SHARED_JWT_SECRET (idéntico al del Worker SSO de clientes)
// GITHUB_TOKEN (token con scope repo del repo web) / GITHUB_REPO

import adminHtml from "./admin.txt?raw";

const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "X-Robots-Tag": "noindex, nofollow",
};
const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8", ...SECURITY_HEADERS };
const HTML_HEADERS = { "Content-Type": "text/html; charset=utf-8", ...SECURITY_HEADERS };

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
    if (url.pathname === "/auth/sso" && (request.method === "GET" || request.method === "POST")) {
      return await ssoLogin(request, env, ctx);
    }

    if (url.pathname === "/auth/logout" && request.method === "POST") return await logout(request, env, url);
    if (url.pathname === "/auth/me") return corsWrap(await me(request, env), env, origin);

    // Imágenes de portada: se sirven desde el repo geo-graficas-web
    // (public/img/recursos/...) para que el panel muestre la portada real
    // aunque el sitio aún no se haya redesplegado.
    if (url.pathname.startsWith("/img/")) {
      return await serveImagen(request, env, url);
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

function normOrigin(u) {
  return (u || "").replace(/\/+$/, "").toLowerCase();
}

function trustedOrigin(request, url, env) {
  const origin = normOrigin(request.headers.get("Origin"));
  if (!origin) return false;
  return (
    origin === normOrigin(url.origin) ||
    origin === normOrigin(env.PANEL_URL) ||
    origin === normOrigin(env.SITE_URL)
  );
}

function isJsonContent(request) {
  const ct = (request.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase();
  return ct === "application/json";
}

async function logout(request, env, url) {
  if (!trustedOrigin(request, url, env)) return json({ error: "Origen no permitido" }, 403);
  const origin = request.headers.get("Origin") || "";
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
  let token = null;
  if (request.method === "POST") {
    const form = await request.formData().catch(() => null);
    token = form ? form.get("token") : null;
  } else {
    token = new URL(request.url).searchParams.get("token");
  }
  if (!token || typeof token !== "string") return new Response("Falta token", { status: 400, headers: HTML_HEADERS });

  const secret = env.SHARED_JWT_SECRET;
  if (!secret) return new Response("SSO no configurado (falta SHARED_JWT_SECRET)", { status: 503, headers: HTML_HEADERS });

  const payload = await verifyJWT(token, secret);
  if (!payload) return new Response("Token inválido o expirado", { status: 401, headers: HTML_HEADERS });

  // El token debe pertenecer a ESTE panel (claim "tenant" = id del cliente)
  const expected = env.TENANT_ID;
  if (expected && payload.tenant !== expected) {
    return new Response("Cliente no autorizado para este panel", { status: 403, headers: HTML_HEADERS });
  }

  // El token fue firmado para el admin_url del tenant (claim "aud");
  // rechazar si no coincide con la URL pública de ESTE panel.
  const expectedAud = (env.PANEL_URL || new URL(request.url).origin).replace(/\/+$/, "");
  if (expectedAud && payload.aud && payload.aud.replace(/\/+$/, "") !== expectedAud) {
    return new Response("Token no emitido para este panel", { status: 403, headers: HTML_HEADERS });
  }

  // Rechazar tokens emitidos por otro emisor (claim "iss" del issuer SSO)
  if (env.CLIENTES_URL && payload.iss && normOrigin(payload.iss) !== normOrigin(env.CLIENTES_URL)) {
    return new Response("Token no emitido por el SSO", { status: 403, headers: HTML_HEADERS });
  }

  // Consumo único del token (claim "jti"): mitiga replay durante su ventana de validez
  if (payload.jti) {
    const jtiKey = `sso:jti:${payload.jti}`;
    if (await env.SESSIONS.get(jtiKey)) {
      return new Response("Token inválido o expirado", { status: 401, headers: HTML_HEADERS });
    }
    await env.SESSIONS.put(jtiKey, "1", { expirationTtl: 330 });
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
  return `gg_session=${sessionId}; HttpOnly; Path=/; SameSite=Lax; Secure; Max-Age=${60 * 60 * 12}`;
}

// ---------- API ----------
async function handleApi(request, env, ctx, url) {
  if (request.method !== "GET" && (!trustedOrigin(request, url, env) || !isJsonContent(request))) {
    return json({ error: "Origen no permitido" }, 403);
  }
  const sessionId = getSession(request);
  const session = sessionId ? JSON.parse((await env.SESSIONS.get(`session:${sessionId}`)) || "null") : null;
  if (!session) return json({ error: "No autenticado" }, 401);

  const [_, , resource] = url.pathname.split("/");

  if (resource === "recursos" && request.method === "GET") return json(await listRecursos(env));
  if (resource === "recurso" && request.method === "GET") {
    const slug = url.searchParams.get("slug");
    if (!slug) return json({ error: "Falta slug" }, 400);
    if (!validSlug(slug)) return json({ error: "Slug inválido" }, 400);
    return json(await getRecurso(env, slug));
  }
  if (resource === "recurso" && (request.method === "POST" || request.method === "PUT")) {
    const body = await request.json().catch(() => null);
    if (!body || !validSlug(body.slug)) return json({ error: "Slug inválido" }, 400);
    const err = validateRecurso(body);
    if (err) return json({ error: `Contenido inválido: ${err}` }, 400);
    const res = await saveRecurso(env, body);
    return json(res, res.ok ? 200 : 400);
  }
  if (resource === "recurso" && request.method === "DELETE") {
    let body = {};
    try { body = await request.json(); } catch {}
    if (!body || !validSlug(body.slug)) return json({ error: "Slug inválido" }, 400);
    const res = await deleteRecurso(env, body);
    return json(res, res.ok ? 200 : 400);
  }
  if (resource === "imagen" && request.method === "POST") {
    const body = await request.json().catch(() => null);
    if (!body || !validSlug(body.slug) || !body.base64) return json({ error: "Faltan slug o base64" }, 400);
    const ext = String(body.ext || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (!IMG_ALLOWED_EXT.includes(ext)) return json({ error: "Formato de imagen no permitido (png/jpg/webp/gif)" }, 400);
    if (typeof body.base64 !== "string" || body.base64.length > IMG_MAX_BASE64) {
      return json({ error: `Imagen demasiado grande (máximo ${Math.round(IMG_MAX_BASE64 / 1.37 / 1024 / 1024)} MB)` }, 400);
    }
    const res = await uploadImagen(env, { ...body, ext });
    return json(res, res.ok ? 200 : 400);
  }
  if (resource === "imagen" && request.method === "DELETE") {
    const body = await request.json().catch(() => null);
    if (!body || !validSlug(body.slug)) return json({ error: "Falta slug" }, 400);
    const ext = String(body.ext || "").toLowerCase().replace(/[^a-z0-9]/g, "");
    if (ext && !IMG_ALLOWED_EXT.includes(ext)) return json({ error: "Formato inválido" }, 400);
    const res = await deleteImagen(env, { slug: body.slug, ext });
    return json(res, res.ok ? 200 : 400);
  }
  if (resource === "prices" && request.method === "GET") return json(await getPrices(env));
  if (resource === "prices" && request.method === "PUT") {
    const body = await request.json().catch(() => null);
    if (!body || typeof body.categories !== "object" || body.categories === null || Array.isArray(body.categories)) {
      return json({ error: "Falta categorías" }, 400);
    }
    const err = validatePrices(body.categories);
    if (err) return json({ error: `Precios inválidos: ${err}` }, 400);
    const res = await savePrices(env, body.categories);
    return json(res, res.ok ? 200 : 400);
  }
  if (resource === "materias" && request.method === "GET") return json(await getMaterias(env));
  if (resource === "mensaje" && request.method === "POST") {
    const body = await request.json().catch(() => null);
    const res = await sendMensaje(env, session, body);
    return json(res, res.ok ? 200 : 400);
  }
  return json({ error: "Ruta no encontrada" }, 404);
}

// ---------- GitHub API ----------
// El contenido (cuadernillos, imágenes, precios, materias) vive en el repo
// geo-graficas-web (GitHub). Se usa GITHUB_TOKEN (scope repo) para escribir.
function ghRepo(env) {
  return env.GITHUB_REPO || "shcdigital/geo-graficas-web";
}

function ghHeaders(env, extra = {}) {
  const h = { "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json", "User-Agent": "geo-graficas-admin-worker", ...extra };
  if (env.GITHUB_TOKEN) h.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  return h;
}

async function ghFetch(env, path, opts = {}) {
  const url = `https://api.github.com${path}`;
  const res = await fetch(url, { ...opts, headers: ghHeaders(env, opts.headers) });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { ok: res.ok, status: res.status, data };
}

function toBase64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

async function ghContents(env, filePath) {
  return ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(filePath)}?ref=${env.DEFAULT_BRANCH}`);
}

async function ghRaw(env, filePath) {
  return ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(filePath)}?ref=${env.DEFAULT_BRANCH}`, {
    headers: { Accept: "application/vnd.github.raw" },
  });
}

async function listRecursos(env) {
  const path = env.CONTENT_PATH;
  const res = await ghContents(env, path);
  if (!res.ok) return { error: `GitHub: ${res.data?.message || res.status}` };
  const files = Array.isArray(res.data) ? res.data.filter((f) => f.type === "file" && f.name.endsWith(".md")) : [];
  const slugify = (name) => name.replace(/\.md$/, "");
  return files.map((f) => ({ name: f.name, slug: slugify(f.name), size: f.size, path: f.path }));
}

async function getRecurso(env, slug) {
  const filePath = `${env.CONTENT_PATH}/${slug}.md`;
  const res = await ghRaw(env, filePath);
  if (!res.ok) return { error: `GitHub: ${res.data?.message || res.status}` };
  return { slug, content: res.data };
}

async function saveRecurso(env, { slug, content, message }) {
  const filePath = `${env.CONTENT_PATH}/${slug}.md`;
  const existing = await ghContents(env, filePath);
  const isUpdate = existing.ok && existing.data?.sha;

  const body = {
    message: message || (isUpdate ? `Actualizar ${slug}.md` : `Crear ${slug}.md`),
    content: toBase64(content),
    branch: env.DEFAULT_BRANCH,
  };
  if (isUpdate) body.sha = existing.data.sha;

  const res = await ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(filePath)}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
  return { ok: res.ok, message: res.ok ? (isUpdate ? "Actualizado" : "Creado") : `GitHub: ${res.data?.message || res.status}` };
}

const IMG_ALLOWED_EXT = ["png", "jpg", "jpeg", "webp", "gif"];

const RECURSO_MAX_CHARS = 200_000;
const IMG_MAX_BASE64 = 4_000_000;
const PRICES_MAX_ENTRIES = 60;
const PRICES_MAX_VALUE = 1_000_000;
const MENSAJE_MAX_ASUNTO = 200;
const MENSAJE_MAX_TEXT = 5_000;

function validateRecurso(body) {
  if (typeof body.content !== "string" || !body.content.trim()) return "contenido requerido";
  if (body.content.length > RECURSO_MAX_CHARS) return `contenido demasiado grande (máximo ${RECURSO_MAX_CHARS} caracteres)`;
  if (body.message !== undefined && (typeof body.message !== "string" || body.message.length > 200)) return "mensaje de commit inválido (máximo 200 caracteres)";
  return null;
}

function validatePrices(categories) {
  const keys = Object.keys(categories);
  if (keys.length === 0) return "categories vacío";
  if (keys.length > PRICES_MAX_ENTRIES) return `máximo ${PRICES_MAX_ENTRIES} entradas`;
  for (const k of keys) {
    const v = categories[k];
    if (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > PRICES_MAX_VALUE) return `"${k}" debe ser un número entre 0 y ${PRICES_MAX_VALUE}`;
  }
  return null;
}

async function uploadImagen(env, { slug, ext, base64, message }) {
  const imagePath = `${env.IMG_PATH}/${slug}.${ext}`;
  const existing = await ghContents(env, imagePath);
  const isUpdate = existing.ok && existing.data?.sha;

  const body = {
    message: message || (isUpdate ? `Actualizar imagen ${slug}.${ext}` : `Crear imagen ${slug}.${ext}`),
    content: base64,
    branch: env.DEFAULT_BRANCH,
  };
  if (isUpdate) body.sha = existing.data.sha;

  const res = await ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(imagePath)}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
  return {
    ok: res.ok,
    path: imagePath,
    message: res.ok ? (isUpdate ? "Imagen actualizada" : "Imagen subida") : `GitHub: ${res.data?.message || res.status}`,
  };
}

async function deleteImagen(env, { slug, ext }) {
  const rel = ext
    ? `${env.IMG_PATH.replace(/^\/+/, "")}/${slug}.${ext}`
    : `${env.IMG_PATH.replace(/^\/+/, "")}/${slug}`;
  const imagePath = rel.replace(/^\/+/, "");
  const existing = await ghContents(env, imagePath);
  if (!existing.ok || !existing.data?.sha) return { ok: false, message: "Imagen no encontrada" };
  const res = await ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(imagePath)}`, {
    method: "DELETE",
    body: JSON.stringify({ message: `Eliminar imagen de ${slug}`, sha: existing.data.sha, branch: env.DEFAULT_BRANCH }),
  });
  return { ok: res.ok, message: res.ok ? "Imagen eliminada" : `GitHub: ${res.data?.message || res.status}` };
}

async function deleteRecurso(env, { slug, message }) {
  const filePath = `${env.CONTENT_PATH}/${slug}.md`;
  const md = await ghRaw(env, filePath);
  if (md.ok && typeof md.data === "string") {
    const m = md.data.match(/^imagen:\s*["']?([^"'\n]+)["']?\s*$/m);
    if (m) {
      const imgRel = m[1].replace(/^\/+/, "");
      const imgPath = decodeURIComponent(imgRel);
      const imgExisting = await ghContents(env, imgPath);
      if (imgExisting.ok && imgExisting.data?.sha) {
        await ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(imgPath)}`, {
          method: "DELETE",
          body: JSON.stringify({ message: `Eliminar imagen de ${slug}`, sha: imgExisting.data.sha, branch: env.DEFAULT_BRANCH }),
        });
      }
    }
  }
  const existing = await ghContents(env, filePath);
  if (!existing.ok || !existing.data?.sha) return { ok: false, message: "Recurso no encontrado" };
  const res = await ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(filePath)}`, {
    method: "DELETE",
    body: JSON.stringify({ message: message || `Eliminar ${slug}.md`, sha: existing.data.sha, branch: env.DEFAULT_BRANCH }),
  });
  return { ok: res.ok, message: res.ok ? "Eliminado" : `GitHub: ${res.data?.message || res.status}` };
}

// ---------- Imágenes de portada (proxy al repo) ----------
// Sirve /img/recursos/<archivo> leyendo el archivo real del repo
// geo-graficas-web (public/img/recursos/...), para que la vista previa del
// editor y el listado muestren la portada publicada en el sitio.
const IMG_MIME = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  webp: "image/webp",
  gif: "image/gif",
};

async function serveImagen(request, env, url) {
  const sessionId = getSession(request);
  const session = sessionId ? JSON.parse((await env.SESSIONS.get(`session:${sessionId}`)) || "null") : null;
  if (!session) return new Response("No autenticado", { status: 401 });

  const rel = url.pathname.replace(/^\/+/, "");
  const name = rel.split("/").pop();
  const ext = (name.split(".").pop() || "").toLowerCase();
  const mime = IMG_MIME[ext];
  if (!mime) return new Response("Not found", { status: 404 });

  const imagePath = `${env.IMG_PATH.replace(/\/+$/, "")}/${name}`;
  const url2 = `https://raw.githubusercontent.com/${ghRepo(env)}/${env.DEFAULT_BRANCH}/${imagePath}`;
  const res = await fetch(url2, env.GITHUB_TOKEN ? { headers: { Authorization: `Bearer ${env.GITHUB_TOKEN}` } } : {});
  if (!res.ok) return new Response("Not found", { status: 404 });

  return new Response(res.body, {
    headers: {
      "Content-Type": mime,
      "Cache-Control": "public, max-age=300",
    },
  });
}

// ---------- Precios (repo geo-graficas-web, archivo canónico) ----------
// El archivo de precios vive en geo-graficas-web (src/data/prices.json) y es
// la fuente única de verdad: la web lo muestra, el worker pay lo toma al
// desplegar y acá se edita. Se usa el mismo GITHUB_TOKEN del repo web.
function pricesFilePath(env) {
  return env.PRICES_PATH || "src/data/prices.json";
}

function validPrices(categories) {
  const out = {};
  for (const [k, v] of Object.entries(categories)) {
    const key = String(k);
    if (!/^Cat-[A-Z]$/.test(key)) return null;
    const num = Number(v);
    if (!Number.isFinite(num) || num < 0) return null;
    out[key] = Math.round(num);
  }
  return Object.keys(out).length ? out : null;
}

async function getPrices(env) {
  const filePath = pricesFilePath(env);
  const res = await ghRaw(env, filePath);
  if (!res.ok) return { error: `GitHub: ${res.data?.message || res.status}` };
  const parsed = typeof res.data === "string" ? safeJson(res.data) : res.data;
  if (!parsed || typeof parsed.categories !== "object" || parsed.categories === null) {
    return { error: "Estructura inesperada en el archivo de precios" };
  }
  return { categories: parsed.categories };
}

function safeJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

// ---------- Materias (repo geo-graficas-web, archivo canónico) ----------
// La lista de materias vive en geo-graficas-web (src/data/materias.json) y es
// la fuente única de verdad: la web la usa para el filtro y la portada, y acá
// alimenta el desplegable del editor. Se lee con el mismo GITHUB_TOKEN.
function materiasFilePath(env) {
  return env.MATERIAS_PATH || "src/data/materias.json";
}

async function getMaterias(env) {
  const filePath = materiasFilePath(env);
  const res = await ghRaw(env, filePath);
  if (!res.ok) return { error: `GitHub: ${res.data?.message || res.status}` };
  const parsed = typeof res.data === "string" ? safeJson(res.data) : res.data;
  if (!parsed || !Array.isArray(parsed.materias)) {
    return { error: "Estructura inesperada en el archivo de materias" };
  }
  const materias = parsed.materias
    .filter((m) => m && typeof m.materia === "string" && typeof m.emoji === "string")
    .map((m) => ({ materia: m.materia, emoji: m.emoji }));
  return { materias };
}

async function savePrices(env, categories) {
  const clean = validPrices(categories);
  if (!clean) {
    return { ok: false, message: "Datos de precios inválidos (solo Cat-A..Cat-J con precios numéricos >= 0)" };
  }
  const filePath = pricesFilePath(env);
  const existing = await ghContents(env, filePath);
  const isUpdate = existing.ok && existing.data?.sha;
  const body = {
    message: isUpdate ? "Actualizar precios desde panel" : "Crear archivo de precios desde panel",
    content: toBase64(JSON.stringify({ categories: clean }, null, 2) + "\n"),
    branch: env.DEFAULT_BRANCH,
  };
  if (isUpdate) body.sha = existing.data.sha;
  const res = await ghFetch(env, `/repos/${ghRepo(env)}/contents/${encodeURIComponent(filePath)}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
  return { ok: res.ok, message: res.ok ? "Precios actualizados" : `GitHub: ${res.data?.message || res.status}` };
}

// ---------- Mensaje al administrador (delegado al worker geo-graficas-pay) ----------
// El worker pay ya tiene el secret RESEND_API_KEY; este worker solo le pide
// que mande el mail, sin duplicar la key en el panel.
async function sendMensaje(env, session, body) {
  const asunto = String((body && body.asunto) || "").trim();
  const mensaje = String((body && body.mensaje) || "").trim();
  if (!asunto || !mensaje) return { ok: false, message: "Faltan asunto y mensaje" };
  if (asunto.length > MENSAJE_MAX_ASUNTO) return { ok: false, message: "Asunto demasiado largo" };
  if (mensaje.length > MENSAJE_MAX_TEXT) return { ok: false, message: "Mensaje demasiado largo" };

  const to = env.ADMIN_EMAIL || "shcdigitalsolutions@gmail.com";
  const payUrl = (env.PAY_URL || "https://geo-graficas-pay.pablo-berthold.workers.dev").replace(/\/+$/, "");
  const cliente = session && (session.name || session.email)
    ? `${session.name || "Cliente"} <${session.email || ""}>`
    : "Sin sesión";
  const text = `${mensaje}\n\n— Enviado desde el panel de administración de Geo.Gráficas\n• Cliente: ${cliente}\n• Sitio: ${env.SITE_URL || ""}`;

  if (!env.EMAIL_TOKEN) return { ok: false, message: "EMAIL_TOKEN no configurado" };

  const res = await fetch(`${payUrl}/email`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${env.EMAIL_TOKEN}`,
    },
    body: JSON.stringify({
      to,
      subject: `[Panel Geo.Gráficas] ${asunto}`,
      text,
    }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) return { ok: false, message: data.error || `Pay: ${res.status}` };
  return { ok: true, message: data.message || "Enviado" };
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

const SLUG_RE = /^[a-z0-9-]{1,80}$/;
function validSlug(s) {
  return typeof s === "string" && SLUG_RE.test(s);
}



function renderAdmin(env, url) {
  const workerBase = url.origin;
  return adminHtml
    .replaceAll("__WORKER_BASE__", workerBase)
    .replaceAll("__SITE_URL__", env.SITE_URL || "")
    .replaceAll("__CLIENTES_URL__", env.CLIENTES_URL || "");
}
