// geo-graficas-admin · Cloudflare Worker
// Panel de administración de Geo.Gráficas con autenticación de Google.
// - OAuth2 de Google (secrets en wrangler secret)
// - Sesiones en Workers KV
// - CRUD de cuadernillos (.md) contra la API de GitLab
// Se sirve en: admin.<tu-dominio>.com.ar (ruta Cloudflare Workers)

// ---------- Secrets requeridos (wrangler secret put) ----------
// GOOGLE_CLIENT_ID
// GOOGLE_CLIENT_SECRET
// GOOGLE_REDIRECT_URI  (ej: https://admin.midominio.com.ar/auth/callback)
// GITLAB_TOKEN         (token de proyecto con scope api)
// GITLAB_PROJECT_ID    (ej: 85162233)

const JSON_HEADERS = { "Content-Type": "application/json; charset=utf-8" };
const HTML_HEADERS = { "Content-Type": "text/html; charset=utf-8" };
const GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth";
const GOOGLE_TOKEN = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO = "https://www.googleapis.com/oauth2/v3/userinfo";

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // CORS para que el sitio (GitLab Pages) pueda llamar al Worker si hiciera falta
    const cors = (res) => {
      const r = new Response(res.body, res);
      r.headers.set("Access-Control-Allow-Origin", env.SITE_URL || "*");
      r.headers.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
      r.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
      r.headers.set("Access-Control-Allow-Credentials", "true");
      return r;
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*" } });
    }

    // Panel admin (SPA) en la raíz
    if (url.pathname === "/" || url.pathname === "/admin") {
      return new Response(renderAdmin(env), HTML_HEADERS);
    }

    // OAuth
    if (url.pathname === "/auth/login") {
      return redirectGoogle(env, url);
    }
    if (url.pathname === "/auth/callback") {
      return await handleCallback(request, env, ctx);
    }
    if (url.pathname === "/auth/logout") {
      return await logout(request, env);
    }
    if (url.pathname === "/auth/me") {
      return await me(request, env);
    }

    // API de cuadernillos (requiere sesión)
    if (url.pathname.startsWith("/api/")) {
      return cors(await handleApi(request, env, ctx, url));
    }

    return new Response("Not found", { status: 404 });
  },
};

// ---------- Login ----------
function redirectGoogle(env, url) {
  const state = crypto.randomUUID();
  const redirect = `${env.GOOGLE_REDIRECT_URI}?state=${state}`;
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
  if (!code || !stored) {
    return new Response("Login inválido (state). Volvé a intentar.", { status: 400 });
  }
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
  if (!tokenResp.ok) {
    return new Response("Error obteniendo token de Google.", { status: 502 });
  }
  const tokenData = await tokenResp.json();
  const accessToken = tokenData.access_token;

  const userResp = await fetch(GOOGLE_USERINFO, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  const user = await userResp.json();

  const allowed = (env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase());
  if (!allowed.includes((user.email || "").toLowerCase())) {
    return new Response("Tu correo no tiene permiso para acceder al panel.", { status: 403 });
  }

  // Sesión con cookie firmada por KV
  const sessionId = crypto.randomUUID();
  const cookie = `gg_session=${sessionId}; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=${60 * 60 * 12}`;
  await env.SESSIONS.put(`session:${sessionId}`, JSON.stringify({ email: user.email, name: user.name || user.email, at: Date.now() }), { expirationTtl: 60 * 60 * 12 });

  return new Response(`<!doctype html><html><body><script>window.location.href = "/";</script></body></html>`, {
    headers: { "Content-Type": "text/html", "Set-Cookie": cookie },
  });
}

async function logout(request, env) {
  const sessionId = getSession(request);
  if (sessionId) await env.SESSIONS.delete(`session:${sessionId}`);
  const cookie = "gg_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0";
  return new Response(`<script>window.location.href = "/";</script>`, {
    headers: { "Content-Type": "text/html", "Set-Cookie": cookie },
  });
}

async function me(request, env) {
  const sessionId = getSession(request);
  if (!sessionId) return new Response(JSON.stringify({ authed: false }), JSON_HEADERS);
  const data = await env.SESSIONS.get(`session:${sessionId}`);
  if (!data) return new Response(JSON.stringify({ authed: false }), JSON_HEADERS);
  const user = JSON.parse(data);
  return new Response(JSON.stringify({ authed: true, email: user.email, name: user.name }), JSON_HEADERS);
}

// ---------- API ----------
async function handleApi(request, env, ctx, url) {
  const sessionId = getSession(request);
  const session = sessionId ? JSON.parse(await env.SESSIONS.get(`session:${sessionId}`) || "null") : null;
  if (!session) return json({ error: "No autenticado" }, 401);

  const [_, , resource] = url.pathname.split("/");

  if (resource === "recursos" && request.method === "GET") {
    return json(await listRecursos(env), 200);
  }
  if (resource === "recurso" && request.method === "GET") {
    const slug = url.searchParams.get("slug");
    if (!slug) return json({ error: "Falta slug" }, 400);
    return json(await getRecurso(env, slug), 200);
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
  return {
    "PRIVATE-TOKEN": env.GITLAB_TOKEN,
    "Content-Type": "application/json",
  };
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
  // Armar lista con metadatos básicos (nombre, slug, tamaño)
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

// ---------- SPA embebida ----------
function renderAdmin(env) {
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>${env.APP_NAME || "Admin"}</title>
<style>
  :root{
    --brand-start:#f9ce34;--brand-mid:#ee2a7b;--brand-end:#6228d7;
    --gradient:linear-gradient(45deg,#f9ce34 0%,#ee2a7b 50%,#6228d7 100%);
    --surface:#ffffff;--raised:#fafafa;--border:#e5e7eb;--text:#1a1a1a;--muted:#6b7280;
    --green:#16a34a;--red:#dc2626;
    --font:"Inter",system-ui,sans-serif;
    --radius:14px;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:var(--font);color:var(--text);background:var(--raised);-webkit-font-smoothing:antialiased}
  .shc-banner{
    display:flex;align-items:center;justify-content:center;gap:.6rem;padding:clamp(1.1rem,3vw,2rem) 1rem;
    background:#000;color:#fff;font-weight:800;font-size:clamp(1.2rem,5vw,3rem);letter-spacing:.12em;
    text-transform:uppercase;text-align:center;white-space:nowrap;font-family:Arial,sans-serif;
  }
  .shc-banner .dot{color:#f00}
  .wrap{max-width:1100px;margin:0 auto;padding:1.5rem clamp(1rem,4vw,2rem)}
  .top{display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap;margin-bottom:1rem}
  .top h1{background:var(--gradient);-webkit-background-clip:text;background-clip:text;color:transparent;margin:0;font-size:1.6rem}
  .btn{border:none;cursor:pointer;font-family:inherit;font-weight:600;font-size:.9rem;padding:.6rem 1.2rem;border-radius:999px;transition:.15s}
  .btn-primary{background:var(--gradient);color:#fff}
  .btn-ghost{background:#fff;border:1px solid var(--border);color:var(--text)}
  .btn-danger{background:var(--red);color:#fff}
  .btn-sm{padding:.4rem .9rem;font-size:.8rem}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.25rem;margin-bottom:1rem;box-shadow:0 1px 2px rgba(17,24,39,.06)}
  .card h2{margin:0 0 .5rem;font-size:1.05rem}
  .row{display:flex;gap:.75rem;flex-wrap:wrap}
  .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1rem}
  .rec{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1rem;display:flex;flex-direction:column;gap:.4rem}
  .rec .name{font-weight:600;word-break:break-all}
  .rec .meta{font-size:.8rem;color:var(--muted)}
  .rec .acts{display:flex;gap:.5rem;margin-top:.5rem}
  input[type=text],textarea,select{font-family:inherit;font-size:.9rem;padding:.55rem .7rem;border:1px solid var(--border);border-radius:10px;width:100%;margin-top:.25rem}
  label{font-size:.85rem;font-weight:600}
  .field{margin-bottom:.8rem}
  .hidden{display:none}
  .muted{color:var(--muted);font-size:.85rem}
  pre{background:#111;color:#e5e7eb;border-radius:10px;padding:1rem;overflow:auto;font-size:.8rem}
  #msg{position:fixed;bottom:1.2rem;left:50%;transform:translateX(-50%);background:#1a1a1a;color:#fff;padding:.6rem 1.2rem;border-radius:999px;font-weight:500;font-size:.85rem;opacity:0;transition:.2s;pointer-events:none;z-index:50}
  #msg.show{opacity:1}
  textarea{font-family:ui-monospace,Menlo,monospace;min-height:340px}
  .savebar{position:sticky;bottom:0;background:rgba(255,255,255,.92);backdrop-filter:blur(8px);border-top:1px solid var(--border);padding:.8rem 1rem;display:flex;justify-content:space-between;gap:1rem;align-items:center;margin-top:1rem;border-radius:var(--radius)}
  @media(max-width:600px){.savebar{flex-direction:column;align-items:stretch}}
</style>
</head>
<body>
<div class="shc-banner">Coding by&nbsp;SHC<span class="dot">.</span>DIGITAL</div>

<div class="wrap">
  <div class="top">
    <h1>Panel de Geo.Gráficas</h1>
    <div class="row">
      <button class="btn btn-primary hidden" id="btnNuevo">+ Nuevo cuadernillo</button>
      <button class="btn btn-ghost hidden" id="btnCerrar">Cerrar sesión</button>
    </div>
  </div>

  <!-- Login -->
  <div class="card" id="loginCard">
    <h2>Acceso restringido</h2>
    <p class="muted">Ingresá con tu cuenta de Google para administrar los cuadernillos.</p>
    <button class="btn btn-primary" onclick="location.href='/auth/login'">Continuar con Google</button>
  </div>

  <!-- Panel -->
  <div class="hidden" id="panel">
    <p class="muted" id="who"></p>
    <div class="grid" id="lista"></div>
  </div>

  <!-- Editor -->
  <div class="card hidden" id="editor">
    <div class="top" style="margin-bottom:.5rem"><h2 id="edTitle">Nuevo cuadernillo</h2></div>
    <div class="field">
      <label>Slug (nombre de archivo, minúsculas y guiones)</label>
      <input type="text" id="edSlug" placeholder="ej: matematica-funciones" />
    </div>
    <div class="field">
      <label>Contenido (.md completo con frontmatter)</label>
      <textarea id="edContent" placeholder="---&#10;title: ...&#10;description: ...&#10;---&#10;&#10;Contenido"></textarea>
    </div>
    <div class="field">
      <label>Mensaje de commit (opcional)</label>
      <input type="text" id="edMsg" placeholder="ej: Agregar cuadernillo de biología" />
    </div>
    <div class="savebar">
      <span class="muted" id="edInfo"></span>
      <div class="row">
        <button class="btn btn-ghost" id="btnVolver">Volver</button>
        <button class="btn btn-danger hidden" id="btnBorrar">Borrar cuadernillo</button>
        <button class="btn btn-primary" id="btnGuardar">Guardar</button>
      </div>
    </div>
  </div>
</div>

<div id="msg"></div>

<script>
const $=(id)=>document.getElementById(id);
let sesion=null;

async function api(path, opts={}){
  const r=await fetch(path,{...opts,headers:{...((opts.headers)||{}),"Content-Type":"application/json"}});
  const d=await r.json();
  if(!r.ok){throw new Error(d.error||"Error de red");}
  return d;
}
function toast(m){const t=$("msg");t.textContent=m;t.classList.add("show");clearTimeout(t._t);t._t=setTimeout(()=>t.classList.remove("show"),2200);}

async function init(){
  try{sesion=await api("/auth/me");}catch(e){sesion={authed:false};}
  if(sesion.authed){
    $("loginCard").classList.add("hidden");
    $("panel").classList.remove("hidden");
    $("btnNuevo").classList.remove("hidden");
    $("btnCerrar").classList.remove("hidden");
    $("who").textContent="Conectado como "+sesion.email;
    cargar();
  }
}

async function cargar(){
  const data=await api("/api/recursos");
  const el=$("lista");
  if(data.error){el.innerHTML='<p class="muted">Error: '+data.error+'</p>';return;}
  el.innerHTML=(data||[]).map(r=>\`
    <div class="rec">
      <div class="name">\${r.name}</div>
      <div class="meta">\${r.slug} · \${r.size||0} B</div>
      <div class="acts">
        <button class="btn btn-ghost btn-sm" onclick="editar('\${r.slug}')">Editar</button>
        <button class="btn btn-danger btn-sm" onclick="borrarDirecto('\${r.slug}')">Borrar</button>
      </div>
    </div>\`).join("")||'<p class="muted">No hay cuadernillos.</p>';
}

async function editar(slug){
  $("panel").classList.add("hidden");
  $("editor").classList.remove("hidden");
  $("btnBorrar").classList.remove("hidden");
  $("edTitle").textContent="Editar: "+slug;
  $("edInfo").textContent="Editando "+slug+".md";
  $("edSlug").value=slug;
  $("edContent").value="Cargando…";
  const data=await api("/api/recurso?slug="+encodeURIComponent(slug));
  if(data.content!==undefined){$("edContent").value=data.content;}else{$("edContent").value="# Error: "+JSON.stringify(data);}
}
function nuevo(){
  $("panel").classList.add("hidden");
  $("editor").classList.remove("hidden");
  $("btnBorrar").classList.add("hidden");
  $("edTitle").textContent="Nuevo cuadernillo";
  $("edInfo").textContent="Nuevo archivo";
  $("edSlug").value="";$("edContent").value="";$("edMsg").value="";
}
async function guardar(){
  const slug=($("edSlug").value||"").trim().toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/(^-|-$)/g,"");
  const content=$("edContent").value;
  if(!slug||!content){toast("Completá slug y contenido");return;}
  $("btnGuardar").disabled=true;
  try{
    const d=await api("/api/recurso",{method:"POST",body:JSON.stringify({slug,content,message:$("edMsg").value||undefined})});
    toast(d.message||"Guardado");$("btnVolver").click();
  }catch(e){toast(e.message);}finally{$("btnGuardar").disabled=false;}
}
async function borrarDirecto(slug){
  if(!confirm("¿Borrar definitivamente "+slug+".md?"))return;
  try{const d=await api("/api/recurso",{method:"DELETE",body:JSON.stringify({slug})});toast(d.message||"Borrado");cargar();}catch(e){toast(e.message);}
}
async function borrarEditor(){
  const slug=$("edSlug").value;
  if(!slug||!confirm("¿Borrar definitivamente "+slug+".md?"))return;
  $("btnBorrar").disabled=true;
  try{const d=await api("/api/recurso",{method:"DELETE",body:JSON.stringify({slug})});toast(d.message||"Borrado");$("btnVolver").click();}catch(e){toast(e.message);}finally{$("btnBorrar").disabled=false;}
}
function volver(){$("editor").classList.add("hidden");$("panel").classList.remove("hidden");cargar();}

$("btnNuevo").addEventListener("click",nuevo);
$("btnCerrar").addEventListener("click",()=>location.href="/auth/logout");
$("btnGuardar").addEventListener("click",guardar);
$("btnBorrar").addEventListener("click",borrarEditor);
$("btnVolver").addEventListener("click",volver);
init();
</script>
</body>
</html>`;
}
