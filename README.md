# Geo.Gráficas — Panel de administración

Panel de administración del sitio Geo.Gráficas con **autenticación de Google**
o **usuario/contraseña local**, servido por un **Cloudflare Worker** (plan
gratuito) y también como página estática en GitLab Pages. Permite crear, editar
y borrar cuadernillos (`.md`) directamente contra el repo de GitLab, y GitLab
Pages vuelve a publicar automáticamente.

## Cómo funciona

```
[admin.<tu-dominio>.com.ar]  (Cloudflare Worker, gratis)
      │  Google OAuth (client secret en el Worker)
      ▼
Cloudflare Worker ──GR GitLab API──▶  repo geo-graficas-web ──pipeline──▶  Pages
   sesiones en KV                          (crear/editar/borrar .md)
```

- El **frontend** (catálogo) sigue 100% en GitLab Pages, intacto.
- El **panel admin** vive en el Worker en el subdominio `admin.*`, con login por
  Google o **usuario/contraseña local** (`admin`/`admin123`, verificado contra
  hash PBKDF2 guardado en el código).
- Login restringido a los emails definidos en `ADMIN_EMAILS`.
- Cada guardado/borrado hace un commit a GitLab que dispara el pipeline Pages.

## Publicar el panel también en GitLab Pages

Además del Worker (que ya sirve el panel en su raíz), podés publicar una copia
estática del panel en GitLab Pages para jugarla incluso si el Worker listo no
está accesible o como respaldo:

1. Configurá la variable de CI `GITLAB_PAGES_WORKER_BASE` con la URL pública del
   Worker (ej: `https://geo-graficas-admin.<subdominio>.workers.dev`).
2. El pipeline `.gitlab-ci.yml` genera `public/index.html` a partir de
   `src/admin.html` reemplazando `__WORKER_BASE__` → el SPA apunta a la API del
   Worker.
3. El panel estático llama al Worker con credenciales (CORS); la cookie de
   sesión se setea `SameSite=None; Secure` para flujos cross-origin.

## Requisitos

1. **Google**: un proyecto OAuth (consola de Google Cloud) con client ID/secret.
2. **Cloudflare**: una cuenta con Workers (plan gratuito) + acceso a los secrets.
3. **GitLab**: un token de proyecto con scope `api` para el repo geo-gráficas-web.

## Configuración

### 1. Crear el Worker local

```bash
npm i -D wrangler
npx wrangler login
npx wrangler kv namespace create SESSIONS
# Copiar el <id> resultante a wrangler.toml (campo id del kv_namespaces)
```

### 2. Setear secrets

```bash
npx wrangler secret put GOOGLE_CLIENT_ID
npx wrangler secret put GOOGLE_CLIENT_SECRET
npx wrangler secret put GOOGLE_REDIRECT_URI   # https://admin.tudominio.com.ar/auth/callback
npx wrangler secret put GITLAB_TOKEN          # token scope api del proyecto
npx wrangler secret put GITLAB_PROJECT_ID      # ej: 85162233
```

### 3. Editar vars en `wrangler.toml`

- `ADMIN_EMAILS`: los emails con acceso (separados por coma).
- `SITE_URL`: la URL del sitio público (para CORS).
- `CONTENT_PATH` / `DEFAULT_BRANCH`: ruta de los `.md` y rama (defaults: `src/content/recursos`, `main`).

### 3b. Login local

El panel acepta también `admin` / `admin123`. El hash PBKDF2-SHA256 (salt y hash
en base64, sin la contraseña en claro) está en `src/index.js`. Para cambiarla,
generá un nuevo hash, por ejemplo con Node:

```bash
node -e '
const {webcrypto:crypto}=require("crypto");
(async()=>{const s=crypto.getRandomValues(new Uint8Array(16));
const k=await crypto.subtle.importKey("raw",new TextEncoder().encode("NUEVA_PASS"),"PBKDF2",false,["deriveBits"]);
const b=await crypto.subtle.deriveBits({name:"PBKDF2",salt:s,iterations:100000,hash:"SHA-256"},k,256);
console.log("SALT="+Buffer.from(s).toString("base64"));
console.log("HASH="+Buffer.from(b).toString("base64"));})()'
```

Copiá esos valores a `LOCAL_SALT_B64` / `LOCAL_HASH_B64` en `src/index.js`.

### 4. Deploy

```bash
npx wrangler deploy
```

## Enrutar el subdominio admin

Cuando tengas el dominio en tu cuenta de Cloudflare:

1. **Dominio en Cloudflare (gratis)**: agregá el dominio como sitio en Cloudflare
   → Cloudflare te da los nameservers → cambiás los nameservers en tu registrador.
2. **Nameserver + registrador**: apuntá el dominio a Cloudflare siguiendo el
   wizard (`Cloudflare → Add site`).
3. **Ruta del Worker**: en Cloudflare Workers → tu Worker → **Routes** → agregá
   `admin.tudominio.com.ar/*` → el Worker se sirve ahí. Cloudflare provee el
   certificado HTTPS gratis y automático.
4. Asegurate de que `GOOGLE_REDIRECT_URI` coincida con `https://admin.tudominio.com.ar/auth/callback` (configurado como URI de redirect válida en el OAuth de Google).

> Sin dominio todavía: se puede probar en la URL temporal del Worker
> `https://geo-graficas-admin.<subdomain>.workers.dev` y setear temporalmente
> `GOOGLE_REDIRECT_URI` a esa URL.

## Posición del repositorio

- Este repo (`geo-graficas-admin`) es solo el Worker. No toca el frontend.
- El frontend (`geo-gradas-web`) sigue en GitLab Pages con su pipeline propio.

## Secretos con datos de producción

⚠ Nunca commitear secretos. Todos los `GOOGLE_*`, `GITLAB_TOKEN`,
`GITLAB_PROJECT_ID` se gestionan con `npx wrangler secret put` (nunca en el repo).