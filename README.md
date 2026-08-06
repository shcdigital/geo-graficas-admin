# Geo.Gráficas — Panel de administración

Panel de administración del sitio Geo.Gráficas con **autenticación de Google**,
servido por un **Cloudflare Worker** (plan gratuito). Permite crear, editar y
borrar cuadernillos (`.md`) directamente contra el repo de GitLab, y GitLab
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
- Solo el **panel admin** vive en el Worker en el subdominio `admin.*`.
- Login restringido a los emails definidos en `ADMIN_EMAILS`.
- Cada guardado/borrado hace un commit a GitLab que dispara el pipeline Pages.

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