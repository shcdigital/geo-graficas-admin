# Geo.Gráficas — Panel de administración

Panel de administración de Geo.Gráficas servido por un **Cloudflare Worker**
(en el dominio `panel.geograficas.shcdigital.net.ar`) y también como copia
estática en GitHub Pages. Permite:

- **CRUD de cuadernillos** (`.md`) directamente contra el repo `geo-graficas-web`
  vía GitHub API; el workflow de Pages republica automáticamente.
- **Editor de precios**: card "Precios por categoría" que lee/escribe
  `src/data/prices.json` del repo `geo-graficas-web` (fuente única; el worker
  `geo-graficas-pay` la baja al desplegar).
- **Dropdown de materia con emoji** en el formulario de edición: el campo
  Materia es un desplegable alimentado por `src/data/materias.json` del repo
  web. Al elegir una materia se autocompleta el emoji de portada.
- **Dropdown de categoría con precio** en el formulario de edición (ej.
  `Cat-B · $4.500`).
- **Enviar mensaje al administrador**: botón en el panel principal → formulario
  Asunto + Mensaje que envía un correo vía **Resend** a `ADMIN_EMAIL`. El envío
  lo hace el worker `geo-graficas-pay` (`POST /email`), que ya posee la
  `RESEND_API_KEY`; este panel no guarda la key.

## Cómo funciona

```
[clientes.shcdigital.net.ar]   (Worker SSO de SHC Digital — repo web)
      │  login → JWT firmado (SHARED_JWT_SECRET)
      ▼
[este Worker /auth/sso]  ── sesión KV + cookie (SameSite=None; Secure)
      ▼
 Cloudflare Worker ──GitHub API──▶  repo geo-graficas-web  (cuadernillos .md)
                         ──GitHub API──▶  repo geo-graficas-web (precios, materias)
```

- **Frontend** (catálogo) sigue 100% en GitHub Pages, intacto.
- Login por **SSO** (JWT de `clientes.shcdigital.net.ar`) o **local**
  (`admin`/`admin123`, hash PBKDF2-SHA256 en el código; cambiar
  `LOCAL_SALT_B64`/`LOCAL_HASH_B64`).
- Cada guardado/borrado hace un commit a GitHub que dispara el workflow Pages.

## Configuración

### 1. Crear el Worker local

```bash
npm i -D wrangler
npx wrangler login
npx wrangler kv namespace create SESSIONS   # copiar id a wrangler.toml
```

### 2. Secrets

```bash
npx wrangler secret put SHARED_JWT_SECRET   # idéntico al del SSO de clientes
npx wrangler secret put GITHUB_TOKEN        # token scope repo del repo web (shcdigital)
npx wrangler secret put EMAIL_TOKEN         # compartido con geo-graficas-pay
```

> `GITHUB_TOKEN` es el que escribe los commits de contenido en el repo web
> (cuadernillos, imágenes, precios, materias). Debe tener scope `repo` sobre
> `shcdigital/geo-graficas-web`. La `RESEND_API_KEY` (para el botón "Enviar
> mensaje") **no** se define acá: el panel delega el envío al worker
> `geo-graficas-pay` (ruta `POST /email`), que ya la tiene como secret y valida
> el `EMAIL_TOKEN` compartido.

### 3. Vars en `wrangler.toml`

- `SITE_URL`: dominio público del sitio (botón "Ver sitio").
- `CLIENTES_URL`: base del panel de clientes/SSO.
- `TENANT_ID` / `ADMIN_EMAILS`: tenant y emails con acceso.
- `GITHUB_REPO`: repo web con el contenido (ej. `shcdigital/geo-graficas-web`).
- `PANEL_URL`: URL pública del panel; debe coincidir con el `aud` que firma el
  SSO (`https://panel.geograficas.shcdigital.net.ar`).
- `PRICES_PATH` / `MATERIAS_PATH`: rutas de precios y materias en el repo web
  (defaults `src/data/prices.json` / `src/data/materias.json`).
- `ADMIN_EMAIL`: destinatario del botón "Enviar mensaje" (default
  `shcdigitalsolutions@gmail.com`).
- `PAY_URL`: URL del worker `geo-graficas-pay` (default
  `https://geo-graficas-pay.pablo-berthold.workers.dev`); es quien envía el mail
  con su `RESEND_API_KEY`.
- `CONTENT_PATH` / `IMG_PATH` / `DEFAULT_BRANCH`: rutas de los `.md` e imágenes.

### 4. Deploy

```bash
npm run deploy        # wrangler deploy manual
```

**Deploy automático:** el workflow de GitHub (`.github/workflows/deploy.yml`)
corre `wrangler deploy` con cada push a `main`, usando el secret de Actions
`CLOUDFLARE_API_TOKEN` (Settings → Secrets and variables → Actions). El
`account_id` está fijado en `wrangler.toml` para que el CI despliegue sin
credenciales OAuth locales.

## Copia estática en GitHub Pages

`.github/workflows/deploy.yml` (job `pages`) genera `public/index.html` a partir
de `src/admin.txt` reemplazando tokens vía `sed`, y publica con
`actions/deploy-pages`. Las URLs (worker, sitio, SSO) van hardcodeadas en el
workflow; para otro cliente hay que editarlas ahí.

## Inyección de tokens

El SPA (`src/admin.txt`) usa placeholders que el Worker reemplaza al servir
(`renderAdmin` en `src/index.js`) y que el workflow Pages reemplaza vía `sed`:

- `__WORKER_BASE__` → origen del Worker (API).
- `__SITE_URL__` → botón "Ver sitio".
- `__CLIENTES_URL__` → botón "← Panel de clientes".

## Migración de cuenta / replicación para otro cliente

Ver [`docs/MIGRACION-CUENTA.md`](../geo-graficas-web/docs/MIGRACION-CUENTA.md)
— lista las variables por repo para cambiar de namespace GitHub o clonar el
sistema para otro cliente.

## Seguridad

Nunca commitear secretos. Todos los tokens se gestionan con
`npx wrangler secret put`.
