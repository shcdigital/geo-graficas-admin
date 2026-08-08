# AGENTS.md — geo-graficas-admin

## Estado (2026-08-08)

- **Migración GitLab -> GitHub COMPLETA.** Todo el contenido (cuadernillos,
  imágenes, precios, materias) se lee/escribe vía GitHub API en
  `shcdigital/geo-graficas-web` (`GITHUB_TOKEN`, scope repo).
- `wrangler.toml`: `GITHUB_REPO=shcdigital/geo-graficas-web`, `SITE_URL` ->
  `https://shcdigital.github.io/geo-graficas-web`, `PANEL_URL` ->
  `https://panel.geograficas.shcdigital.net.ar`.
- Deploy: `.github/workflows/deploy.yml` (job `deploy-worker` con
  `CLOUDFLARE_API_TOKEN` + job `pages` que genera `index.html` desde
  `src/admin.txt`). Ambos jobs pasan.
- Validado en producción: CRUD recursos, imágenes, precios, materias, mensaje/
  email (EMAIL_TOKEN). Commit de referencia de la migración: `75410b8`.

## Secrets (Cloudflare, `wrangler secret put`)

- `GITHUB_TOKEN` — token scope repo de `shcdigital/geo-graficas-web`.
- `SHARED_JWT_SECRET` — idéntico al Worker SSO de clientes.shcdigital.net.ar.
- `EMAIL_TOKEN` — compartido con geo-graficas-pay (firma `POST /email`).

> `GITLAB_TOKEN`/`GITLAB_PAY_TOKEN` fueron eliminados (ya no se usan).

## Puntos de atención

- El botón "Enviar mensaje" delega a `geo-graficas-pay` (`POST /email`) con
  `Authorization: Bearer EMAIL_TOKEN`; el pay valida en const-time.
- `User-Agent` es obligatorio en `ghHeaders` (GitHub devuelve 403 sin él).
- El worker `geo-graficas-pay` NO es fuente de precios ni materias; los lee del
  repo web (GitHub). Su CI baja `prices.json` de `raw.githubusercontent.com`.
