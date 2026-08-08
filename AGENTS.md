# AGENTS.md — geo-graficas-admin

## Pendientes (para la próxima sesión)

- **Deploy del fix de seguridad EMAIL_TOKEN (2026-08-07):**
  - Se firmó el POST `pay/email` con `Authorization: Bearer EMAIL_TOKEN`.
  - `sendMensaje` en `src/index.js` exige `env.EMAIL_TOKEN`.
  - `geo-graficas-pay/src/index.ts` valida el token (constante-time) en `handleEmail`.
  - **Acción requerida:** setear el MISMO valor de `EMAIL_TOKEN` como secret en ambos workers:
    - `cd geo-graficas-admin && wrangler secret put EMAIL_TOKEN`
    - `cd geo-graficas-pay && wrangler secret put EMAIL_TOKEN`
  - Luego redeploy de ambos workers.
  - Hasta no hacerlo, el botón "Enviar mensaje" del panel devolverá "EMAIL_TOKEN no configurado".

## Migración GitLab -> GitHub (2026-08-07, en curso)

- Capa de contenido migrada de GitLab API a GitHub API (`ghFetch`/`ghContents`/`ghRaw`, token `GITHUB_TOKEN`).
- `wrangler.toml`: `GITHUB_REPO=shcdigital/geo-graficas-web`, `SITE_URL` -> shcdigital.github.io.
- Validado localmente contra GitHub real: CRUD recursos, imágenes, precios, materias. Commit `75410b8`.
- [OK] Secret `GITHUB_TOKEN` seteado en Cloudflare (admin worker); `GITLAB_TOKEN`/`GITLAB_PAY_TOKEN` eliminados.
- [OK] `EMAIL_TOKEN` generado y seteado en workers admin y pay (mismo valor).
- [OK] `CLOUDFLARE_API_TOKEN` seteado como secret en los 3 repos GitHub; workflow `deploy.yml` pasa (worker + pages).
- [OK] Worker admin deployado desde GitHub Actions y validado en producción contra GitHub API.
