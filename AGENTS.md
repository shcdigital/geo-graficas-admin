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
