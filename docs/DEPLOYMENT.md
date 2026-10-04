# Despliegue

**Opción recomendada (la más barata): 1 VPS (~5–8 €/mes) + Docker Compose + Caddy (HTTPS automático) + SQLite en volumen + cron.** No hace falta Kubernetes ni base de datos gestionada hasta unos 1.000 usuarios.

> No despliegues públicamente hasta tener: dominio propio, `SECRET_KEY`, SMTP real, textos legales revisados y `/.well-known/security.txt`.

## 1. Variables de entorno

Ver `.env.example`. Las imprescindibles en producción son:

| Variable | Valor |
|---|---|
| `APP_ENV` | `production` (obliga a definir `SECRET_KEY`) |
| `SECRET_KEY` | `python -c "import secrets;print(secrets.token_urlsafe(48))"`. Si se cambia, se invalidan los hashes de IP (no afecta a las sesiones) |
| `BASE_URL` | `https://tudominio.com` |
| `COOKIE_SECURE` | `1` |
| `DATABASE_URL` | `sqlite:////data/app.db` o `postgresql+psycopg://...` (añadir `psycopg[binary]` a requirements) |
| `EMAIL_BACKEND` | `smtp` + `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `EMAIL_FROM` (Brevo, Resend, Postmark, SES…) |
| `CONTACT_EMAIL` | email que verán los clientes |
| `TRUST_PROXY` | `1` detrás de Caddy/Nginx (para la IP real en el rate limit) |
| `SCANNER_USER_AGENT` | incluye una URL tuya que explique el bot |
| `BILLING_PROVIDER` | `none` (alta manual) o `stripe` (cuando se implemente; necesita `STRIPE_SECRET_KEY` y `STRIPE_WEBHOOK_SECRET`) |

**Secretos:** solo en `.env` en el servidor (permisos 600) o en el gestor de secretos del proveedor. **Nunca en git.**

## 2. Local

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m app.cli seed-demo           # crea la organización DEMO e imprime su login
uvicorn app.main:app --reload         # http://localhost:8000
pytest -q                             # tests
```

## 3. Producción con Docker Compose

```bash
cp .env.example .env && nano .env     # rellena los valores
# en deploy/Caddyfile, sustituye tudominio.com
docker compose up -d --build
docker compose exec app python -m app.cli seed-demo     # opcional
docker compose exec app python -m app.cli make-admin tu@email.com   # tras registrarte
```

`docker-compose.yml` arranca:
- `app`: uvicorn con 1 worker (el rate limiter y el pool de análisis viven en el proceso; escala verticalmente con `SCAN_WORKERS`);
- `caddy`: TLS automático con Let's Encrypt y proxy inverso;
- `cron`: `monitor` cada hora y `purge` a diario (comparte imagen y volumen).

Alternativa sin cron: `MONITOR_IN_PROCESS=1` lanza un hilo de vigilancia dentro de `app`.

## 4. Base de datos y migraciones

- El esquema se crea al arrancar (`create_all`). Es idempotente.
- **Antes del primer cambio de esquema con datos reales**, añade Alembic (`alembic init`, `target_metadata = Base.metadata`) y genera la migración base.
- SQLite en modo WAL aguanta de sobra la carga prevista. Se pasa a Postgres al ir a más de 1 instancia.

## 5. Copias de seguridad

- **SQLite:** `sqlite3 /data/app.db ".backup '/backups/app-$(date +%F).db'"` diario por cron, y copia fuera del servidor (Backblaze B2, S3 o Hetzner Storage Box, por unos céntimos al mes). O mejor, **Litestream** para replicación continua a S3.
- Prueba la restauración una vez al mes.
- **Postgres gestionado:** copias del proveedor + `pg_dump` semanal fuera.

## 6. Observabilidad

- `GET /healthz` → `{"status":"ok"}` o 503 si la BD falla. Conéctalo a un monitor gratuito (UptimeRobot, Better Stack).
- Logs JSON a stdout (`docker compose logs app`): eventos `scan_started|completed|failed`, `login`, `login_failed`, `domain_added`, etc.
- `/admin` (usuarios con `is_admin`) muestra métricas de negocio y técnicas: tasa de éxito, p50/p95 de duración y fallos por causa.

## 7. Stripe (cuando tengas cuenta)

1. Crea Products/Prices para Pro, Business y Agency.
2. Implementa `StripeBilling.checkout_url` (Checkout Session `mode=subscription`, `client_reference_id=org.id`).
3. Añade `POST /billing/webhook` que verifique la firma con `STRIPE_WEBHOOK_SECRET` y llame a `billing.apply_subscription` en `checkout.session.completed` / `customer.subscription.updated|deleted`.
4. Mientras tanto: alta manual con `python -m app.cli set-plan EMAIL PLAN --months N`.

## 8. Checklist de lanzamiento

- [ ] `APP_ENV=production`, `SECRET_KEY`, `COOKIE_SECURE=1`, `TRUST_PROXY=1`
- [ ] `EMAIL_BACKEND=smtp` probado (reset de contraseña)
- [ ] SPF, DKIM y DMARC del dominio emisor configurados (¡nuestro propio producto debe sacar A!)
- [ ] `python -m app.cli scan tudominio.com` → nota A
- [ ] Textos legales revisados; datos del responsable del tratamiento
- [ ] `security.txt` publicado
- [ ] Copias automáticas + restauración probada
- [ ] Monitor de `/healthz`
