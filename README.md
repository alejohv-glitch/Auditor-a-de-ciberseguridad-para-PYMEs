# Seclara: postura de seguridad externa y correo para pymes

> Nombre de trabajo; se cambia con `APP_NAME`. Ver propuestas de marca en [docs/BUSINESS_PLAN.md](docs/BUSINESS_PLAN.md#marca-10-propuestas).

**Qué hace en una frase:** analiza de forma **pasiva y autorizada** lo que cualquiera puede ver de un dominio (correo SPF/DKIM/DMARC, HTTPS, certificado, cabeceras, cookies, DNS, exposición). Genera un **informe en español o inglés** que dice qué falla, por qué le importa al negocio y cómo arreglarlo, y **vigila** el dominio para avisar si algo empeora.

> Evaluación automatizada de controles de seguridad públicamente observables. No es una auditoría completa ni un pentest y no garantiza la ausencia de vulnerabilidades.

## Empieza aquí
| Documento | Contenido |
|---|---|
| [docs/EXECUTIVE_SUMMARY.md](docs/EXECUTIVE_SUMMARY.md) | **Resumen final**: qué se ha construido, quién paga, costes, cómo cobrar, primeros clientes, riesgos y siguientes pasos |
| [docs/MARKET_RESEARCH.md](docs/MARKET_RESEARCH.md) | Competencia, precios, demanda, diferenciación (con fuentes) |
| [docs/BUSINESS_PLAN.md](docs/BUSINESS_PLAN.md) | Nicho, propuesta de valor, precios, costes, MoSCoW, marcas, riesgos |
| [docs/ACQUISITION_PLAN.md](docs/ACQUISITION_PLAN.md) | Plan para 10 leads → 3 → 10 clientes, plantillas de outreach, reglas LSSI/RGPD |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Arquitectura y modelo de datos |
| [docs/SCORING.md](docs/SCORING.md) | Metodología de severidad y puntuación |
| [docs/SECURITY.md](docs/SECURITY.md) | Uso ético, modelo de amenazas (SSRF, IDOR…), revisión, privacidad |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Variables, Docker, copias, Stripe, checklist de lanzamiento |
| [docs/sample-report-es.html](docs/sample-report-es.html) / [en](docs/sample-report-en.html) | Informe de ejemplo (DEMO, datos ficticios) |

## Arranque rápido

```bash
pip install -r requirements-dev.txt
python -m app.cli seed-demo          # organización DEMO (imprime su usuario/contraseña)
uvicorn app.main:app --reload        # http://localhost:8000
pytest -q                            # 135 tests
python -m app.cli scan tudominio.com # análisis desde terminal (solo dominios autorizados)
```

Páginas: `/` (landing + análisis gratuito), `/demo` (informe de ejemplo), `/register`, `/app` (panel), `/admin` (métricas, solo admin).

## Stack
Python 3.11 · FastAPI · Jinja2 (HTML en servidor, sin build de frontend) · SQLAlchemy (SQLite → Postgres) · dnspython · cryptography · argon2. Un único proceso, desplegable en un VPS de unos 5 € con Docker Compose y Caddy.

## Estructura
```
app/
  scanner/   netguard (SSRF), dns, email, tls, web, engine  → RAW FACTS
  rules/     catalog (textos ES/EN), engine                 → FINDINGS
  scoring.py reports.py services.py notify.py billing.py plans.py demo.py cli.py
  web/       rutas, plantillas, CSS
tests/       scanner, reglas, puntuación, app (auth, multi-tenant, CSRF, límites), vigilancia
docs/        negocio + técnica
```

## Comandos de operación
`python -m app.cli monitor` (cron cada hora) · `purge` (diario, retención) · `make-admin EMAIL` · `set-plan EMAIL pro --months 3` (alta manual) · `sample-report out.html`.
