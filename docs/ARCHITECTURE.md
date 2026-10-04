# Arquitectura

Un único proceso Python (un monolito **modular**, sin microservicios) que se despliega en un solo VPS. Esa es la opción más barata y sencilla que cumple los requisitos.

```
                ┌─────────────────────── app (FastAPI, uvicorn) ───────────────────────┐
 navegador ──►  │ web/        public · auth_routes · dashboard · admin  (Jinja2, sin SPA)│
                │   deps.py   sesión, CSRF, consultas limitadas por tenant              │
                │ services.py crear/ejecutar análisis · cambios · alertas · retención   │
                │   ├─ scanner/   netguard (SSRF) · dns · email · tls · web · engine    │
                │   ├─ rules/     catalog (textos ES/EN) · engine (hechos → hallazgos)  │
                │   ├─ scoring.py hallazgos → puntuación explicable                     │
                │   ├─ reports.py hallazgos → informe localizado (+ Explainer IA opc.)  │
                │   ├─ notify.py  canales: email · webhook · discord · telegram         │
                │   ├─ billing.py manual | stripe (abstracción)                         │
                │   └─ plans.py   límites por plan                                      │
                │ models.py / db.py   SQLAlchemy (SQLite o Postgres)                    │
                └────────────────────────────────────────────────────────────────────────┘
 cron ──► python -m app.cli monitor (cada hora) · purge (diario)
```

## Flujo de datos (la IA nunca es fuente de verdad)

```
SCANNER (consultas pasivas) → RAW FACTS (JSON) → RULE ENGINE (determinista) → FINDINGS
   → SCORING (pesos + topes) → REPORT (plantillas ES/EN) → [Explainer opcional: solo reformula]
```

- Los **raw facts** se guardan tal cual (`scans.raw_facts`). Eso permite re-evaluar con nuevas reglas, auditar cualquier hallazgo y calcular cambios.
- Las **reglas** son funciones puras (`rules/engine.py`) y los textos están separados en `rules/catalog.py`. Para añadir un control basta con añadir el hecho, la regla y el texto, más un test.
- `ANALYSIS_VERSION` y `SCANNER_VERSION` quedan grabados en cada análisis.

## Módulos

| Módulo | Responsabilidad |
|---|---|
| `scanner/netguard.py` | Normalizar y validar dominios, resolver solo IPs públicas, GET con IP fijada (anti DNS rebinding), solo puertos 80/443, redirecciones re-validadas, cuerpo limitado |
| `scanner/dns_checks.py` | A, AAAA, MX, NS, TXT, CAA, SOA, DS, CNAME www |
| `scanner/email_checks.py` | SPF (parseo, «all», conteo recursivo de consultas), DMARC, DKIM (15 selectores comunes en paralelo), MTA-STS, TLS-RPT |
| `scanner/tls_checks.py` | Handshake verificado y no verificado, certificado (x509), sondeo de TLS 1.0/1.1 |
| `scanner/web_checks.py` | ≤3 GET: http://, https://, security.txt. Cabeceras, cookies, tecnologías, detección de bloqueo WAF |
| `scanner/engine.py` | Orquestación y errores tipados (`ScanError`: nxdomain, dns_timeout, unsafe_target) |
| `rules/` | Hallazgos con estado `fail`/`pass`/`unknown`/`na`, severidad, tipo y evidencia |
| `scoring.py` | Ver [SCORING.md](SCORING.md) |
| `services.py` | Pool de hilos para análisis, *sweeper* de análisis colgados, cambios, alertas, vigilancia, retención |
| `web/` | Rutas HTML server-side, sin JS imprescindible (CSP estricta) |

## Base de datos

Tablas: `users`, `organizations`, `memberships`, `sessions`, `password_reset_tokens`, `domains`, `scans`, `findings` (con la **evidencia** en JSON por hallazgo), `score_history`, `subscriptions`, `notification_channels`, `notifications`, `audit_logs`, `leads`.

- Todas las fechas son UTC (`db.utcnow()`).
- Toda fila de tenant lleva `org_id`. Las consultas pasan por `owned_domain`/`owned_scan` y devuelven 404 si no es tuya.
- El borrado es en cascada: organización → dominios → análisis → hallazgos e historial.
- Hoy se usa `create_all` (MVP). **Siguiente paso** antes de cambiar el esquema en producción: Alembic.

## Multi-tenancy y marca blanca

- El modelo es Usuario ↔ Membership ↔ Organization, así que varios usuarios por organización ya están soportados por el esquema (falta la interfaz para invitar).
- `Organization.brand_name`/`brand_color`/`report_lang` y `Domain.client_name` permiten que una agencia gestione varios clientes y genere informes con su marca. Más adelante, un «cliente final» puede ser una sub-organización sin romper nada.

## Concurrencia y escalado

- Los análisis se ejecutan en `ThreadPoolExecutor(SCAN_WORKERS)` dentro del proceso web. La página de estado se refresca cada 3 s y un *sweeper* marca como fallido cualquier análisis de más de 5 minutos.
- La vigilancia la lanza el cron (`app.cli monitor`) de forma secuencial: 1.000 dominios a ~10 s cada uno son menos de 3 h, suficiente con frecuencia diaria.
- El rate limit está en memoria y es correcto con **1 instancia**. Para varias, se cambia `RateLimiter` por Redis (misma interfaz).

## Extensión IA (opcional, no implementada a propósito)

`reports.Explainer.rewrite_summary(summary, findings, lang)` solo recibe hallazgos ya calculados y devuelve un texto. Si se implementa con un LLM:
- no puede añadir ni quitar hallazgos (validar que solo cambia el texto);
- solo se usa en planes de pago y con caché por análisis;
- el texto determinista se mantiene como respaldo.
