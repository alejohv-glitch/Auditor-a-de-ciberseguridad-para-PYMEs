# Seguridad, uso ético y privacidad

## 1. Qué hace y qué NO hace el escáner

**Hace (pasivo):** consultas DNS públicas mediante un resolutor recursivo (unas 40 por análisis), 1 handshake TLS verificado, 1 sin verificar si el certificado falla, hasta 2 sondas breves de TLS 1.0/1.1, y como máximo 3 GET HTTP (`http://`, `https://` y `/.well-known/security.txt`) siguiendo hasta 5 redirecciones. Lleva un User-Agent identificable (`SCANNER_USER_AGENT`).

**No hace:** escaneo de puertos, fuerza bruta, credenciales, crawling, *fuzzing* de rutas, payloads, envío de emails, conexiones SMTP, evasión de WAF o de rate limits, ni nada contra puertos distintos de 80/443.

**Autorización:** para dar de alta un dominio es obligatorio marcar «I confirm that I own or am authorized to assess this domain». Se guardan el usuario, la fecha y el texto (`domains.authorized_*`). Hay además verificación opcional por TXT DNS. El check público también exige la casilla, tiene un límite de 3 por hora e IP y reutiliza el resultado del mismo dominio durante 24 h, para no repetir análisis contra un tercero.

## 2. Modelo de amenazas y controles

| Amenaza | Control | Test |
|---|---|---|
| **SSRF** (usar el escáner como proxy hacia localhost, la red interna o metadatos cloud) | `normalize_domain` rechaza IPs literales, userinfo (`a@b`), puertos, TLDs internos (.local, .internal, .test…). `resolve_public` exige que **todas** las IPs sean globales (bloquea 127/8, 10/8, 172.16/12, 192.168/16, 169.254/16, 100.64/10, IPv6 ULA/link-local, IPv4-mapped). La conexión va a la **IP ya validada** (anti DNS rebinding). Solo 80/443. **Cada redirección se re-valida.** Lectura limitada (512 KB) y timeouts | `test_netguard.py` |
| SSRF vía webhooks de alertas | Solo `https://`, host público validado, sin seguir redirecciones | `test_webhook_channel_ssrf_blocked` |
| IDOR / multi-tenancy | Todo acceso a datos de tenant pasa por `owned_domain`/`owned_scan` filtrando por `org_id`; responde **404** (no 403). Los IDs de análisis son tokens aleatorios de 128 bits | `test_tenant_isolation` |
| Robo de sesión | Token aleatorio de 256 bits; en BD solo su SHA-256. Cookie `HttpOnly`, `SameSite=Lax`, `Secure` (prod). Caduca a los 14 días. Logout invalida en servidor. Un reset de contraseña cierra todas las sesiones | `test_session_cookie_flags`, `test_password_reset_flow` |
| Contraseñas | Argon2id; mínimo 10 caracteres; verificación en tiempo constante (hash ficticio para usuarios inexistentes) | `test_password_is_hashed` |
| Enumeración de usuarios | El mismo error en login y la misma respuesta en «olvidé contraseña» | `test_wrong_password_generic_error`, `test_forgot_unknown_email_same_answer` |
| Fuerza bruta / abuso | Límites: login 20/15 min por IP y 8/15 min por email; registro 5/h por IP; reset 5/h; check público 3/h por IP; análisis manuales por plan y día; 1 re-análisis por dominio cada 2 min | `test_login_rate_limited`, `test_register_rate_limited`, `test_public_check_rate_limit`, `test_manual_scan_rate_limit` |
| CSRF | Token *double-submit* en todos los POST más SameSite=Lax | `test_csrf_required` |
| XSS (también a través de cabeceras o HTML de sitios analizados, que controla un atacante) | Jinja2 con autoescape; CSP `script-src 'self'` sin `unsafe-inline`; estilos inline solo con nonce; el color de marca se valida con `^#[0-9a-f]{6}$` | `test_paid_plan_features`, `test_white_label_brand_color_validated`, `test_security_headers` |
| Clickjacking | `frame-ancestors 'none'` + `X-Frame-Options: DENY` | `test_security_headers` |
| Inyección SQL | Solo ORM o consultas parametrizadas (SQLAlchemy) | — |
| Path traversal / ficheros | No hay subida de ficheros ni rutas a disco basadas en input | — |
| CORS | No hay API cross-origin; sin cabeceras CORS (bloqueado por defecto) | — |
| Fuga de secretos en logs | Logs JSON sin IPs, sin query strings y **con los tokens de reset redactados**; nunca se registran contraseñas, tokens ni URLs de webhooks | `test_reset_token_not_logged` |
| Secretos en el repo | Configuración solo por variables de entorno; `SECRET_KEY` obligatoria en producción; `.env` en `.gitignore` | — |
| DoS del propio servicio | Pool de análisis acotado (`SCAN_WORKERS`), timeouts, *sweeper* de análisis colgados | `test_stuck_scans_are_failed` |

## 3. Revisión de seguridad: resultado y riesgos residuales

Revisado: autenticación, autorización/IDOR, inyección, XSS, CSRF, SSRF, path traversal, ficheros, fuga de secretos, logging, rate limiting, CORS y sesiones. Problemas encontrados **y corregidos** durante la revisión:
1. El token de reset de contraseña aparecía en el log de acceso. Ahora se redacta.
2. Las páginas de bloqueo WAF (403) se evaluaban como si fueran la web real, lo que daba falsos positivos. Ahora se marcan como «no verificado».

**Riesgos residuales aceptados (MVP):**
- **TOCTOU en webhooks:** se valida el host antes del POST, pero `httpx` vuelve a resolver el nombre. Riesgo bajo: requiere un webhook propio con DNS rebinding y solo permite un POST con JSON de alertas. *Mejora:* fijar la IP como en el escáner.
- **Rate limit en memoria:** se reinicia al reiniciar el proceso y no se comparte entre instancias. Aceptable con 1 instancia.
- **Mensajes `?err=` en la URL:** el texto se refleja escapado (no hay XSS), pero un enlace manipulado puede mostrar un texto falso. *Mejora:* códigos de error en vez de texto.
- **Ruta de demo pública `/demo`:** solo muestra datos ficticios generados en memoria.
- **Backend de email `console`** (por defecto en desarrollo): imprime los enlaces de reset en stdout. **En producción debe usarse `EMAIL_BACKEND=smtp`** (está en la checklist de despliegue).

## 4. Privacidad (RGPD)

| Dato | Por qué | Retención | Borrado |
|---|---|---|---|
| Email + hash de contraseña | Cuenta | Mientras exista la cuenta | «Borrar cuenta» (inmediato y en cascada) |
| Dominios, hechos técnicos, hallazgos | El servicio | Según la ventana del plan: 30 días (Free), 365 (Pro), 730 (Business/Agency); `cli purge` | Borrar informe / dominio / cuenta |
| Registro de autorización | Prevención de abuso y responsabilidad | Mientras exista el dominio | Con el dominio |
| Audit log (acciones) | Seguridad | Mientras exista la organización | Con la organización |
| IP | — | **No se guarda**: solo un HMAC truncado (16 hex) con la `SECRET_KEY` | — |
| Leads del check público (dominio, email opcional, consentimiento) | Captación | `LEAD_RETENTION_DAYS` (30) | `cli purge` |

No hay cookies de analítica ni publicidad: solo `sid` (sesión) y `csrftoken`. Las plantillas de `/privacy` y `/terms` son orientativas y **deben revisarse con un profesional** antes del lanzamiento.

## 5. Divulgación responsable
Publique `/.well-known/security.txt` en su dominio de producción con un `Contact:` antes del lanzamiento.
