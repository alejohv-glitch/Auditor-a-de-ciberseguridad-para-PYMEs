# Metodología de puntuación y severidad

## Severidad (sin abusar de CRITICAL)

| Severidad | Criterio | Ejemplos |
|---|---|---|
| **CRITICAL** | Cualquiera puede abusar hoy, sin esfuerzo, con impacto de negocio serio | SPF `+all` (autoriza a cualquier servidor a enviar como tú) |
| **HIGH** | Falta un control básico o está roto | Sin DMARC; varios SPF (permerror); DMARC inválido; sin HTTPS; certificado no válido o caducado; certificado que caduca en menos de 7 días; SPF ausente en un dominio con MX |
| **MEDIUM** | El control existe pero es débil, o la configuración es obsoleta | DMARC p=none; SPF `?all` o sin `all`; más de 10 consultas SPF; HTTP no redirige a HTTPS; TLS 1.0/1.1; certificado a ≤20 días; cookies de sesión sin Secure; un solo NS; SPF ausente en un dominio sin MX |
| **LOW** | Falta de refuerzo (*hardening*) que reduce el impacto de otros fallos | Sin HSTS, CSP, X-Content-Type-Options o anti-clickjacking; sin CAA; sin DNSSEC; versión de software visible; DMARC sin rua; cookies sin HttpOnly/SameSite |
| **INFO** | Recomendación sin impacto en la nota | Referrer-Policy, Permissions-Policy, MTA-STS, security.txt, HSTS con max-age corto |

Cada hallazgo indica además su **tipo**: vulnerabilidad, mala configuración, falta de refuerzo, recomendación o información. La ausencia de una cabecera **nunca** se marca como vulnerabilidad crítica.

## Estados

- `fail`: problema observado.
- `pass`: control correcto (aparece en «Controles correctos»).
- `unknown`: **no verificable** (timeout, bloqueo WAF, DKIM con selector desconocido). **No resta puntos** y se informa.
- `na`: no aplica (por ejemplo, no hay cookies, o el dominio no recibe correo).

## Puntuación (0–100)

1. **Pesos por área:** correo 30 · HTTPS y certificado 25 · cabeceras 15 · cookies 10 · DNS 10 · exposición 10.
   *Por qué:* el correo es el vector de fraude más directo en una pyme (BEC, facturas falsas) y lo que más afecta a la entrega del email. HTTPS es lo que ve el cliente final. Las cabeceras son refuerzo.
2. **Penalización por hallazgo** = peso del área × factor (critical 1.0, high 0.5, medium 0.25, low 0.1, info 0). Un área no baja de 0.
3. **Áreas sin reglas aplicables** se excluyen y el resto se reescala a 100. Así no se castiga ni se premia por no tener cookies, por ejemplo.
4. **Topes:** cualquier CRITICAL limita la nota a 40 y cualquier HIGH a 70. Así un buen promedio no oculta un fallo grave. El informe muestra la nota sin tope.
5. **Nota:** A ≥ 90 · B ≥ 75 · C ≥ 60 · D ≥ 40 · F < 40.

**Explicabilidad:** `summary.deductions` asigna cada punto perdido a un hallazgo concreto, y el informe muestra «−X pts» en cada uno. Un test (`test_deductions_explain_every_point`) comprueba que 100 − Σ deducciones = nota sin tope.

## Límites conocidos (y cómo se tratan)

- **DKIM** no se puede enumerar: se prueban 15 selectores comunes y, si no hay coincidencia, el resultado es `unknown`, nunca fallo.
- **WAF/anti-bots:** si la web responde 403/429/503 a nuestro User-Agent identificado, las comprobaciones de cabeceras, cookies y exposición pasan a `unknown`. **No se intenta evadir el bloqueo.**
- **TLS 1.0/1.1:** si el OpenSSL local no puede ofrecer el protocolo, el resultado es `unknown`.
- **www vs dominio raíz:** se analiza la web del host introducido (siguiendo redirecciones) y el correo del dominio sin `www.`.
