# Plan de negocio (breve)

## Propuesta de valor (una frase)

> **«Sepa en un minuto si pueden suplantar su empresa por email o si su web da avisos de seguridad, con un informe en español que dice qué arreglar, y le avisamos si algo empeora.»**

Versión para agencias e IT:
> **«Informes de seguridad externa y correo con su marca, para entregar a sus clientes y justificar su cuota de mantenimiento.»**

## Variante recomendada (frente a la idea inicial)

| Idea inicial | Variante recomendada | Por qué |
|---|---|---|
| Escáner genérico de ciberseguridad para todas las pymes | **Auditoría externa de correo y web en español, revisada por una persona y vigilada**, vendida directamente a pymes con datos sensibles **y a través de agencias e IT freelance** | El escáner es una commodity gratuita (ver [MARKET_RESEARCH.md](MARKET_RESEARCH.md)). La diferencia defendible está en el idioma, la confianza, el servicio y el canal |

El foco del contenido es el **correo (DMARC)**, porque es lo más fácil de explicar y lo que más se acerca al dinero: facturas falsas, presupuestos que acaban en spam y preguntas de la aseguradora. Además, se corrige en minutos, lo que permite demostrar valor muy rápido.

## Nicho

Los nichos se puntuaron de 1 a 5 según necesidad, capacidad de pago, competencia, facilidad de contacto, problemas visibles y potencial de recurrencia:

| Nicho | Necesidad | Pago | Contacto | Visible | Recurrencia | Total |
|---|---|---|---|---|---|---|
| **Agencias web / IT freelance (canal)** | 4 | 4 | 5 | 4 | 5 | **22** |
| **Asesorías / gestorías** | 5 (manejan IBAN, nóminas, fraude de facturas) | 4 | 4 | 4 | 4 | **21** |
| **Despachos de abogados** | 5 (confidencialidad) | 5 | 3 | 4 | 4 | **21** |
| **Clínicas (dentales, fisioterapia, estética)** | 4 (datos de salud) | 4 | 4 | 4 | 3 | **19** |
| Inmobiliarias | 4 (fraude de señales/arras) | 3 | 4 | 4 | 3 | 18 |
| E-commerce pequeño | 4 | 3 | 3 | 4 | 4 | 18 |
| Hoteles | 3 | 3 | 3 | 3 | 3 | 15 |
| Restaurantes / gimnasios | 2 | 2 | 4 | 3 | 2 | 13 |

**Decisión:** el **canal** son las agencias web e IT freelance, y los **clientes finales** son asesorías y gestorías, despachos de abogados y clínicas en España, y después en Latinoamérica. Son negocios que mueven dinero por email, tratan datos sensibles, tienen 3–30 empleados sin IT interno y ya pagan servicios profesionales recurrentes. **No** vamos a por restaurantes ni gimnasios.

## Precios

Los precios se fijan por comparación: Scanward cobra 29 $/mes por 10 dominios, DMARCTrust desde 19 $, Domian Posture 29 $ por auditoría y 49 $/mes, y MxToolbox de 19 a 49 $. Nuestro valor diferencial es el servicio y el idioma, no un precio más bajo.

### Fase A: servicios puntuales (ingresos desde la primera semana)
| Servicio | Precio (sin IVA) | Contenido | Tiempo real tuyo |
|---|---|---|---|
| Análisis gratuito | 0 € | Teaser público con 3 hallazgos | 0 |
| **Informe revisado** | **99 €** | Informe completo + tus notas de consultor + llamada de 30 min | ~1 h |
| **Informe + corrección guiada** | **249 €** | Lo anterior + acompañamiento para SPF/DKIM/DMARC y cabeceras + re-análisis | 2–3 h |

Con 99 € el cliente no necesita aprobación interna y tú cobras unos 99 €/h. Los 249 € son el producto donde está el margen: la mayoría de las pymes no sabe tocar DNS.

### Fase B: suscripciones
| Plan | €/mes | Dominios | Vigilancia | Historial | Alertas | Informes | Usuarios |
|---|---|---|---|---|---|---|---|
| Free | 0 | 1 | No (2 análisis manuales/día) | 30 días | — | Ejecutivo completo | 1 |
| **Pro** | **19** | 3 | Diaria/semanal | 1 año | Email, webhook | + técnico, exportable | 1 |
| Business | 49 | 10 | Diaria | 2 años | + Discord, Telegram | + técnico, exportable | 3 |
| Agency | 99 | 30 | Diaria | 2 años | Todos | + **marca blanca** | 5 |

- Pago anual = 10 meses (2 gratis).
- **Venta cruzada clave**: cada informe de 99/249 € incluye 3 meses de Pro gratis, y después se renueva a 19 €/mes. Es la vía de Fase A → Fase B.
- **El plan Free da valor real, pero sin vigilancia.** Lo que se paga es la tranquilidad («te avisamos»), el historial y la exportación.

Todo esto se configura en `app/plans.py`.

## Costes de operación

Arquitectura: un VPS + SQLite (o Postgres gestionado) + SMTP transaccional. Los análisis son ligeros (unas 40 consultas DNS, 1–2 conexiones TLS y ≤3 GET; poca CPU) y no hay APIs de pago.

| Usuarios activos | Infraestructura | Email | Copias | Total aprox./mes |
|---|---|---|---|---|
| 1 | VPS pequeño (~5–8 €) | Plan gratuito (Brevo/Resend) | Snapshot o Litestream → S3 (<1 €) | **~6–9 €** |
| 10 | igual | gratuito | <1 € | **~6–9 €** |
| 100 | igual (≈100 análisis/día ≈ 20 min de trabajo secuencial) | gratuito o ~10 € | ~1 € | **~8–20 €** |
| 1.000 | VPS 4 GB (~10–20 €) o 2 workers; Postgres gestionado (~15 €) | ~15–25 € | ~2 € | **~45–65 €** |

Más el dominio (~12 €/año) y las comisiones de Stripe en la UE (aprox. 1,5 % + 0,25 € por cobro; compruebe la tarifa actual). **Coste por usuario a partir de 100 usuarios: menos de 0,10 €/mes.** El margen bruto supera el 95 %.

**Posibles cuellos de botella económicos:**
1. **Tu tiempo de soporte** (con diferencia el mayor coste real). Se mitiga con informes autoexplicativos y plantillas.
2. **El email de alertas** si crece mucho. Solo se envían alertas en cambios, no informes diarios.
3. **IA generativa**, si se añade: se acota a 1 resumen por informe de pago (~0,01–0,05 €) y nunca en el plan Free.
4. **La reputación de la IP del escáner**: si algún sitio la bloquea, el análisis da «no verificado», no un error. No se intenta evadir el bloqueo.

## Economía unitaria (objetivo a 12 meses)

- 5 informes de 99 € + 2 de 249 € al mes ≈ **1.000 €/mes** en servicios, alcanzable sin tráfico orgánico si funciona el outreach.
- Conversión del informe a Pro (3 meses gratis → pago): objetivo del 40 %.
- 5 agencias en plan Agency = 495 € de MRR, más los clientes directos.
- **Objetivo de 1.000 € de MRR en 12 meses** ≈ 5 Agency + 20 Pro + 4 Business. Es ambicioso pero plausible si las agencias funcionan como canal. Si al mes 4 no hay ni una agencia de pago, hay que replantearse (ver riesgos).

## MoSCoW

**MUST (implementado):** análisis pasivo de correo, TLS, cabeceras, cookies, DNS y exposición · protección SSRF · puntuación explicable · informe ES/EN ejecutivo/técnico con impresión a PDF · autorización obligatoria con registro · registro, login y reset de contraseña · aislamiento multi-tenant · límites de uso por plan · check público de captación con teaser · vigilancia periódica, cambios y alertas (email/webhook/Discord/Telegram) · historial · demo marcada como DEMO · métricas internas · borrado de cuenta, dominio e informe · tests.

**SHOULD (siguiente):** Stripe Checkout + webhooks (cuando tengas cuenta) · PDF del lado del servidor (si los clientes lo piden; hoy se usa «Imprimir → PDF») · invitar a miembros del equipo (los campos ya existen) · email automático con el resultado del check público · Postgres + migraciones Alembic al pasar de un VPS · página de estado del escáner · gestor de leads para la venta manual.

**LATER:** portal del cliente final con la marca de la agencia · resumen con IA (la interfaz `Explainer` ya existe) · informes de proveedores / NIS2 · paquete de respuesta a cuestionarios de seguridad · comprobación de typosquatting · análisis de informes DMARC rua (posible producto aparte) · API pública.

**NO (fuera del alcance a propósito):** escaneo de puertos, escaneo de vulnerabilidades, fuerza bruta, crawling, cualquier cosa activa contra terceros.

## Marca: 10 propuestas

Ninguna está verificada en registros de marcas (OEPM/EUIPO) ni en disponibilidad de dominios. **Compruébelo antes de decidir.** El nombre de trabajo es `Seclara` y se cambia con la variable `APP_NAME`.

1. **Seclara**: *security + clara*. Transmite «seguridad explicada claro». Es la recomendada.
2. **Vigilio**: vigilancia continua; suena bien en ES, IT y EN.
3. **Postura**: término técnico correcto («postura de seguridad»), internacional.
4. **Sentinela**: centinela; evoca vigilancia.
5. **Guardalia**: cercana y amable para pymes.
6. **Fortivo**: fortaleza; corta, aunque más genérica.
7. **Blindo**: «blindado», coloquial en España.
8. **Clarasec**: variante de Seclara, más descriptiva.
9. **Domely**: dominio + seguro; anglófona.
10. **Trustdom**: confianza en el dominio; anglófona, para LatAm/EN.

## Riesgos y qué podría matar el negocio

1. **Adquisición.** Las pymes no buscan «DMARC». Sin canal (agencias) ni outreach constante no hay clientes. *Mitigación:* el plan de adquisición, vender servicios antes que suscripciones y el canal de agencias.
2. **Commodity y precio.** Scanward a 29 $ por 10 dominios y EasyDMARC gratis. Si se compite por precio, se pierde. *Mitigación:* idioma, servicio humano y nicho.
3. **Un competidor grande lo regala.** Por ejemplo, un registrador de dominios o Google/Microsoft muestra el estado de DMARC en su panel. *Mitigación:* el valor está en el acompañamiento y en el canal, no en el dato.
4. **Legal y reputación.** Alguien usa el producto contra terceros, o se hace outreach que se percibe como spam. *Mitigación:* análisis pasivo, autorización registrada, límites, caché y **respeto estricto de la LSSI** (ver plan de adquisición).
5. **Riesgo de dar falsa seguridad.** Un cliente con nota A sufre un incidente. *Mitigación:* lenguaje de limitaciones en cada informe y en las condiciones; nunca prometer «está seguro».
6. **Tu tiempo.** El servicio no escala. *Mitigación:* subir precios de los servicios con la demanda y empujar a las agencias hacia el autoservicio con marca blanca.
