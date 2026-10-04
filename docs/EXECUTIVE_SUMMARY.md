# Resumen final

## WHAT WE BUILT
Un MVP funcional y desplegable:
- **Escáner pasivo** de correo (SPF, DMARC, DKIM, MTA-STS), HTTPS y certificado, TLS obsoleto, cabeceras de seguridad, cookies, DNS (NS, CAA, DNSSEC) y exposición (versiones, CMS, security.txt). Lleva **protección SSRF** (IP fijada, solo puertos 80/443, redirecciones re-validadas) y **autorización obligatoria registrada**.
- **Motor de reglas determinista** con 30 controles y textos de negocio en ES y EN: qué encontramos, por qué importa, recomendación, dificultad y evidencia.
- **Puntuación explicable** de 0 a 100: pesos por área, topes por severidad y cada punto perdido ligado a un hallazgo.
- **Aplicación web**: registro, login, reset de contraseña, panel, dominios, informe ejecutivo/técnico imprimible a PDF, notas del consultor, exportación JSON, marca blanca, historial con gráfico, «qué cambió», vigilancia con alertas (email, webhook, Discord, Telegram), planes Free/Pro/Business/Agency con límites, check público de captación con teaser, demo marcada como DEMO y métricas internas.
- **135 tests**, documentación de negocio y técnica, Dockerfile y Compose con Caddy, e informe de ejemplo.

## WHAT PROBLEM IT SOLVES
Las pymes sin IT no saben si alguien puede **suplantar su dominio por email** (fraude de facturas y del CEO), por qué **sus correos acaban en spam** (requisitos de Google, Yahoo y Microsoft), si su web **muestra avisos de seguridad** o qué contestar cuando **un cliente grande (NIS2) o la aseguradora** les pregunta por su seguridad. Las herramientas que existen son técnicas y están en inglés.

## WHO PAYS FOR IT
1. **Agencias web y técnicos IT freelance** que mantienen webs y correo de pymes: plan Agency con marca blanca, o comisión por cliente derivado.
2. **Asesorías y gestorías, despachos de abogados y clínicas** (3–30 empleados, sin IT): mueven dinero por email, tratan datos sensibles y ya pagan servicios profesionales.
3. Pymes que acaban de recibir **un cuestionario de seguridad o una pregunta de la aseguradora**.

## WHY THEY WOULD PAY
No pagan por «un escáner» (los hay gratis). Pagan por:
- **«Arréglamelo y dime que está bien»**: un informe revisado y una corrección guiada en su idioma.
- **Tranquilidad continua**: «te avisamos antes de que caduque el certificado o alguien toque el DNS».
- **Evidencia** para su cliente o su aseguradora: historial y un informe profesional.
- En el caso de las agencias, **un producto que vender** a su cartera con su marca.

## HOW MUCH IT COSTS TO RUN
Unos 6–9 €/mes para 1, 10 o 100 usuarios (un VPS, SQLite, el plan gratuito de SMTP y copias de céntimos). Unos 45–65 €/mes para 1.000 usuarios. Menos de 0,10 € por usuario y mes, sin APIs de pago. El coste real es **tu tiempo** de venta y soporte. Detalle en [BUSINESS_PLAN.md](BUSINESS_PLAN.md#costes-de-operación).

## HOW WE CAN CHARGE
- **Fase A (ya):** Informe revisado **99 €** · Informe + corrección guiada **249 €** (149 € para los 5 primeros a cambio de un testimonio). Cobro manual por factura y transferencia; el plan se activa con `cli set-plan`.
- **Fase B:** Pro **19 €/mes** · Business **49 €/mes** · Agency **99 €/mes** (marca blanca). Cada informe incluye 3 meses de Pro, que después pasan a pago.
- Stripe preparado como abstracción (`billing.py`), sin implementar hasta que haya credenciales.

## HOW TO GET FIRST 10 CUSTOMERS
Detalle y plantillas en [ACQUISITION_PLAN.md](ACQUISITION_PLAN.md). En resumen:
1. **Tu red + LinkedIn personalizado** (sin email en frío: la LSSI lo prohíbe también entre empresas) → 10 conversaciones con permiso para analizar → 10 llamadas de 20 minutos enseñando el informe → **3 ventas de 149–249 €**.
2. Enseña el **antes y el después** (re-análisis) y pide testimonio y 2 referidos.
3. **2 agencias o técnicos IT** con Agency gratis 2 meses o comisión del 30 %: cada uno tiene unos 20 clientes potenciales.
4. Una **charla gratuita** en un colegio o asociación profesional (gestores, dentistas) con chequeo en directo.
5. **Contenido semanal** en español sobre fraude de facturas y DMARC.

## WHAT IS STILL UNPROVEN
- Que las pymes del nicho **paguen 99–249 €** (frente a «ya lo mira mi informático»).
- Que las **agencias adopten** la marca blanca y la revendan.
- La conversión de informe → suscripción (objetivo del 40 %) y el churn de una suscripción de «tranquilidad».
- La tasa de bloqueo de nuestro User-Agent por WAFs a gran escala (hoy se marca como «no verificado»).
- Los precios exactos de la competencia: varios proceden de terceros.

## WHAT COULD KILL THIS BUSINESS
1. **No conseguir canal:** sin agencias ni outreach constante no hay tráfico, porque el SEO compite con herramientas gratuitas y con EasyDMARC.
2. **Guerra de precios** con Scanward o EasyDMARC si se posiciona como «escáner».
3. **Un gigante lo regala:** que el registrador o Google/Microsoft muestren el estado de DMARC en su panel.
4. **Un problema legal o de reputación** por uso contra terceros o por outreach percibido como spam.
5. **Falsa seguridad:** un cliente con nota A sufre un incidente y te culpa. Se mitiga con el lenguaje de limitaciones, que ya está en todo el producto.

## NEXT 5 HIGHEST-VALUE ACTIONS
1. **Esta semana:** 30 mensajes personales (plantillas A/B) y 5 chequeos con permiso usando tu cuenta local o un despliegue privado. **Valida antes de programar más.**
2. **Elegir nombre y dominio**, configurar su correo con SPF, DKIM y DMARC (el producto debe sacar A en sí mismo) y desplegar en un VPS siguiendo la checklist de [DEPLOYMENT.md](DEPLOYMENT.md). *Requiere tu autorización y unos 15 € (dominio + VPS).*
3. **Contactar con 15 agencias o técnicos IT** (plantilla C) y cerrar 2 pilotos del plan Agency.
4. Revisar los textos legales (`/privacy`, `/terms`) con un profesional y publicar `security.txt`.
5. **Solo cuando haya 3 clientes de pago:** Stripe Checkout y el envío automático por email del resultado del check público (el SHOULD de mayor impacto en la conversión).
