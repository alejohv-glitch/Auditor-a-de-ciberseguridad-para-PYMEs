# Plan para conseguir los primeros clientes

> Nada de esto se envía automáticamente. Todo el contacto lo haces tú, una persona cada vez, de forma personalizada.

## 0. Reglas legales (España / UE): léelas primero

- **Email comercial no solicitado:** la **LSSI-CE (art. 21)** prohíbe enviar comunicaciones comerciales por email sin consentimiento previo, **también a empresas**. La excepción es que exista una relación contractual previa. **No hagas email en frío masivo a pymes españolas.** (En otros países las reglas B2B varían; asume la regla más estricta.)
- **Sí son válidos:** el contacto en persona, el teléfono a la empresa (respetando la Lista Robinson cuando aplique), los mensajes personales en LinkedIn, las presentaciones por terceros, los eventos, el formulario de contacto de la propia empresa con un mensaje individual y no comercial masivo, y el email a quien te ha dado permiso (por ejemplo, un lead del check gratuito que marcó la casilla de consentimiento).
- **No analices el dominio de un prospecto sin su permiso.** Las comprobaciones son pasivas y públicas, pero nuestra regla es **pedir permiso antes** («¿te hago un chequeo gratuito de tu dominio?»). En el primer mensaje habla del **problema en general**, no de «he analizado tu web y tienes fallos».
- **RGPD:** los datos de contacto de prospectos se usan con base en el interés legítimo, de forma mínima y con opción de baja. No compres listas.

## 1. Proceso de venta manual (lo que el producto ya soporta)

1. **Encontrar** una empresa del nicho (ver la lista de abajo).
2. **Pedir permiso** para un chequeo gratuito (mensaje 1).
3. **Analizar** en tu cuenta: *Añadir dominio* → «Nombre del cliente» → confirmar la autorización (queda registrada con fecha y usuario).
4. **Preparar la muestra:** abre el informe en vista ejecutiva, revisa los hallazgos y añade tus **Notas del consultor** (vista técnica → caja de notas). Aparecen en el informe.
5. **Mostrar** el informe por videollamada (pantalla compartida) o envíalo como PDF (botón *Descargar PDF*).
6. **Ofrecer** el Informe + corrección guiada (249 €) o el Informe revisado (99 €).
7. **Cobrar** por factura y transferencia, o con un enlace de pago, y activar el plan con `python -m app.cli set-plan EMAIL pro --months 3`.
8. **Convertir a vigilancia:** a los 3 meses se renueva a Pro (19 €/mes). La primera alerta real («tu certificado caduca en 10 días») es la mejor venta.

## 2. Primeros 10 leads (semanas 1–2)

**Objetivo:** 10 conversaciones con permiso para analizar su dominio.

| Fuente | Acción concreta | Esperado |
|---|---|---|
| **Tu red** | Lista de 30 personas que conoces con negocio propio o que trabajan en una pyme (gestoría, clínica, despacho). Mensaje personal (plantilla A). | 4–5 leads |
| **LinkedIn** | Busca «gerente gestoría [tu ciudad]», «socio despacho abogados», «director clínica dental». 10 solicitudes de conexión al día con nota personal, sin enlace. Cuando acepten, plantilla B. | 3–4 leads |
| **Agencias web locales** | 15 agencias pequeñas (2–10 personas) de Google Maps o Clutch. Llamada o LinkedIn al fundador (plantilla C). | 1–2 leads (canal) |
| **Comunidades** | Grupos de LinkedIn/Facebook de asesores fiscales, foros de WordPress en español, comunidades de freelancers IT. **Aporta valor** (post: «3 registros DNS que evitan que suplanten tu gestoría»), sin vender. Ofrece el check gratuito en comentarios si alguien pregunta. | 1–2 leads |

## 3. Primeros 3 clientes de pago (semanas 2–5)

- De los 10 leads, haz **10 chequeos y 10 llamadas de 20 minutos** para mostrar resultados.
- Oferta de lanzamiento: **Informe + corrección guiada a 149 € (en vez de 249 €) para los 5 primeros clientes**, a cambio de un testimonio y permiso para citarles.
- Con una conversión esperada del 25–35 % sobre llamadas con problemas reales salen **3 clientes**. La mayoría tendrá DMARC ausente o en p=none: es un problema real, concreto y fácil de arreglar.
- Tras arreglarlo, **re-analiza y enséñales el antes y el después** (el panel muestra 55 → 85, +30). Esa captura es tu mejor material comercial (con su permiso).

## 4. Primeros 10 clientes (semanas 5–12)

1. **Canal de agencias (prioridad):** consigue 2 agencias o técnicos IT freelance que usen el producto con sus clientes.
   - Oferta: **plan Agency gratis 2 meses** y después 99 €/mes, o un 30 % de comisión recurrente por cliente final que te deriven, si prefieren no operar ellos.
   - Una agencia con 20 clientes de mantenimiento equivale a 20 informes potenciales.
2. **Referidos:** cada cliente satisfecho conoce a otros 3 del mismo gremio. Pide 2 presentaciones por email (le das tú el texto).
3. **Asociaciones profesionales:** colegios de gestores administrativos, asociaciones de asesores fiscales y colegios de dentistas o fisioterapeutas. Ofrece una **charla gratuita de 30 minutos** («Fraude de facturas por email: cómo protegerse en 15 minutos») con chequeo en directo del dominio de voluntarios (con permiso).
4. **Contenido (lento pero acumulativo):** 1 artículo por semana en LinkedIn en español sobre casos concretos (cambio de IBAN, Gmail rechaza tus correos, la aseguradora pregunta por DMARC).
5. **Partners de seguros:** los corredores de ciberseguros necesitan que sus clientes mejoren su postura. Puedes ofrecerles el informe como servicio de preparación para la póliza.

## 5. Plantillas de outreach (personalízalas siempre)

**A. Conocido (WhatsApp / email personal)**
> Hola [Nombre], ¿qué tal? Estoy lanzando un servicio para revisar si el dominio de correo de una empresa está protegido contra suplantaciones (lo del email falso pidiendo cambiar el IBAN de una factura). Es un chequeo pasivo de 1 minuto, no toca nada de vuestros sistemas. ¿Te apetece que lo haga gratis para [empresa] y te cuento en 15 minutos lo que salga? Me ayudaría mucho tu opinión.

**B. LinkedIn (tras aceptar la conexión)**
> Gracias por conectar, [Nombre]. Trabajo con [gestorías/despachos/clínicas] en un tema concreto: que nadie pueda enviar emails haciéndose pasar por su dominio y que sus correos no acaben en spam (Gmail y Microsoft lo endurecieron en 2024–2025). Si te interesa, hago un chequeo gratuito y pasivo de vuestro dominio y te explico el resultado en 15 minutos, sin compromiso. ¿Te encaja?

**C. Agencia web / IT freelance**
> Hola [Nombre], he visto que gestionáis webs y mantenimiento para [tipo de clientes]. Tengo una herramienta que genera informes de seguridad externa y de correo (SPF, DKIM, DMARC, HTTPS, certificados) en español y con vuestra marca, y vigila los dominios para avisaros antes de que caduque un certificado o alguien cambie el DNS. A muchas agencias les sirve para justificar la cuota de mantenimiento o para vender la corrección. ¿Os lo enseño 20 minutos con el dominio de vuestra propia agencia?

**D. Seguimiento tras el chequeo (con permiso)**
> Hola [Nombre], te adjunto el informe de [dominio]: puntuación [X]/100. Lo más importante: [hallazgo 1 en lenguaje de negocio]. Se arregla en [tiempo] desde el panel de [proveedor]. Si quieres que te acompañe a corregirlo y lo dejemos verificado, son 249 € (149 € para los primeros clientes) e incluye 3 meses de vigilancia. ¿Lo vemos?

**E. Post para comunidades (aporta valor, no vende)**
> 3 registros DNS que evitan que alguien envíe facturas falsas en nombre de tu empresa: SPF (quién puede enviar), DKIM (firma) y DMARC (qué hacer con lo que no cuadra). Si tu DMARC dice «p=none», hoy todavía no protege. Si alguien quiere, comprobad vuestro dominio gratis en [enlace] (solo dominios propios).

## 6. Métricas a seguir (panel /admin)
- Leads del check público (con email) por semana.
- Llamadas hechas → informes vendidos (objetivo: 30 %).
- Informes vendidos → Pro a los 3 meses (objetivo: 40 %).
- Agencias activas y dominios por agencia.
- **Señal de alarma:** si en 8 semanas hay menos de 2 ventas con más de 15 llamadas, el mensaje o el nicho están mal. Prueba otro nicho de la tabla del plan de negocio antes de invertir más en producto.
