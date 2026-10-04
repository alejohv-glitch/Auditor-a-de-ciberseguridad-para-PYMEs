# Investigación de mercado y competencia

> Fecha: octubre 2026. Precios tomados de fuentes públicas (webs de comparación, Capterra, centros de ayuda). Varios proveedores ya no publican precios: lo indico cuando la cifra es de un tercero. **Verifique los precios antes de usarlos en material comercial.**

## 1. Resumen honesto

- **El escáner en sí no se puede vender como producto diferenciado.** Hay herramientas gratuitas y buenas para cada pieza: Mozilla HTTP Observatory, securityheaders.com, Hardenize, internet.nl, SSL Labs y MxToolbox (versión gratuita). SecurityScorecard incluso ofrece gratis la nota de su propia empresa.
- **Ya hay SaaS baratos que hacen casi lo mismo que nuestro MVP**: Scanward (29 $/mes, 10 dominios), DMARCTrust (desde 19 $/mes), Domian Posture (29 $ por auditoría puntual y 49 $/mes por la vigilancia), MxToolbox (de 19 a 129 $/mes según la fuente) y dmarcian (desde 19,99 $/mes).
- **Arriba del todo están las plataformas enterprise**: UpGuard desde 250 $/mes para empresas de 0 a 99 empleados, SecurityScorecard desde unos 20.000 $/año e Intruder desde unos 149 $/mes (cifra de terceros). Ninguna está pensada para una gestoría de 8 personas.
- **Hay hueco en el medio**: un servicio en **español**, con **lenguaje de negocio** y **revisión humana**, para pymes que no saben qué es DMARC y no van a usar una herramienta técnica. Ese hueco no está en la tecnología sino en la **distribución y en el servicio**. Ahí es donde hay que competir.

## 2. Competidores

| Competidor | Segmento | Precio de entrada | Qué hace bien | Debilidad para nuestra pyme objetivo |
|---|---|---|---|---|
| Mozilla Observatory / securityheaders.com / SSL Labs | Desarrolladores | Gratis | Rigor técnico, marca | Solo web, inglés, sin explicación de negocio ni vigilancia |
| Hardenize / internet.nl | Técnicos | Gratis (internet.nl) | Muy completos (correo + web + DNS) | Técnicos, sin informe comercial ni alertas para pymes |
| MxToolbox | IT / email marketing | Gratis; 19–129 $/mes ([Capterra](https://www.capterra.com/p/193765/MxToolbox/)) | Herramientas de correo, monitorización, marca conocida | Interfaz técnica, inglés |
| EasyDMARC / dmarcian / Valimail | DMARC | Plan gratuito; desde 19,99 $/mes (dmarcian); 35,99 €/mes Plus anual (EasyDMARC); 39 $/mes Bronze (Valimail) ([comparativa](https://dmarcreport.com/compare/easydmarc-valimail-dmarcreport/)) | Especialistas en DMARC, informes rua | Solo correo; requieren conocimientos para llegar a p=reject |
| Scanward | Pymes / agencias | 29 $/mes, 10 dominios; Agency 79 $/mes, 50 dominios ([AlternativeTo](https://alternativeto.net/software/scanward/about)) | Muy parecido a nuestro MVP, precio agresivo | Inglés, autoservicio, sin servicio humano |
| Domian Posture | Pymes | 29 $ por auditoría; 49 $/mes vigilancia ([Capterra](https://www.capterra.com/p/10049058/Domian-Posture/)) | Valida el modelo «auditoría puntual + mensualidad» | Inglés, centrado en correo |
| DMARCTrust | Pymes | desde 19 $/mes ([Capterra](https://www.capterra.com/p/10036636/DMARCTrust/)) | Alertas en tiempo real de cambios DNS | Solo correo |
| HostedScan / ScanYour.Site | MSP / agencias | ~99 $/mes por 100 análisis; marca blanca ([HostedScan](https://hostedscan.com/enterprise-reseller-whitelabel)) | Marca blanca y escaneo de vulnerabilidades | Más intrusivo (escaneo de vulnerabilidades); técnico |
| UpGuard Breach Risk | Medianas / grandes | 250 $/mes (0–99 empleados) ([UpGuard Help](https://help.upguard.com/en/what-is-included-in-upguards-self-service-breach-risk-plans)) | Puntuación de riesgo, proveedores | Caro y sobredimensionado para una micro-pyme |
| SecurityScorecard | Grandes | Gratis para la propia empresa; ~20.000 $/año ([GetApp](https://www.getapp.com/security-software/a/securityscorecard/pricing/)) | Marca, ratings de terceros | Enterprise |
| Intruder | Pymes técnicas | ~149 $/mes Essential (cifra de terceros, [ref](https://ethicalhacking.ai/pricing/intruder-pricing)) | Escaneo de vulnerabilidades real | Precio y complejidad; es otro producto (escaneo activo) |

## 3. Respuestas a las preguntas clave

**1. ¿Existe demanda?** Sí, pero sobre todo como **presión externa**, no como interés propio de la pyme:
- **Correo**: desde 2024 (Google y Yahoo) y desde mayo de 2025 (Microsoft), los grandes proveedores exigen SPF, DKIM y DMARC a los remitentes masivos, y la autenticación pesa en la entrega de todo el correo ([Red Sift](https://redsift.com/guides/bulk-email-sender-requirements), [URIports](https://www.uriports.com/blog/email-authentication-sender-requirements-2025/)). El dolor que siente el cliente es concreto: «mis presupuestos acaban en spam».
- **Fraude**: el fraude de facturas y del CEO por suplantación de dominio es un riesgo directo de dinero. INCIBE gestionó 97.348 incidentes en 2024 (+16,6 %), más de 31.500 en empresas. Varias fuentes de prensa sitúan el coste medio de un incidente en una pyme española entre 35.000 y 40.000 € (cifras de prensa, [elderecho.com](https://elderecho.com/los-ciberataques-en-espana-crecen-un-35-en-2025-y-superan-los-45-000-diarios-perdidas-millonarias-y-pymes-en-riesgo)).
- **Cadena de suministro (NIS2)**: las entidades reguladas envían a sus proveedores pyme cuestionarios de 40 a 120 preguntas, y más del 50 % de las pymes no sabe cómo demostrar que es de confianza ([DIGITAL SME](https://www.digitalsme.eu/digital-sme-launches-guide-to-position-smes-as-trusted-nis2-suppliers/)).
- **Ciberseguros**: las aseguradoras ya analizan el dominio desde fuera y preguntan por DMARC ([CRC Group](https://www.crcgroup.com/Tools-Intel/Specialty-Tools-Intel/cyber-loss-control-security-scans-have-pros-and-cons-8), [Palisade](https://www.palisade.email/learning/how-does-dmarc-affect-cyber-insurance.md)).

**2. ¿Quién paga hoy por algo así?** Tres perfiles: (a) las **agencias web y los MSP**, que pagan herramientas de 29 a 99 $/mes para revender o justificar su mantenimiento; (b) los **departamentos de IT y de marketing** que pagan herramientas DMARC; (c) las **pymes que ya tienen un problema**: les llega el spam, sufren una suplantación, reciben un cuestionario de un cliente o la aseguradora les pregunta. Estas últimas compran **un servicio** («arréglamelo»), no una herramienta.

**3. ¿Qué precios existen?** Autoservicio de 19 a 49 $/mes. Herramientas para agencias de 79 a 99 $/mes. Auditoría puntual automatizada desde 29 $. Enterprise desde 250 $/mes. Los servicios humanos (consultoría) cuestan entre 300 y 1.500 € por proyecto en el mercado local, aunque no tengo cifras auditadas de esto último.

**4. ¿Qué competidores son fuertes?** En DMARC, EasyDMARC (tiene plan gratuito y mucho contenido SEO). En herramientas gratuitas, Mozilla y Hardenize. En nuestro mismo formato, Scanward (precio muy agresivo). En enterprise, UpGuard y SecurityScorecard.

**5. ¿Dónde diferenciarse? (de más a menos defendible)**
1. **Distribución + servicio local en español**: informe revisado por una persona, llamada de 30 minutos y corrección guiada. Un SaaS en inglés no compite aquí, porque el valor está en la confianza y el acompañamiento.
2. **Canal de agencias e IT freelance** con marca blanca: ellos tienen la relación y la autorización del cliente, y nosotros les damos un producto que vender en su cuota de mantenimiento.
3. **Lenguaje de negocio**: cada hallazgo explica qué significa para la empresa (facturas falsas, spam, avisos del navegador), no solo «falta la cabecera X».
4. **Historial y evidencia** («su postura en los últimos 90 días») para responder a clientes, a cuestionarios NIS2 y a la aseguradora.
5. Precio accesible: es necesario, pero **no defendible por sí solo**.

**6. ¿Qué nicho atacar primero?** Ver [BUSINESS_PLAN.md](BUSINESS_PLAN.md#nicho). En resumen: **agencias web y técnicos IT freelance** como canal, y como cliente final **asesorías y gestorías, despachos de abogados, clínicas e inmobiliarias**.

**7. Funcionalidades realmente necesarias:** correo (SPF, DMARC y DKIM), HTTPS y certificado (caducidad), un informe claro en español, vigilancia con alertas de caducidad del certificado y de cambios en DNS o correo, historial, y el flujo de autorización. Es lo que está implementado.

**8. Funcionalidades innecesarias (por ahora):** escaneo de puertos o de vulnerabilidades (más riesgo legal y otro producto), IA generativa (la explicación determinista basta), integraciones SIEM, SSO, app móvil, decenas de cabeceras exóticas, un panel en tiempo real, typosquatting y monitorización de la dark web.

## 4. Conclusión de viabilidad

**¿Merece la pena construirlo?** Sí, con dos condiciones:
1. No posicionarlo como «otro escáner», sino como **«informe de seguridad externa y correo en español, revisado y vigilado»**, y venderlo primero como **servicio** (Fase A) y a través de **agencias e IT freelance** (marca blanca).
2. Aceptar que el SaaS de autoservicio puro a 19 €/mes **no generará ingresos por sí solo sin un canal**. El tráfico orgánico contra herramientas gratuitas y contra el SEO de EasyDMARC es lento.

El coste de construcción ya está pagado (este MVP) y el coste de operación es casi cero. El riesgo real está en la adquisición de clientes, no en la tecnología. Por eso el plan de clientes ([ACQUISITION_PLAN.md](ACQUISITION_PLAN.md)) es la pieza más importante.
