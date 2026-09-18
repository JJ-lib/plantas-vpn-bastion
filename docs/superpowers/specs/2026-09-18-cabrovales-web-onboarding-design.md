# Alta WEB mínima para Cabrovales

## Objetivo

Rediseñar únicamente el alta de equipos WEB de la planta Cabrovales para que el usuario introduzca solo los datos del equipo y el panel seleccione, valide y publique automáticamente la estrategia de acceso. Las demás plantas y los equipos existentes quedan fuera del piloto y conservan su flujo actual.

## Evidencia que motiva el cambio

El incidente de septiembre de 2026 mostró que la conectividad IPsec y los inversores seguían funcionando, pero los equipos WEB A–I estaban publicados en passthrough y exponían el certificado Sungrow. ITS J usaba bridge TLS y funcionaba. El sistema permitía que el modo almacenado, el certificado montado y la configuración efectiva quedaran desalineados.

La solución debe hacer que el modo efectivo, el transporte hacia el equipo, el Host/SNI y el certificado sean una única decisión generada y validada por el proceso de alta.

## Alcance

Incluido:

- Nuevas altas de tipo WEB iniciadas desde Cabrovales.
- Detección automática de HTTP o HTTPS en el equipo.
- Detección de redirecciones y URLs privadas.
- Uso automático del perfil de planta cuando un equipo necesita Host/SNI.
- Generación atómica de base de datos, HAProxy y Compose.
- Validación de configuración y prueba HTTP antes de confirmar el alta.
- Backport al repositorio del hotfix de montaje del certificado TLS común que existe actualmente en producción.

No incluido en el piloto:

- Cambiar el formulario o el comportamiento de otras plantas.
- Migrar NCU, ITS A–J, RDP, VNC, trackers u otros equipos ya existentes.
- Sustituir inmediatamente el certificado autofirmado por Let’s Encrypt.
- Cambiar el dominio público del bastión.

## Experiencia de usuario

Para una nueva alta WEB de Cabrovales, el formulario normal mostrará únicamente:

1. Nombre del equipo.
2. IP real.
3. Puerto real, con `80` como valor predeterminado.

Planta se obtiene del contexto de alta y no se edita en este flujo. El usuario no selecciona `direct`, `rewrite_cache`, `bridge_tls`, Host/SNI, URL pública ni puerto público.

El único botón operativo será **Guardar y validar**. La pantalla mostrará el resultado y el diagnóstico concreto. Un fallo no crea un equipo parcialmente activo.

La edición avanzada seguirá disponible solo para administración técnica durante el piloto, separada del flujo normal y sin mostrarse como opción de alta.

## Perfil de planta

Se añadirá una política explícita de alta WEB por planta, con valor por defecto `legacy`. Cabrovales tendrá `minimal_auto` y el host candidato de planta `local.domain`.

La política de Cabrovales no obliga a todos los equipos a usar `local.domain`:

- Un equipo HTTP simple no usa Host/SNI canónico.
- Un equipo HTTPS normal usa la conexión HTTPS detectada y no necesita un host especial.
- Un equipo Sungrow/legacy usa `local.domain` solo si la prueba confirma que ese perfil obtiene una respuesta válida.

La política se consultará por planta, no por una lista global de IPs. Las plantas que no tengan `minimal_auto` seguirán ejecutando el flujo actual.

## Clasificación automática

El preflight se ejecutará dentro del namespace VPN de Cabrovales y no desde el navegador ni desde el host del operador.

### Secuencia

1. Probar HTTP contra la IP y puerto introducidos.
2. Probar HTTPS contra la IP y puerto con validación de certificado desactivada solo para el enlace interno.
3. Seguir como máximo dos redirecciones y leer una respuesta limitada.
4. Si el perfil de planta tiene un host candidato, repetir la prueba HTTP/HTTPS con `Host` y, para HTTPS, SNI coherente.
5. Clasificar el resultado.

### Clases internas

- `generic_http`: responde por HTTP, sin evidencia de Host/SNI especial.
- `generic_https`: responde por HTTPS, sin evidencia de Host/SNI especial.
- `plant_host_https`: responde por HTTPS solo con el host/SNI de planta.
- `private_urls`: la respuesta contiene redirecciones o URLs absolutas privadas; se activa la reescritura existente.
- `unreachable`: no hay respuesta válida; el alta se rechaza sin modificar estado.

La clasificación no se expone como selector al usuario. Se guarda como diagnóstico reproducible junto con el transporte elegido y el host utilizado, sin guardar el HTML descargado.

## Modelo de configuración

Se mantienen `web_mode` y `web_effective_mode` para compatibilidad con las plantas existentes, pero el alta automática añadirá los datos que ahora faltan:

- Transporte hacia el equipo: `http` o `https`.
- Host/SNI efectivo: vacío, IP o host de planta.
- Perfil de validación utilizado.
- Estado de validación y diagnóstico resumido.

Para Cabrovales, el frontend público será HTTPS del bastión. El backend podrá ser HTTP o HTTPS según el resultado del preflight:

- Frontend TLS + backend HTTP para `generic_http`.
- Frontend TLS + backend HTTPS para `generic_https`.
- Frontend TLS + backend HTTPS con SNI/Host de planta para `plant_host_https`.

El certificado común del bastión se montará desde un único path estable. La configuración no volverá a depender de una excepción por slug de planta.

## Publicación transaccional

El alta seguirá este orden y no confirmará la fila hasta completar la publicación:

1. Validar campos básicos.
2. Ejecutar preflight dentro de la VPN.
3. Construir una fila candidata en un savepoint.
4. Renderizar HAProxy y Compose desde esa misma fila candidata.
5. Validar `haproxy -c` y `docker compose config`.
6. Verificar que el certificado requerido existe y está montado cuando el frontend sea TLS.
7. Publicar únicamente `vpn-cabrovales` y su `webfix` si corresponde.
8. Probar el puerto público y exigir un código HTTP válido.
9. Confirmar la transacción y mostrar el diagnóstico.

Si falla cualquier paso posterior al savepoint:

- Se restaura la configuración anterior.
- Se revierte la fila candidata.
- No se reinician otras plantas.
- El formulario conserva los datos para corregirlos.
- El mensaje indica la fase exacta: preflight, configuración, publicación o smoke test.

## Compatibilidad y certificados

La terminación TLS uniforme del bastión no obliga al backend a hablar HTTPS; el renderer debe distinguir explícitamente HTTP y HTTPS para no añadir `ssl` a un backend HTTP.

Durante este piloto se reutiliza el certificado actual del bastión. Por tanto, un navegador nuevo puede seguir mostrando advertencia de confianza si se accede mediante la IP y el certificado es autofirmado.

Eliminar esa advertencia es un trabajo separado: requiere acceder mediante un nombre DNS cubierto por el certificado. Let’s Encrypt no resuelve el acceso por IP privada. Para un dominio controlado, DNS-01 y renovación automática son posibles; para una red solo interna, una CA interna confiada en los equipos suele ser más sencilla.

## Pruebas de aceptación

El cambio se considerará válido solo si se cumplen todas estas condiciones:

1. El formulario mínimo aparece para nuevas altas WEB de Cabrovales.
2. El formulario actual permanece para una planta distinta de Cabrovales.
3. Un fixture HTTP simple genera frontend TLS y backend sin `ssl` ni SNI.
4. Un fixture HTTPS normal genera frontend TLS y backend HTTPS.
5. Un fixture que solo responde con `local.domain` genera SNI/Host de planta.
6. Un fixture con URLs absolutas privadas activa la reescritura existente.
7. Un equipo inalcanzable no deja fila, configuración ni contenedor modificados.
8. Un fallo de `haproxy -c`, Compose o smoke test ejecuta rollback.
9. La publicación correcta modifica solo Cabrovales.
10. Las 32 filas WEB existentes de Cabrovales mantienen sus modos y diagnósticos durante el piloto.
11. Las demás plantas mantienen sus contenedores, configuración y flujo de alta.
12. El runtime construido desde el repositorio pasa las pruebas focalizadas y una prueba HTTP real contra un equipo de prueba autorizado.

## Despliegue del piloto

1. Incorporar al repositorio el hotfix TLS que actualmente existe solo en el runtime.
2. Añadir la política `minimal_auto` únicamente a Cabrovales.
3. Ejecutar pruebas unitarias y de generación con datos sintéticos.
4. Construir una imagen candidata sin tocar runtime.
5. Promover solo el panel y verificar que las plantas no cambian.
6. Dar de alta primero un equipo WEB de prueba no crítico en Cabrovales.
7. Verificar el flujo completo y conservar evidencia de la clasificación, configuración, estado HTTP y rollback.
8. Solo después permitir altas WEB reales de Cabrovales.

## Criterio de ampliación

No se habilitará `minimal_auto` en otra planta hasta que el piloto de Cabrovales tenga una alta correcta, un fallo controlado con rollback y una segunda alta de una clase distinta —por ejemplo HTTP simple frente a HTTPS con Host/SNI— documentadas con resultados reales.
