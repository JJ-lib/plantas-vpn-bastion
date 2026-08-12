# Promoción y rollback del monitor de endpoints VPN

Este runbook define una promoción gradual. No sustituye la validación de la
política de salida descrita en
[`vpn-endpoint-monitor-egress.md`](vpn-endpoint-monitor-egress.md) y no autoriza
un despliegue desde el checkout.

## Prerrequisitos verificables

- La imagen del worker instala exactamente `ike-scan=1.9.5-2`. Verificar la
  imagen candidata con `ike-scan --version` y comprobar que informa la versión
  `1.9.5`; el sufijo `-2` es la revisión exacta del paquete Debian fijada en el
  Dockerfile. No promover si el paquete instalado difiere.
- Conservar referencias inmutables de las imágenes anteriores del panel,
  Caddy y monitor, junto con un respaldo identificado de SQLite. No registrar
  variables de entorno, contenido de secretos ni filas de la base de datos.
- Mantener desactivados collection, diagnósticos Admin y alertas públicas hasta
  alcanzar su paso correspondiente.

## Generación segura del token

Crear el token fuera del repositorio y de cualquier directorio montado de forma
general. El ejemplo no muestra el valor y usa sustitución atómica del archivo:

```sh
umask 077
TOKEN_DIR=/ruta/protegida
TOKEN_FILE="$TOKEN_DIR/vpn-endpoint-monitor.token"
TOKEN_TMP="$TOKEN_FILE.new"
mkdir -p "$TOKEN_DIR"
openssl rand -hex 32 > "$TOKEN_TMP"
chmod 0600 "$TOKEN_TMP"
mv -f "$TOKEN_TMP" "$TOKEN_FILE"
```

El propietario debe ser la cuenta que gestiona Compose y el archivo solo debe
montarse como secreto de solo lectura en panel y monitor. Nunca imprimir el
token, pasarlo como argumento, guardarlo en variables versionadas ni incluirlo
en logs, tickets o salidas de diagnóstico.

## Orden obligatorio de promoción

1. **Panel y migración** — promover primero el panel compatible con el esquema
   anterior, con collection y UI desactivadas. Ejecutar la migración sobre una
   copia protegida, repetirla para probar idempotencia y reabrir SQLite para
   comprobar estado, contador e histórico. Después verificar el panel real sin
   habilitar el worker.
2. **Caddy** — promover la política que bloquea `/internal/*` antes del proxy
   general. Probar desde el exterior que no se alcanza la API interna y desde
   la red interna que Flask sigue exigiendo autenticación.
3. **Token** — generar o instalar el archivo externo mediante el procedimiento
   anterior, comprobar propietario/permisos sin leerlo y reiniciar únicamente
   panel y monitor cuando sea necesario para que ambos carguen el mismo token.
4. **Canary** — seleccionar explícitamente un endpoint aprobado mediante la
   allowlist, ejecutar un único ciclo y comprobar solo resultados normalizados,
   ausencia de secretos y cero mutaciones/reinicios de VPN.
5. **Scheduler** — habilitar collection programada y observar al menos tres
   ciclos completos de 60 segundos. Validar timestamps, contadores, uso de
   recursos, logs normalizados y ausencia de reinicios de VPN.
6. **UI** — habilitar primero diagnósticos Admin y validar su detalle; habilitar
   alertas de usuario al final, verificando la matriz túnel/endpoint y la
   redacción de datos técnicos.

No adelantar un paso: si falla un gate, ejecutar el rollback acotado.

## Rotación del token

1. Mantener la UI como esté, pero desactivar collection y detener el scheduler
   para evitar peticiones durante la ventana corta de rotación.
2. Generar un token nuevo en `TOKEN_TMP` con el mismo bloque seguro, permisos y
   propietario; no inspeccionar su contenido.
3. Sustituir atómicamente el archivo con `mv -f "$TOKEN_TMP" "$TOKEN_FILE"`.
4. Reiniciar primero el panel y después el monitor para que ambos carguen el
   mismo archivo; comprobar rechazo sin token y éxito interno sin mostrarlo.
5. Reactivar el canary, después el scheduler y confirmar ciclos aceptados antes
   de volver al selector normal.

Si la rotación falla, mantener collection detenida; no recuperar el token desde
logs ni copiarlo a Git. Generar otro valor y repetir el procedimiento.

## Rollback acotado

1. Desactivar las alertas públicas y diagnósticos para desactivar la UI nueva.
2. Desactivar collection y detener el scheduler del monitor.
3. Retirar o revertir únicamente la referencia de imagen del monitor. Si el
   fallo está en panel o Caddy, volver a sus referencias inmutables anteriores
   después de detener la ingestión.
4. Conservar SQLite y sus tablas aditivas: no restaurar una copia completa de
   la base de datos como rollback rutinario. Solo usar el respaldo ante una
   corrupción demostrada y mediante el procedimiento de recuperación aprobado.
5. No reiniciar ni recrear contenedores VPN, no modificar perfiles y no cambiar
   el estado declarado de ninguna VPN.
6. Verificar login, rutas existentes, Caddy, Guacamole y runtime VPN. Registrar
   solo identidades, hashes y estados no sensibles.

El rollback termina al recuperar el servicio previo con el monitor y su UI
desactivados; las tablas de salud pueden permanecer para una promoción futura.
