# VPN Endpoint Monitor Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use software-development:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cerrar mediante TDD la migración SQLite compatible/repetible, la persistencia tras reapertura, el pin exacto de `ike-scan` y el procedimiento seguro de token, promoción y rollback.

**Architecture:** La migración seguirá siendo propiedad de `panel-app` y detectará cualquier esquema incompleto antes de reconstruirlo atómicamente. Un test operativo estático vinculará Dockerfile y runbook para impedir que se desalineen la versión fijada, la gestión del token, el orden de promoción y el rollback acotado.

**Tech Stack:** Python 3.12, `unittest`, SQLite, Markdown, Dockerfile.

---

### Task 1: Migración y persistencia SQLite

**Files:**
- Modify: `tests/test_vpn_endpoint_health.py`
- Modify: `panel-app/vpn_endpoint_health.py`

- [ ] Añadir un test file-backed que parta de un esquema parcialmente migrado, preserve estado/eventos, ejecute la migración dos veces, cierre y reabra SQLite.
- [ ] Ejecutar el test y observar RED por columnas modernas ausentes.
- [ ] Hacer que la detección compare el conjunto completo de columnas requeridas y reconstruya cualquier esquema incompleto.
- [ ] Ejecutar el test y observar GREEN.

### Task 2: Contrato operativo verificable

**Files:**
- Create: `tests/test_vpn_endpoint_monitor_operations.py`
- Create: `docs/operations/vpn-endpoint-monitor-rollout.md`
- Modify: `README.md`

- [ ] Añadir tests que exijan `ike-scan=1.9.5-2` tanto en Dockerfile como en documentación.
- [ ] Añadir tests que exijan generación criptográfica, permisos, rotación sin imprimir el token y rollback sin tocar VPN ni restaurar SQLite rutinariamente.
- [ ] Añadir test de orden estricto: panel → Caddy → token → canary → scheduler → UI.
- [ ] Ejecutar tests y observar RED por runbook ausente.
- [ ] Escribir el runbook operativo en español y enlazarlo desde README.
- [ ] Ejecutar tests y observar GREEN.

### Task 3: Verificación

**Files:** todos los modificados.

- [ ] Formatear Python con la herramienta disponible sin cambiar semántica.
- [ ] Ejecutar tests focalizados y suite completa.
- [ ] Ejecutar `compileall`, `git diff --check`, revisión del diff y búsqueda de secretos.
- [ ] Confirmar que `docker-compose.yml` y su `command` no cambiaron y que no se creó ningún commit.
