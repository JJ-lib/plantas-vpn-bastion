# Forzar aplicación de cambios de VPN activa — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hacer que la edición de una VPN activa conserve y aplique la nueva configuración como el flujo de creación, sin rollback automático después de que la recreación de la VPN haya terminado.

**Architecture:** Mantener validación previa, lock por VPN, backup durable, persistencia atómica, generación completa y recreación únicamente de la VPN editada y sus sidecars. Si `apply_candidate` termina correctamente pero el gate de salud falla, conservar DB, artefactos y runtime candidatos, marcar la revisión como `applied_unhealthy` y mostrar un mensaje seguro. Si la aplicación misma falla antes de terminar, conservar el rollback de consistencia existente.

**Tech Stack:** Python/Flask, SQLite, Docker Compose, `unittest`, imagen Docker del panel.

---

### Task 1: Definir el contrato force-apply con una prueba RED

**Files:**
- Modify: `tests/test_vpn_active_edit.py`
- Modify: `panel-app/vpn_active_edit.py`

- [ ] **Step 1: Add the failing test**

Añadir una prueba que invoque `run_active_edit(..., rollback_on_failure=False)` con un `verify_candidate` que falle después de `apply_candidate`. Debe exigir estado `applied_unhealthy`, conservar el mensaje de que la nueva revisión permanece aplicada y demostrar que `restore_database` y `restore_runtime` no se ejecutan.

- [ ] **Step 2: Run the focused test and confirm RED**

Run inside the dependency-bearing panel image:

```bash
PYTHONPATH=/work/panel-app:/work/tests python -B -m unittest -v test_vpn_active_edit.ActiveVpnEditTests.test_force_apply_keeps_candidate_after_runtime_failure
```

Expected: failure because `run_active_edit` no acepta todavía `rollback_on_failure`.

### Task 2: Implementar la semántica de aplicación forzosa

**Files:**
- Modify: `panel-app/vpn_active_edit.py`
- Modify: `panel-app/app.py`

- [ ] **Step 1: Add the minimal engine behavior**

Añadir `rollback_on_failure=True` como valor compatible por defecto, marcar `runtime_started=True` solo después de que `apply_candidate` termine, y cuando el modo force-apply recibe un fallo de verificación posterior conservar el candidato, actualizar la revisión a `applied_unhealthy` y llamar a un hook que marque la VPN activa pero no saludable.

- [ ] **Step 2: Add the database state hook**

Implementar en `app.py` un hook que actualice solo la VPN editada con `validation_code='active_edit_applied_unhealthy'` y un texto público seguro. No escribir detalles técnicos, secretos ni credenciales.

- [ ] **Step 3: Route active edits through force-apply**

Usar `rollback_on_failure=False` en `_apply_active_vpn_edit`. Mantener rollback únicamente si la aplicación/recreación no llega a terminar, para evitar una DB candidata con runtime antiguo cuando Docker/Compose rechace la publicación.

- [ ] **Step 4: Redirect the applied-but-unhealthy result**

Tras un resultado `applied_unhealthy`, mostrar el mensaje mediante `flash` y volver al listado de VPNs, igual que el flujo de creación deja el resultado persistido.

### Task 3: Verificar, construir y desplegar solo el panel

**Files:**
- No additional source files.

- [ ] **Step 1: Run focused tests and compile checks**
- [ ] **Step 2: Run related onboarding/security tests with synthetic bootstrap values**
- [ ] **Step 3: Build an immutable panel image and smoke-test the exact image**
- [ ] **Step 4: Back up Compose, promote only `panel` with `--no-deps --force-recreate --pull never`, and verify non-panel IDs**
- [ ] **Step 5: Verify the live result and publish the commit**

**Acceptance:** A successful candidate application followed by a health-gate failure leaves the new candidate persisted and deployed, records `applied_unhealthy`, does not invoke automatic restoration, and exposes only a safe public message. A failure during the actual publication still restores consistency.
