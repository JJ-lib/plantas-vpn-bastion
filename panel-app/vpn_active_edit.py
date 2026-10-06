from __future__ import annotations

import base64
import json
import os
import re
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from plant_paths import plant_artifact_dir


ACTIVE_EDIT_STATES = {"applying", "confirmed", "rolled_back", "rollback_failed"}
_MAX_FILE_BYTES = 8 * 1024 * 1024
_MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class ActiveEditHooks:
    stage_candidate: Callable[[Mapping[str, Any], Path], Any]
    validate_candidate: Callable[[Mapping[str, Any], Any], None]
    persist_candidate: Callable[[Any, Mapping[str, Any]], None]
    apply_candidate: Callable[[Any], None]
    verify_candidate: Callable[[Mapping[str, Any], Any], None]
    restore_database: Callable[[Any, Mapping[str, Any]], None]
    restore_runtime: Callable[[Mapping[str, Any]], None]
    finalize_candidate: Callable[[Any, Mapping[str, Any], int], None]
    cleanup_candidate: Callable[[Any], None] = lambda artifact: None


@dataclass(frozen=True)
class ActiveEditResult:
    state: str
    code: str
    message: str
    backup_id: int | None = None
    revision: int = 0


class ActiveEditError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.public_message = message


def ensure_active_edit_schema(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS vpn_active_edit_revisions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vpn_id INTEGER NOT NULL,
            base_revision INTEGER NOT NULL,
            candidate_revision INTEGER NOT NULL,
            state TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            snapshot_enc TEXT NOT NULL,
            failure_code TEXT NOT NULL DEFAULT '',
            failure_detail TEXT NOT NULL DEFAULT ''
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS ix_vpn_active_edit_revisions_vpn "
        "ON vpn_active_edit_revisions(vpn_id, created_at)"
    )
    conn.commit()


def _json_safe(value):
    if isinstance(value, bytes):
        return {"__type__": "bytes", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _json_restore(value):
    if isinstance(value, dict) and value.get("__type__") == "bytes":
        return base64.b64decode(str(value.get("value", "")))
    if isinstance(value, dict):
        return {key: _json_restore(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_restore(item) for item in value]
    return value


def _safe_relative(base: Path, path: Path) -> str:
    try:
        relative = path.resolve().relative_to(base.resolve())
    except ValueError as exc:
        raise ActiveEditError("backup_failed", "La ruta de backup queda fuera del proyecto.") from exc
    return relative.as_posix()


def _snapshot_tree(base: Path, root: Path) -> dict[str, Any]:
    root = root.resolve()
    item: dict[str, Any] = {
        "root": _safe_relative(base, root),
        "exists": root.exists(),
        "mode": stat.S_IMODE(root.stat().st_mode) if root.exists() else 0,
        "dirs": [],
        "files": [],
        "bytes": 0,
    }
    if not root.exists():
        return item
    if root.is_symlink() or not root.is_dir():
        raise ActiveEditError("backup_failed", "Los artefactos de la VPN no tienen una estructura segura.")
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ActiveEditError("backup_failed", "Los artefactos de la VPN contienen un enlace no permitido.")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            item["dirs"].append({"path": relative, "mode": stat.S_IMODE(path.stat().st_mode)})
            continue
        if not path.is_file():
            raise ActiveEditError("backup_failed", "Los artefactos de la VPN contienen un tipo no permitido.")
        size = path.stat().st_size
        if size > _MAX_FILE_BYTES or item["bytes"] + size > _MAX_SNAPSHOT_BYTES:
            raise ActiveEditError("backup_failed", "Los artefactos de la VPN superan el límite de backup.")
        item["bytes"] += size
        item["files"].append(
            {
                "path": relative,
                "mode": stat.S_IMODE(path.stat().st_mode),
                "content": base64.b64encode(path.read_bytes()).decode("ascii"),
            }
        )
    return item


def capture_active_edit_snapshot(base, old_row: Mapping[str, Any]) -> dict[str, Any]:
    base = Path(base).resolve()
    slug = str(old_row.get("slug") or "")
    configs = base / "configs" / slug
    artifacts = plant_artifact_dir(base, slug)
    return {
        "version": 1,
        "row": {str(key): _json_safe(value) for key, value in dict(old_row).items()},
        "trees": [_snapshot_tree(base, configs), _snapshot_tree(base, artifacts)],
    }


def _remove_tree(path: Path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def restore_active_edit_snapshot(base, snapshot: Mapping[str, Any]):
    base = Path(base).resolve()
    trees = snapshot.get("trees")
    if not isinstance(trees, list):
        raise ActiveEditError("rollback_failed", "El backup durable no tiene un formato válido.")
    for tree in trees:
        if not isinstance(tree, dict):
            raise ActiveEditError("rollback_failed", "El backup durable no tiene un formato válido.")
        relative = str(tree.get("root") or "")
        root = (base / relative).resolve()
        try:
            root.relative_to(base)
        except ValueError as exc:
            raise ActiveEditError("rollback_failed", "El backup durable apunta fuera del proyecto.") from exc
        _remove_tree(root)
        if not tree.get("exists"):
            continue
        root.mkdir(parents=True, exist_ok=True)
        os.chmod(root, int(tree.get("mode") or 0o700))
        for directory in sorted(tree.get("dirs") or [], key=lambda value: str(value.get("path", "")).count("/")):
            child = root / str(directory.get("path") or "")
            child.mkdir(parents=True, exist_ok=True)
            os.chmod(child, int(directory.get("mode") or 0o700))
        for file_item in tree.get("files") or []:
            child = (root / str(file_item.get("path") or "")).resolve()
            try:
                child.relative_to(root)
            except ValueError as exc:
                raise ActiveEditError("rollback_failed", "El backup durable contiene una ruta inválida.") from exc
            child.parent.mkdir(parents=True, exist_ok=True)
            child.write_bytes(base64.b64decode(str(file_item.get("content") or "")))
            os.chmod(child, int(file_item.get("mode") or 0o600))


def _snapshot_payload(snapshot):
    return json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def create_active_edit_backup(conn, old_row, snapshot, seal, now=None, candidate_revision=None) -> int:
    now = int(time.time() if now is None else now)
    base_revision = int(old_row.get("onboarding_revision") or 0)
    candidate_revision = int(candidate_revision if candidate_revision is not None else base_revision + 1)
    sealed = seal(_snapshot_payload(snapshot))
    if not isinstance(sealed, str) or not sealed:
        raise ActiveEditError("backup_failed", "No se pudo sellar el backup durable.")
    cur = conn.execute(
        """INSERT INTO vpn_active_edit_revisions(
            vpn_id,base_revision,candidate_revision,state,created_at,updated_at,
            snapshot_enc,failure_code,failure_detail
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            int(old_row["id"]),
            base_revision,
            candidate_revision,
            "applying",
            now,
            now,
            sealed,
            "",
            "",
        ),
    )
    conn.commit()
    return int(cur.lastrowid)


def load_active_edit_snapshot(conn, backup_id, unseal):
    row = conn.execute(
        "SELECT snapshot_enc FROM vpn_active_edit_revisions WHERE id=?",
        (int(backup_id),),
    ).fetchone()
    if not row:
        raise ActiveEditError("backup_missing", "No existe el backup durable de la revisión.")
    try:
        payload = json.loads(unseal(row[0]))
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError
        return _json_restore(payload)
    except Exception as exc:
        raise ActiveEditError("backup_invalid", "No se pudo abrir el backup durable de la revisión.") from exc


def _update_backup(conn, backup_id, state, now, failure_code="", failure_detail=""):
    if state not in ACTIVE_EDIT_STATES:
        raise ValueError("Estado de revisión activa no válido.")
    conn.execute(
        """UPDATE vpn_active_edit_revisions
           SET state=?,updated_at=?,failure_code=?,failure_detail=?
         WHERE id=?""",
        (state, int(now), str(failure_code or ""), str(failure_detail or "")[:240], int(backup_id)),
    )
    conn.commit()


def _failure_code(exc, phase):
    if isinstance(exc, ActiveEditError):
        return exc.code
    text = str(exc or "").lower()
    if phase == "preflight":
        return "candidate_invalid"
    if "target" in text or "conect" in text:
        return "target_gate_failed"
    if "auth" in text or "cred" in text:
        return "auth_failed"
    if "proposal" in text or "propuesta" in text:
        return "proposal_failed"
    if "listener" in text or "haproxy" in text:
        return "listener_gate_failed"
    return "runtime_failed"


def _safe_failure_detail(exc):
    text = str(getattr(exc, "public_message", exc) or "")
    text = re.sub(r"(?i)(password|psk|secret|xauth)\s*[=:].*", r"\1=REDACTED", text)
    text = re.sub(r"(?i)encx\s+\S+", "REDACTED", text)
    return text[:240] or "fallo_no_detallado"


def run_active_edit(
    conn,
    old_row: Mapping[str, Any],
    candidate_row: Mapping[str, Any],
    base,
    hooks: ActiveEditHooks,
    *,
    seal: Callable[[str], str],
    unseal: Callable[[str], str],
    now=None,
) -> ActiveEditResult:
    now = int(time.time() if now is None else now)
    base = Path(base).resolve()
    old = dict(old_row)
    candidate = dict(candidate_row)
    revision = int(candidate.get("onboarding_revision") or (int(old.get("onboarding_revision") or 0) + 1))

    artifact = None
    try:
        artifact = hooks.stage_candidate(candidate, base)
        hooks.validate_candidate(candidate, artifact)
    except Exception as exc:
        if artifact is not None:
            try:
                hooks.cleanup_candidate(artifact)
            except Exception:
                pass
        return ActiveEditResult(
            "rejected",
            "candidate_invalid",
            "La configuración candidata no supera la validación previa.",
            revision=revision,
        )

    try:
        snapshot = capture_active_edit_snapshot(base, old)
        backup_id = create_active_edit_backup(
            conn,
            old,
            snapshot,
            seal,
            now=now,
            candidate_revision=revision,
        )
    except Exception as exc:
        if artifact is not None:
            try:
                hooks.cleanup_candidate(artifact)
            except Exception:
                pass
        try:
            conn.rollback()
        except Exception:
            pass
        return ActiveEditResult(
            "rejected",
            "backup_failed",
            "No se pudo crear el backup durable; no se aplicó ningún cambio.",
            revision=revision,
        )

    persisted = False
    runtime_started = False
    try:
        hooks.persist_candidate(conn, candidate)
        persisted = True
        runtime_started = True
        hooks.apply_candidate(artifact)
        hooks.verify_candidate(candidate, artifact)
        hooks.finalize_candidate(conn, candidate, backup_id)
        _update_backup(conn, backup_id, "confirmed", now)
        result = ActiveEditResult(
            "confirmed",
            "active_edit_confirmed",
            "La edición se aplicó y superó todos los gates.",
            backup_id=backup_id,
            revision=revision,
        )
        try:
            hooks.cleanup_candidate(artifact)
        except Exception:
            pass
        return result
    except Exception as failure:
        failure_code = _failure_code(failure, "runtime")
        failure_detail = _safe_failure_detail(failure)
        rollback_ok = True
        try:
            if persisted:
                hooks.restore_database(conn, old)
        except Exception:
            rollback_ok = False
        try:
            if runtime_started:
                snapshot = load_active_edit_snapshot(conn, backup_id, unseal)
                restore_active_edit_snapshot(base, snapshot)
                hooks.restore_runtime(old)
        except Exception:
            rollback_ok = False
        state = "rolled_back" if rollback_ok else "rollback_failed"
        code = failure_code if rollback_ok else "rollback_failed"
        message = (
            "La nueva revisión falló y se revirtió automáticamente."
            if rollback_ok
            else "La revisión falló y el rollback automático no terminó; requiere intervención administrativa."
        )
        try:
            _update_backup(conn, backup_id, state, now, code, failure_detail)
        except Exception:
            pass
        result = ActiveEditResult(
            state,
            code,
            message,
            backup_id=backup_id,
            revision=revision,
        )
        try:
            hooks.cleanup_candidate(artifact)
        except Exception:
            pass
        return result
