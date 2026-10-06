import base64
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "panel-app"))

from vpn_active_edit import (
    ActiveEditHooks,
    ensure_active_edit_schema,
    load_active_edit_snapshot,
    run_active_edit,
)


class ActiveVpnEditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        (self.base / "configs/demo").mkdir(parents=True)
        (self.base / "plants/demo").mkdir(parents=True)
        (self.base / "configs/demo/ipsec.conf").write_text("old-conf", encoding="utf-8")
        (self.base / "configs/demo/ipsec.secrets").write_text("old-secret", encoding="utf-8")
        (self.base / "plants/demo/compose.yml").write_text("old-compose", encoding="utf-8")
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.execute(
            "CREATE TABLE vpns(id INTEGER PRIMARY KEY, slug TEXT, onboarding_revision INTEGER DEFAULT 4)"
        )
        self.conn.execute("INSERT INTO vpns(id,slug,onboarding_revision) VALUES(1,'demo',4)")
        ensure_active_edit_schema(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    @staticmethod
    def seal(value):
        return "sealed:" + base64.urlsafe_b64encode(value.encode()).decode()

    @staticmethod
    def unseal(value):
        return base64.urlsafe_b64decode(value.removeprefix("sealed:")).decode()

    def row(self):
        return dict(self.conn.execute("SELECT * FROM vpns WHERE id=1").fetchone())

    def hooks(self, verify_error=None, rollback_error=None):
        calls = []

        def stage(candidate, base):
            calls.append("stage")
            return {"candidate": dict(candidate)}

        def validate(candidate, artifact):
            calls.append("validate")

        def persist(conn, candidate):
            calls.append("persist")
            conn.execute(
                "UPDATE vpns SET onboarding_revision=?,slug=? WHERE id=1",
                (candidate["onboarding_revision"], candidate["slug"]),
            )
            conn.commit()

        def apply(artifact):
            calls.append("apply")
            (self.base / "configs/demo/ipsec.conf").write_text("new-conf", encoding="utf-8")

        def verify(candidate, artifact):
            calls.append("verify")
            if verify_error:
                raise RuntimeError(verify_error)

        def restore_db(conn, old):
            calls.append("restore_db")
            conn.execute(
                "UPDATE vpns SET onboarding_revision=?,slug=? WHERE id=1",
                (old["onboarding_revision"], old["slug"]),
            )
            conn.commit()

        def restore_runtime(old):
            calls.append("restore_runtime")
            if rollback_error:
                raise RuntimeError(rollback_error)

        def finalize(conn, candidate, backup_id):
            calls.append("finalize")

        return ActiveEditHooks(
            stage_candidate=stage,
            validate_candidate=validate,
            persist_candidate=persist,
            apply_candidate=apply,
            verify_candidate=verify,
            restore_database=restore_db,
            restore_runtime=restore_runtime,
            finalize_candidate=finalize,
        ), calls

    def test_success_confirms_and_stores_encrypted_durable_backup(self):
        old = {"id": 1, "slug": "demo", "onboarding_revision": 4, "password_enc": "ciphertext"}
        candidate = {**old, "onboarding_revision": 5, "password_enc": "new-ciphertext"}
        hooks, calls = self.hooks()

        result = run_active_edit(
            self.conn,
            old,
            candidate,
            self.base,
            hooks,
            seal=self.seal,
            unseal=self.unseal,
            now=1000,
        )

        self.assertEqual(result.state, "confirmed")
        self.assertEqual(result.code, "active_edit_confirmed")
        self.assertEqual(calls, ["stage", "validate", "persist", "apply", "verify", "finalize"])
        revision = self.conn.execute(
            "SELECT state,snapshot_enc FROM vpn_active_edit_revisions WHERE id=?",
            (result.backup_id,),
        ).fetchone()
        self.assertEqual(revision[0], "confirmed")
        self.assertNotIn("ciphertext", revision[1])
        snapshot = load_active_edit_snapshot(self.conn, result.backup_id, self.unseal)
        self.assertEqual(snapshot["row"]["password_enc"], "ciphertext")

    def test_backup_failure_cleans_staged_candidate(self):
        old = {"id": 1, "slug": "demo", "onboarding_revision": 4}
        candidate = {**old, "onboarding_revision": 5}
        hooks, calls = self.hooks()
        cleaned = []
        hooks = ActiveEditHooks(
            stage_candidate=hooks.stage_candidate,
            validate_candidate=hooks.validate_candidate,
            persist_candidate=hooks.persist_candidate,
            apply_candidate=hooks.apply_candidate,
            verify_candidate=hooks.verify_candidate,
            restore_database=hooks.restore_database,
            restore_runtime=hooks.restore_runtime,
            finalize_candidate=hooks.finalize_candidate,
            cleanup_candidate=lambda artifact: cleaned.append(artifact),
        )

        def fail_seal(value):
            raise RuntimeError("seal unavailable")

        result = run_active_edit(
            self.conn,
            old,
            candidate,
            self.base,
            hooks,
            seal=fail_seal,
            unseal=self.unseal,
            now=1000,
        )

        self.assertEqual(result.state, "rejected")
        self.assertEqual(result.code, "backup_failed")
        self.assertEqual(len(cleaned), 1)
        self.assertEqual(calls, ["stage", "validate"])
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM vpn_active_edit_revisions").fetchone()[0],
            0,
        )

    def test_persist_failure_does_not_restore_or_restart_runtime(self):
        old = {"id": 1, "slug": "demo", "onboarding_revision": 4}
        candidate = {**old, "onboarding_revision": 5}
        hooks, calls = self.hooks()

        def fail_persist(conn, candidate_row):
            calls.append("persist")
            raise RuntimeError("stale revision")

        hooks = ActiveEditHooks(
            stage_candidate=hooks.stage_candidate,
            validate_candidate=hooks.validate_candidate,
            persist_candidate=fail_persist,
            apply_candidate=hooks.apply_candidate,
            verify_candidate=hooks.verify_candidate,
            restore_database=hooks.restore_database,
            restore_runtime=hooks.restore_runtime,
            finalize_candidate=hooks.finalize_candidate,
        )
        result = run_active_edit(
            self.conn,
            old,
            candidate,
            self.base,
            hooks,
            seal=self.seal,
            unseal=self.unseal,
            now=1000,
        )

        self.assertEqual(result.state, "rolled_back")
        self.assertEqual(result.code, "runtime_failed")
        self.assertEqual(calls, ["stage", "validate", "persist"])
        self.assertEqual(self.row()["onboarding_revision"], 4)

    def test_failed_gate_restores_database_files_and_runtime(self):
        old = {"id": 1, "slug": "demo", "onboarding_revision": 4}
        candidate = {**old, "onboarding_revision": 5}
        hooks, calls = self.hooks(verify_error="target gate failed")

        result = run_active_edit(
            self.conn,
            old,
            candidate,
            self.base,
            hooks,
            seal=self.seal,
            unseal=self.unseal,
            now=1000,
        )

        self.assertEqual(result.state, "rolled_back")
        self.assertEqual(result.code, "target_gate_failed")
        self.assertEqual(self.row()["onboarding_revision"], 4)
        self.assertEqual((self.base / "configs/demo/ipsec.conf").read_text(), "old-conf")
        self.assertEqual(
            calls,
            ["stage", "validate", "persist", "apply", "verify", "restore_db", "restore_runtime"],
        )
        state = self.conn.execute(
            "SELECT state,failure_code FROM vpn_active_edit_revisions WHERE id=?",
            (result.backup_id,),
        ).fetchone()
        self.assertEqual(tuple(state), ("rolled_back", "target_gate_failed"))

    def test_rollback_failure_is_explicit_and_keeps_durable_backup(self):
        old = {"id": 1, "slug": "demo", "onboarding_revision": 4}
        candidate = {**old, "onboarding_revision": 5}
        hooks, _ = self.hooks(verify_error="runtime failed", rollback_error="restore failed")

        result = run_active_edit(
            self.conn,
            old,
            candidate,
            self.base,
            hooks,
            seal=self.seal,
            unseal=self.unseal,
            now=1000,
        )

        self.assertEqual(result.state, "rollback_failed")
        self.assertEqual(result.code, "rollback_failed")
        state = self.conn.execute(
            "SELECT state FROM vpn_active_edit_revisions WHERE id=?",
            (result.backup_id,),
        ).fetchone()[0]
        self.assertEqual(state, "rollback_failed")

    def test_preflight_failure_does_not_persist_or_mutate_live_files(self):
        old = {"id": 1, "slug": "demo", "onboarding_revision": 4}
        candidate = {**old, "onboarding_revision": 5}
        hooks, calls = self.hooks()

        def reject(candidate, artifact):
            calls.append("validate")
            raise ValueError("candidate syntax invalid")

        hooks = ActiveEditHooks(
            stage_candidate=hooks.stage_candidate,
            validate_candidate=reject,
            persist_candidate=hooks.persist_candidate,
            apply_candidate=hooks.apply_candidate,
            verify_candidate=hooks.verify_candidate,
            restore_database=hooks.restore_database,
            restore_runtime=hooks.restore_runtime,
            finalize_candidate=hooks.finalize_candidate,
        )

        result = run_active_edit(
            self.conn,
            old,
            candidate,
            self.base,
            hooks,
            seal=self.seal,
            unseal=self.unseal,
            now=1000,
        )

        self.assertEqual(result.state, "rejected")
        self.assertEqual(result.code, "candidate_invalid")
        self.assertEqual(calls, ["stage", "validate"])
        self.assertEqual((self.base / "configs/demo/ipsec.conf").read_text(), "old-conf")
        self.assertEqual(
            self.conn.execute("SELECT COUNT(*) FROM vpn_active_edit_revisions").fetchone()[0],
            0,
        )


if __name__ == "__main__":
    unittest.main()
