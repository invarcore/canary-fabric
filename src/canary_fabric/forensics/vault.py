"""SQLite WAL-backed Incident Vault for persistent tamper-evident forensic logging."""

import json
import sqlite3
from pathlib import Path

from canary_fabric.forensics.certificate import LeakCertificate
from canary_fabric.forensics.exporters import BaseIncidentExporter


class IncidentVault:
    """Tamper-evident SQLite WAL audit store for canary tripwire incidents.

    Automatically dispatches certificates to configured SIEM exporters (Webhooks, CEF, OTel).
    """

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        exporters: list[BaseIncidentExporter] | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.exporters = exporters or []
        self._is_memory = self.db_path == ":memory:" or "mode=memory" in self.db_path
        self._conn: sqlite3.Connection | None = None
        if self._is_memory:
            # Maintain persistent connection for in-memory database
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is not None:
            return self._conn
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS canary_incidents (
                certificate_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                source_doc_id TEXT NOT NULL,
                source_chunk_id TEXT NOT NULL,
                canary_token TEXT NOT NULL,
                leak_channel TEXT NOT NULL,
                action_taken TEXT NOT NULL,
                user_session_id TEXT,
                prompt_hash TEXT,
                signature TEXT NOT NULL,
                raw_certificate JSON NOT NULL
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_canary_incidents_tenant
            ON canary_incidents(tenant_id, timestamp);
        """)
        if not self._is_memory:
            conn.commit()
            conn.close()
        else:
            conn.commit()

    def record_certificate(self, cert: LeakCertificate) -> None:
        """Store a verified leak certificate in the vault and dispatch to exporters."""
        conn = self._get_connection()
        conn.execute(
            """
            INSERT OR REPLACE INTO canary_incidents (
                certificate_id, timestamp, tenant_id, source_doc_id, source_chunk_id,
                canary_token, leak_channel, action_taken, user_session_id, prompt_hash,
                signature, raw_certificate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """,
            (
                cert.certificate_id,
                cert.timestamp,
                cert.tenant_id,
                cert.source_doc_id,
                cert.source_chunk_id,
                cert.canary_token,
                cert.leak_channel,
                cert.action_taken,
                cert.user_session_id,
                cert.prompt_hash,
                cert.signature,
                cert.model_dump_json(),
            ),
        )
        conn.commit()
        if not self._is_memory:
            conn.close()

        # Dispatch to all registered SIEM / Webhook exporters
        for exporter in self.exporters:
            try:
                exporter.export(cert)
            except Exception:
                pass

    def get_certificate(self, certificate_id: str) -> LeakCertificate | None:
        """Retrieve a specific certificate by ID."""
        conn = self._get_connection()
        cursor = conn.execute(
            "SELECT raw_certificate FROM canary_incidents WHERE certificate_id = ?;",
            (certificate_id,),
        )
        row = cursor.fetchone()
        if not self._is_memory:
            conn.close()
        if not row:
            return None
        data = json.loads(row["raw_certificate"])
        return LeakCertificate.model_validate(data)

    def list_incidents(
        self,
        tenant_id: str | None = None,
        limit: int = 50,
    ) -> list[LeakCertificate]:
        """List recent leak incidents from the vault."""
        conn = self._get_connection()
        if tenant_id:
            cursor = conn.execute(
                "SELECT raw_certificate FROM canary_incidents WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?;",
                (tenant_id, limit),
            )
        else:
            cursor = conn.execute(
                "SELECT raw_certificate FROM canary_incidents ORDER BY timestamp DESC LIMIT ?;",
                (limit,),
            )

        records = []
        for row in cursor.fetchall():
            data = json.loads(row["raw_certificate"])
            records.append(LeakCertificate.model_validate(data))
        if not self._is_memory:
            conn.close()
        return records