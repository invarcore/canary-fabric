"""Synthetic Honeytoken and Decoy Artifact Generator."""

import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class HoneytokenType(str, Enum):
    API_KEY = "api_key"
    DB_URI = "db_uri"
    EMAIL = "email"
    EMPLOYEE_ID = "employee_id"
    JWT_SECRET = "jwt_secret"


@dataclass
class Honeytoken:
    token_id: str
    token_type: HoneytokenType
    value: str
    tenant_id: str
    doc_id: str
    description: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


class HoneytokenRegistry:
    """In-memory registry and matcher for active synthetic honeytokens."""

    def __init__(self) -> None:
        self._tokens: dict[str, Honeytoken] = {}

    def register(self, honeytoken: Honeytoken) -> None:
        self._tokens[honeytoken.value] = honeytoken

    def unregister(self, value: str) -> None:
        self._tokens.pop(value, None)

    def find_matches(self, text: str) -> list[Honeytoken]:
        """Scan text for any registered honeytokens."""
        if not text:
            return []
        matches = []
        for value, token in self._tokens.items():
            if value in text:
                matches.append(token)
        return matches

    def clear(self) -> None:
        self._tokens.clear()


class HoneytokenGenerator:
    """Generates high-fidelity synthetic honeytokens for canary documents."""

    def __init__(self, registry: HoneytokenRegistry | None = None) -> None:
        self.registry = registry or HoneytokenRegistry()

    def generate(
        self,
        token_type: HoneytokenType,
        tenant_id: str,
        doc_id: str,
        description: str = "",
        auto_register: bool = True,
    ) -> Honeytoken:
        """Generate a realistic synthetic honeytoken."""
        raw_nonce = secrets.token_hex(6).lower()
        token_id = f"ht_{token_type.value}_{raw_nonce}"

        if token_type == HoneytokenType.API_KEY:
            value = f"sk_live_canary_{secrets.token_hex(16)}"
        elif token_type == HoneytokenType.DB_URI:
            value = f"postgresql://canary_sec_app:k8s_{secrets.token_urlsafe(12)}@db.internal.corp:5432/{doc_id.lower()}_prod"
        elif token_type == HoneytokenType.EMAIL:
            value = f"canary-audit-{raw_nonce}@secops.internal"
        elif token_type == HoneytokenType.EMPLOYEE_ID:
            value = f"EMP-CANARY-{secrets.token_hex(4).upper()}"
        elif token_type == HoneytokenType.JWT_SECRET:
            value = f"canary_jwt_secret_{secrets.token_urlsafe(24)}"
        else:
            value = f"canary_token_{raw_nonce}"

        ht = Honeytoken(
            token_id=token_id,
            token_type=token_type,
            value=value,
            tenant_id=tenant_id,
            doc_id=doc_id,
            description=description,
        )

        if auto_register:
            self.registry.register(ht)

        return ht
