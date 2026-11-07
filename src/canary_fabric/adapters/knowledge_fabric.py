# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Native adapter for Knowledge Fabric evidence chunks and RAG pipelines."""

from __future__ import annotations

import hashlib
from typing import Any

from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.honeytoken import HoneytokenRegistry
from canary_fabric.core.lexical import CanaryMode, LexicalCanaryInjector
from canary_fabric.core.watermark import WatermarkEncoder


class KnowledgeFabricCanaryAdapter:
    """Wraps Knowledge Fabric retrieved evidence with invisible cryptographic and lexical canaries."""

    def __init__(
        self,
        secret_key: str,
        honeytoken_registry: HoneytokenRegistry | None = None,
    ) -> None:
        self.secret_key = secret_key
        self.registry = honeytoken_registry or HoneytokenRegistry()
        self.lexical_injector = LexicalCanaryInjector(
            secret_key=secret_key,
            honeytoken_registry=self.registry,
        )

    def watermark_chunk_tokens(
        self,
        chunk_text: str,
        tenant_id: str,
        doc_id: str,
        chunk_id: str,
        session_nonce: str | None = None,
        mode: CanaryMode | str = CanaryMode.STEGO,
    ) -> tuple[str, list[str]]:
        """Inject canaries into a chunk, returning the watermarked text and all active tokens."""
        op_mode = CanaryMode(mode) if isinstance(mode, str) else mode

        if op_mode == CanaryMode.STEGO:
            canary_token = derive_canary_token(
                secret_key=self.secret_key,
                tenant_id=tenant_id,
                doc_id=doc_id,
                chunk_id=chunk_id,
                session_nonce=session_nonce,
            )
            watermarked_text = WatermarkEncoder.inject_watermark(
                text=chunk_text,
                canary_token=canary_token,
                strategy="organic",
            )
            return watermarked_text, [canary_token]

        return self.lexical_injector.inject(
            text=chunk_text,
            tenant_id=tenant_id,
            doc_id=doc_id,
            chunk_id=chunk_id,
            mode=op_mode,
            session_nonce=session_nonce,
        )

    def watermark_chunk(
        self,
        chunk_text: str,
        tenant_id: str,
        doc_id: str,
        chunk_id: str,
        session_nonce: str | None = None,
        mode: CanaryMode | str = CanaryMode.STEGO,
    ) -> tuple[str, str]:
        """Inject canaries into a chunk, returning watermarked text and primary canary token."""
        text, tokens = self.watermark_chunk_tokens(
            chunk_text=chunk_text,
            tenant_id=tenant_id,
            doc_id=doc_id,
            chunk_id=chunk_id,
            session_nonce=session_nonce,
            mode=mode,
        )
        primary = tokens[0] if tokens else ""
        return text, primary

    def watermark_evidence_package(
        self,
        evidence_items: list[dict[str, Any]],
        tenant_id: str,
        session_nonce: str | None = None,
        mode: CanaryMode | str = CanaryMode.STEGO,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Batch-watermark a list of Knowledge Fabric evidence chunks."""
        watermarked_items = []
        tokens = []

        for item in evidence_items:
            doc_id = str(
                item.get("document_id")
                or item.get("document_uri")
                or item.get("source_uri")
                or "doc_unknown"
            )
            chunk_id = str(item.get("chunk_id", "chunk_0"))
            has_snippet = "snippet" in item
            raw_text = str(item.get("snippet") if has_snippet else item.get("content", ""))

            wm_content, item_tokens = self.watermark_chunk_tokens(
                chunk_text=raw_text,
                tenant_id=tenant_id,
                doc_id=doc_id,
                chunk_id=chunk_id,
                session_nonce=session_nonce,
                mode=mode,
            )

            new_item = dict(item)
            if has_snippet:
                new_item["snippet"] = wm_content
            new_item["content"] = wm_content

            new_digest = hashlib.sha256(wm_content.encode("utf-8")).hexdigest()
            if "chunk_hash" in item:
                new_item["chunk_hash"] = new_digest
            elif "provenance_hash" in item:
                new_item["chunk_hash"] = new_digest
            if "provenance_hash" in item:
                new_item["provenance_hash"] = new_digest

            new_item["_canary_tokens"] = item_tokens
            if item_tokens:
                new_item["_canary_token"] = item_tokens[0]
            watermarked_items.append(new_item)
            tokens.extend(item_tokens)

        return watermarked_items, tokens
