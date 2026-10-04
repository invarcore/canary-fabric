# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""LlamaIndex integration for Canary Fabric: NodePostprocessor for RAG query engines."""

from typing import Any

from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkEncoder


class CanaryNodePostprocessor:
    """LlamaIndex NodePostprocessor that automatically injects cryptographic canaries into retrieved nodes."""

    def __init__(
        self,
        secret_key: str,
        tenant_id: str = "default_tenant",
        strategy: str = "organic",
    ) -> None:
        self.secret_key = secret_key
        self.tenant_id = tenant_id
        self.strategy = strategy

    def postprocess_nodes(
        self,
        nodes: list[Any],
        query_bundle: Any = None,
        session_nonce: str | None = None,
    ) -> list[Any]:
        """Watermark all retrieved NodeWithScore or TextNode instances before LLM synthesis."""
        watermarked_nodes = []

        for idx, item in enumerate(nodes):
            # LlamaIndex nodes can be NodeWithScore (item.node) or direct BaseNode (item)
            node_obj = getattr(item, "node", item)

            content = getattr(node_obj, "text", "")
            if not content and hasattr(node_obj, "get_content"):
                content = node_obj.get_content()

            metadata = getattr(node_obj, "metadata", {}) or {}
            node_id = getattr(node_obj, "node_id", f"node_{idx}")
            doc_id = str(metadata.get("document_id", metadata.get("file_name", node_id)))

            canary_token = derive_canary_token(
                secret_key=self.secret_key,
                tenant_id=self.tenant_id,
                doc_id=doc_id,
                chunk_id=str(node_id),
                session_nonce=session_nonce,
            )

            watermarked_text = WatermarkEncoder.inject_watermark(
                text=content,
                canary_token=canary_token,
                strategy=self.strategy,
            )

            # Update text and metadata
            if hasattr(node_obj, "text"):
                node_obj.text = watermarked_text
            metadata["_canary_token"] = canary_token
            metadata["_canary_active"] = True
            node_obj.metadata = metadata

            watermarked_nodes.append(item)

        return watermarked_nodes