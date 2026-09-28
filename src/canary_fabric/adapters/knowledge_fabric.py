"""Native adapter for Knowledge Fabric evidence chunks and RAG pipelines."""

from typing import Any

from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkEncoder


class KnowledgeFabricCanaryAdapter:
    """Wraps Knowledge Fabric retrieved evidence with invisible cryptographic canaries."""

    def __init__(self, secret_key: str) -> None:
        self.secret_key = secret_key

    def watermark_chunk(
        self,
        chunk_text: str,
        tenant_id: str,
        doc_id: str,
        chunk_id: str,
        session_nonce: str | None = None,
    ) -> tuple[str, str]:
        """Inject an invisible canary token into a retrieved Knowledge Fabric chunk.

        Returns:
            (watermarked_text, canary_token_hex)
        """
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
        return watermarked_text, canary_token

    def watermark_evidence_package(
        self,
        evidence_items: list[dict[str, Any]],
        tenant_id: str,
        session_nonce: str | None = None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Batch-watermark a list of Knowledge Fabric evidence chunks."""
        watermarked_items = []
        tokens = []

        for item in evidence_items:
            doc_id = str(item.get("document_id", "doc_unknown"))
            chunk_id = str(item.get("chunk_id", "chunk_0"))
            content = str(item.get("content", ""))

            wm_content, token = self.watermark_chunk(
                chunk_text=content,
                tenant_id=tenant_id,
                doc_id=doc_id,
                chunk_id=chunk_id,
                session_nonce=session_nonce,
            )

            new_item = dict(item)
            new_item["content"] = wm_content
            new_item["_canary_token"] = token
            watermarked_items.append(new_item)
            tokens.append(token)

        return watermarked_items, tokens
