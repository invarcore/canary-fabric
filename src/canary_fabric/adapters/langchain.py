"""LangChain integration for Canary Fabric: DocumentTransformer, Retriever, and CallbackHandler."""

from collections.abc import Sequence
from typing import Any

from canary_fabric.breaker.circuit import CircuitBreaker, TripwireEvent
from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder


class CanaryTripwireException(PermissionError):
    """Raised when Canary Fabric detects exfiltration of a protected canary token."""


class CanaryDocumentTransformer:
    """Injects zero-width steganographic canary tokens into LangChain Document objects."""

    def __init__(
        self,
        secret_key: str,
        tenant_id: str = "default_tenant",
        strategy: str = "organic",
    ) -> None:
        self.secret_key = secret_key
        self.tenant_id = tenant_id
        self.strategy = strategy

    def transform_documents(
        self,
        documents: Sequence[Any],
        session_nonce: str | None = None,
        **kwargs: Any,
    ) -> Sequence[Any]:
        """Watermark a sequence of LangChain Documents or duck-typed document objects.

        Each document's ``page_content`` has a 64-bit HMAC-derived canary invisibly
        injected, and metadata is populated with cryptographic provenance.
        """
        transformed = []
        for idx, doc in enumerate(documents):
            # Support both LangChain Document objects and dicts
            is_dict = isinstance(doc, dict)
            content = doc.get("page_content", "") if is_dict else getattr(doc, "page_content", "")
            metadata = doc.get("metadata", {}) if is_dict else getattr(doc, "metadata", {})

            doc_id = str(metadata.get("id", metadata.get("source", f"doc_{idx}")))
            chunk_id = str(metadata.get("chunk_id", f"chunk_{idx}"))

            canary_token = derive_canary_token(
                secret_key=self.secret_key,
                tenant_id=self.tenant_id,
                doc_id=doc_id,
                chunk_id=chunk_id,
                session_nonce=session_nonce,
            )

            watermarked_content = WatermarkEncoder.inject_watermark(
                text=content,
                canary_token=canary_token,
                strategy=self.strategy,
            )

            # Preserve metadata
            new_metadata = dict(metadata)
            new_metadata["_canary_token"] = canary_token
            new_metadata["_canary_active"] = True

            if is_dict:
                new_doc = dict(doc)
                new_doc["page_content"] = watermarked_content
                new_doc["metadata"] = new_metadata
                transformed.append(new_doc)
            else:
                # LangChain Document
                doc.page_content = watermarked_content
                doc.metadata = new_metadata
                transformed.append(doc)

        return transformed


class CanaryRetriever:
    """Wraps any LangChain BaseRetriever or duck-typed retriever to auto-inject canary tokens."""

    def __init__(
        self,
        base_retriever: Any,
        secret_key: str,
        tenant_id: str = "default_tenant",
        strategy: str = "organic",
    ) -> None:
        self.base_retriever = base_retriever
        self.transformer = CanaryDocumentTransformer(
            secret_key=secret_key,
            tenant_id=tenant_id,
            strategy=strategy,
        )

    def get_relevant_documents(self, query: str, **kwargs: Any) -> list[Any]:
        """Synchronously retrieve documents and watermark them."""
        docs = self.base_retriever.get_relevant_documents(query, **kwargs)
        return list(self.transformer.transform_documents(docs))

    def invoke(self, input: Any, **kwargs: Any) -> list[Any]:
        """LangChain Runnable protocol support (sync)."""
        if hasattr(self.base_retriever, "invoke"):
            docs = self.base_retriever.invoke(input, **kwargs)
        else:
            docs = self.get_relevant_documents(str(input), **kwargs)
        return list(self.transformer.transform_documents(docs))

    async def aget_relevant_documents(self, query: str, **kwargs: Any) -> list[Any]:
        """Asynchronously retrieve documents and watermark them."""
        if hasattr(self.base_retriever, "aget_relevant_documents"):
            docs = await self.base_retriever.aget_relevant_documents(query, **kwargs)
        else:
            docs = self.base_retriever.get_relevant_documents(query, **kwargs)
        return list(self.transformer.transform_documents(docs))

    async def ainvoke(self, input: Any, **kwargs: Any) -> list[Any]:
        """LangChain Runnable protocol support (async)."""
        if hasattr(self.base_retriever, "ainvoke"):
            docs = await self.base_retriever.ainvoke(input, **kwargs)
        else:
            docs = await self.aget_relevant_documents(str(input), **kwargs)
        return list(self.transformer.transform_documents(docs))


class CanaryCallbackHandler:
    """LangChain CallbackHandler to intercept streaming tokens and tool inputs in real-time."""

    def __init__(
        self,
        circuit_breaker: CircuitBreaker,
        active_canary_tokens: set[str] | None = None,
        tenant_id: str = "default_tenant",
    ) -> None:
        self.breaker = circuit_breaker
        self.active_canary_tokens = active_canary_tokens or set()
        self.tenant_id = tenant_id
        self._buffer = ""

    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        """Invoked on each new LLM streaming token. Raises CanaryTripwireException if leaked."""
        self._buffer += token
        if len(self._buffer) > 256:
            self._buffer = self._buffer[-128:]

        extracted = WatermarkDecoder.extract_tokens(self._buffer)
        for t in extracted:
            if not self.active_canary_tokens or t in self.active_canary_tokens:
                event = TripwireEvent(
                    canary_token=t,
                    tenant_id=self.tenant_id,
                    source_doc_id="langchain_llm_stream",
                    source_chunk_id="token",
                    matched_text_snippet=token,
                )
                _, replacement = self.breaker.handle_tripwire(event)
                raise CanaryTripwireException(
                    f"CanaryFabric security tripwire triggered: {replacement}"
                )

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        """Invoked before a tool executes. Raises CanaryTripwireException if tool input contains a canary."""
        extracted = WatermarkDecoder.extract_tokens(input_str)
        for t in extracted:
            if not self.active_canary_tokens or t in self.active_canary_tokens:
                tool_name = serialized.get("name", "unknown_tool")
                event = TripwireEvent(
                    canary_token=t,
                    tenant_id=self.tenant_id,
                    source_doc_id=f"langchain_tool_{tool_name}",
                    source_chunk_id="input",
                    matched_text_snippet=input_str[:200],
                )
                _, replacement = self.breaker.handle_tripwire(event)
                raise CanaryTripwireException(
                    f"CanaryFabric tool gate tripped for tool '{tool_name}': {replacement}"
                )