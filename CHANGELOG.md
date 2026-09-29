# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-09-29

### Added
- **Ecosystem Framework Adapters**:
  - **LangChain**: `CanaryDocumentTransformer`, `CanaryRetriever`, and `CanaryCallbackHandler` for seamless document watermarking and token/tool-start exfiltration gating.
  - **LlamaIndex**: `CanaryNodePostprocessor` for post-retrieval node watermarking before response synthesis.
  - **OpenAI & LiteLLM**: `CanaryStreamWrapper` and `wrap_streaming_response` for client-side streaming tripwire enforcement.
- **Wire-Level Proxy Hardening & Tool-Call Scanner**:
  - Real-time partial JSON parameter scanning for streaming tool calls (`choices[0].delta.tool_calls[].function.arguments`) to catch agent context leaks into external tool APIs.
  - Persistent HTTP client connection pooling via FastAPI `lifespan` context manager.
  - Dynamic upstream URL resolution via `CANARY_UPSTREAM_URL` environment variable or `X-Upstream-Url` request header.
- **Keyed Semantic Micro-Synonym Steganography**:
  - `SemanticWatermarker` fallback steganography using deterministic pseudo-random synonym substitution ($p < 0.001$ statistical confidence) for environments that strip zero-width Unicode characters.
- **Synthetic Adversarial Red-Team Benchmark Suite**:
  - `RedTeamEvaluator` profiling canary retention and circuit breaker performance across 5 attack vectors (Verbatim Extraction, Paraphrasing, Summarization, Translation, Base64 Obfuscation).
  - New interactive CLI command: `canary-fabric eval`.
- **Enterprise SIEM & Telemetry Exporters**:
  - Pluggable incident exporters in `IncidentVault`: `WebhookExporter` (signed HTTPS POST), `CEFExporter` (Common Event Format for Splunk/Sentinel/QRadar), and `OpenTelemetryExporter` (distributed tracing spans).
- **Packaging & CI Automation**:
  - `.github/workflows/release.yml` for automated wheel builds and GitHub releases on tag push.
  - PEP 561 `py.typed` typing marker for static type checker compliance.

## [0.1.0] - 2026-09-28

### Added
- **4-ary Zero-Width Unicode Steganography**: Invisible 64-bit HMAC-derived watermark encoder & decoder using `\u200B`, `\u200C`, `\u200D`, and `\uFEFF` with non-colliding LRM/RLM framing sentinels.
- **Ultra-Low-Latency Stream Watcher**: Real-time sliding ring-buffer scanner with `<0.8ms` (3.12 µs benchmarked) inspection tax per streaming chunk.
- **Active Tripwire Circuit Breaker**: Instant socket severance and output replacement preventing confidential RAG chunk exfiltration.
- **Synthetic Honeytoken Generator & Registry**: High-fidelity decoy API keys, database URIs, canary emails, and employee credentials.
- **Tamper-Evident Forensic Vault**: SQLite WAL audit storage and cryptographically signed `LeakCertificate` with HMAC non-repudiation.
- **Ecosystem Adapters**: Native integration with `Knowledge Fabric` (`knowledge-fabric`), `Intent Fabric` (`intent-fabric`), and FastMCP security gate decorator (`@canary_gate`).
- **CLI & Reverse Proxy**: Comprehensive CLI with `watermark`, `inspect`, `honeytoken`, `verify`, `benchmark`, and `canary-proxy` streaming reverse proxy.
- **Backward-Compatible Alias**: Full alias export supporting `promptcanary` (`import canary_fabric as promptcanary`).