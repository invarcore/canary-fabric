# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-28

### Added
- **4-ary Zero-Width Unicode Steganography**: Invisible 64-bit HMAC-derived watermark encoder & decoder using `\u200B`, `\u200C`, `\u200D`, and `\uFEFF` with non-colliding LRM/RLM framing sentinels.
- **Ultra-Low-Latency Stream Watcher**: Real-time sliding ring-buffer scanner with `<0.8ms` (3.12µs benchmarked) inspection tax per streaming chunk.
- **Active Tripwire Circuit Breaker**: Instant socket severance and output replacement preventing confidential RAG chunk exfiltration.
- **Synthetic Honeytoken Generator & Registry**: High-fidelity decoy API keys, database URIs, canary emails, and employee credentials.
- **Tamper-Evident Forensic Vault**: SQLite WAL audit storage and cryptographically signed `LeakCertificate` with HMAC non-repudiation.
- **Ecosystem Adapters**: Native integration with `Knowledge Fabric` (`knowledge-fabric`), `Intent Fabric` (`intent-fabric`), and FastMCP security gate decorator (`@canary_gate`).
- **CLI & Reverse Proxy**: Comprehensive CLI with `watermark`, `scan`, `honeytoken`, `cert-verify`, `benchmark`, and `canary-proxy` streaming reverse proxy.
- **Backward-Compatible Alias**: Full alias export supporting `promptcanary` (`import canary_fabric as promptcanary`).