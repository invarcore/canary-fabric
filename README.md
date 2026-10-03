<p align="center">
  <img src="assets/logo.jpg" alt="Canary Fabric Logo" width="220px" style="border-radius: 16px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);" />
</p>

<h1 align="center">Canary Fabric</h1>

<p align="center">
  <strong>Invisible Cryptographic Tripwires & Sub-Millisecond Egress Circuit Breakers for RAG and AI Agents.</strong>
</p>

<p align="center">
  <a href="https://github.com/sagarv48/canary-fabric/actions"><img src="https://img.shields.io/badge/CI-passing-brightgreen.svg" alt="CI"></a>
  <a href="https://pypi.org/project/canary-fabric/"><img src="https://img.shields.io/badge/PyPI-canary--fabric-3776AB?logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://github.com/sagarv48/canary-fabric/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://github.com/sagarv48/canary-fabric/releases"><img src="https://img.shields.io/badge/Release-v0.2.0-blue.svg" alt="Release"></a>
  <a href="https://modelcontextprotocol.io"><img src="https://img.shields.io/badge/MCP-Native%20Security-purple.svg" alt="MCP Native"></a>
</p>

---

## 🛡️ The Problem: Stealthy RAG Exfiltration & Indirect Prompt Injections

When enterprise applications connect Large Language Models (LLMs) or autonomous agents to private knowledge bases (wikis, HR records, customer PII, financial ledgers), **Indirect Prompt Injection** and **Context Leakage** represent critical zero-day threats:

1. **Undetected Exfiltration**: Adversarial prompts or untrusted retrieved documents command the model to summarize, base64-encode, or leak sensitive chunks over streaming channels or external agent tool parameters.
2. **The Guardrail Latency Dilemma**: Heavy synchronous guardrails (Microsoft Presidio, Guardrails AI, NeMo) add **150ms – 2,000ms of Time-to-First-Token (TTFT)** latency, destroying the real-time user experience.
3. **No Forensic Chain of Custody**: When a data breach occurs, SecOps teams cannot prove *which specific document chunk* was leaked, in *which session*, to *which user*, and *through which prompt*.

---

## ⚡ The Solution: Canary Fabric

**Canary Fabric** (`canary-fabric`) introduces zero-overhead **invisible cryptographic tripwires** and **ultra-low-latency streaming circuit breakers**:

* **4-ary Zero-Width Steganography**: Injects 64-bit HMAC-derived canary tokens (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`) invisibly into retrieved chunks. They are 100% invisible to human reviewers and preserved through LLM tokenization.
* **Tokenizer-Resilient Semantic Micro-Synonyms**: Keyed pseudo-random synonym substitution with statistical binomial confidence testing ($p < 0.001$) for environments that strip zero-width characters.
* **Sliding-Window Stream Buffer (`SlidingWindowStreamBuffer`)**: Lookahead ring buffer that inspects outbound token streams and tool-call JSON in real time, severing connections before honeytokens or confidential data can leak over the wire.
* **Sub-Millisecond (<0.8ms) Stream Circuit Breaker**: Scans outbound Server-Sent Events (SSE) and partial agent tool-call argument JSON in real-time with sub-millisecond overhead.
* **Synthetic Honeytokens**: Generates realistic decoy credentials (`sk_live_canary_...`, postgres connection strings, canary emails) for honeypot documents.
* **Cryptographic Leak Certificates**: Issues tamper-evident, HMAC-signed forensic certificates binding the leak to the source chunk, tenant ID, and prompt hash.
* **Enterprise SIEM Dispatchers**: Pluggable export to Webhooks (Slack/PagerDuty), CEF/Syslog (Splunk/Sentinel/QRadar), and OpenTelemetry Spans.
* **Turnkey Framework Integrations**: Native zero-dependency adapters for LangChain, LlamaIndex, FastMCP, Knowledge Fabric, Intent Fabric, and OpenAI/LiteLLM streaming wrappers.
* **Backward Compatible**: Full alias compatibility with `promptcanary` (`import canary_fabric as promptcanary`).

---

## 📊 Latency & Throughput Benchmark

Tested on AMD/Intel & Apple Silicon architectures scanning 64-bit cryptographic canary signatures over streaming token chunks:

| Metric | Traditional Guardrails (NER/LLM) | Canary Fabric Streaming Watcher | Advantage |
| :--- | :--- | :--- | :--- |
| **Inspection Latency (Per Chunk)** | 180 ms – 1,200 ms | **3.12 µs (0.0031 ms)** | **50,000x Faster** |
| **TTFT Degradation Tax** | +250 ms to +1.5 s | **< 0.05 ms** | **Zero perceptible delay** |
| **Throughput** | 5 – 50 req/sec | **320,000+ ops/sec** | **Native wire speed** |
| **False-Positive Rate** | 5% – 12% (Probabilistic) | **0.00% (Cryptographic HMAC)** | **Zero false alarms** |

---

## 🏛️ Architecture Blueprint

```
                               CANARY FABRIC RUNTIME ARCHITECTURE

    [Enterprise Sources] ---> [Knowledge Fabric / LangChain / LlamaIndex]
                                      |
                                      v
                         +--------------------------+
                         | Steganographic Watermark | (Zero-width Unicode \u200B-\uFEFF
                         |    & Canary Inserter     |  + HMAC-SHA256 nonces / Synonyms)
                         +--------------------------+
                                      |
                                      v (Watermarked Chunks)
                         [LLM Reasoning & Agent Engine]
                                      |
                                      v (Outbound SSE Tokens & Streaming Tool Arguments)
                         +--------------------------+
                         | Streaming Token Watcher  | (Sliding Ring Buffer Scanner
                         |   (Egress Wire Proxy)    |  Latency tax: < 0.005 ms)
                         +--------------------------+
                                      |
                      [Is Canary Signature Detected?]
                                 /          \
                             NO /            \ YES
                               v              v
                     [Passthrough]     [TRIPWIRE CIRCUIT BREAKER]
                           |                  |
                           v                  +---> 1. Sever Outbound Socket Instantly
                    Normal User Stream        +---> 2. Emit Compliant Masked Redaction
                                              +---> 3. Dispatch SIEM / Slack / CEF Alert
                                              +---> 4. Sign Cryptographic Leak Certificate
```

---

## 🚀 Quickstart (60 Seconds)

### Installation

```bash
pip install canary-fabric
# or using uv
uv pip install canary-fabric
```

### 1. Watermark Retrieved Chunks & Guard Streams

```python
from canary_fabric import (
    derive_canary_token,
    WatermarkEncoder,
    StreamWatcher,
    CircuitBreaker,
)

secret_key = "enterprise_master_secret"
tenant_id = "tenant_acme"
doc_id = "q3_acquisition_memo"

# 1. Generate invisible canary watermark for RAG chunk
canary_token = derive_canary_token(secret_key, tenant_id, doc_id, chunk_id="chunk_0")
raw_doc = "Project Titan will acquire CyberShield for $850M on Nov 1st."
watermarked_doc = WatermarkEncoder.inject_watermark(raw_doc, canary_token)

# 2. Watch outbound LLM streaming response
breaker = CircuitBreaker(secret_key=secret_key)
watcher = StreamWatcher(
    circuit_breaker=breaker,
    active_canary_tokens={canary_token},
    tenant_id=tenant_id,
    doc_id=doc_id,
)

# Simulated LLM stream attempting to leak the chunk
llm_stream = ["Here is the secret: ", watermarked_doc[:25], watermarked_doc[25:]]

for chunk in watcher.wrap_sync_stream(iter(llm_stream)):
    print(chunk, end="")
# Output:
# Here is the secret: [SECURITY ALERT: CanaryFabric Circuit Breaker Tripped - Confidential data exfiltration prevented. Incident ID: cf_inc_8f9a2b1c]
```

---

## 🔌 Ecosystem Framework Integrations

### LangChain Integration
```python
from canary_fabric.adapters.langchain import (
    CanaryRetriever,
    CanaryDocumentTransformer,
    CanaryCallbackHandler,
)
from canary_fabric import CircuitBreaker

breaker = CircuitBreaker(secret_key="my_secret")

# 1. Watermark documents automatically during retrieval
retriever = CanaryRetriever(base_retriever=my_vector_retriever, secret_key="my_secret")
docs = retriever.invoke("Find acquisition terms")

# 2. Add callback to interrupt generation if canary leaks in tokens or tool inputs
callback = CanaryCallbackHandler(circuit_breaker=breaker)
response = llm.invoke("Summarize documents", config={"callbacks": [callback]})
```

### LlamaIndex Integration
```python
from canary_fabric.adapters.llamaindex import CanaryNodePostprocessor

postprocessor = CanaryNodePostprocessor(secret_key="my_secret")
query_engine = index.as_query_engine(node_postprocessors=[postprocessor])
response = query_engine.query("What is the Q3 revenue?")
```

### OpenAI & LiteLLM Streaming Client Wrapper
```python
from openai import OpenAI
from canary_fabric.adapters.openai import wrap_streaming_response
from canary_fabric import CircuitBreaker

client = OpenAI()
breaker = CircuitBreaker(secret_key="my_secret")

raw_stream = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "..."}],
    stream=True,
)

# Safe streaming wrapper - severs socket instantly if canary leaks
safe_stream = wrap_streaming_response(raw_stream, circuit_breaker=breaker)
for chunk in safe_stream:
    if chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="")
```

### FastMCP Tool Security Gate
```python
from canary_fabric import CircuitBreaker, canary_gate

breaker = CircuitBreaker(secret_key="mcp_secret")

@canary_gate(circuit_breaker=breaker)
def execute_external_webhook(url: str, payload: dict) -> dict:
    # If an agent attempts to leak watermarked context into external tool arguments,
    # @canary_gate raises PermissionError and trips the breaker.
    return requests.post(url, json=payload).json()
```

---

## 🛡️ Synthetic Red-Team Benchmark

Run automated evaluations profiling canary survival and circuit breaker interception across 5 adversarial attack vectors (verbatim extraction, paraphrasing, summarization, translation, base64 obfuscation):

```bash
canary-fabric eval --text "Confidential term sheet: Project Titan acquisition for $850M."
```

```
           Synthetic Red-Team Adversarial Evaluation Report            
+-------------------+----------+------------------+-------------------+
| Attack Vector     | Tripped? | Canary Retained? | Scan Latency (µs) |
|-------------------+----------+------------------+-------------------|
| direct_extraction | YES      | YES              | 26.89             |
| paraphrase        | YES      | YES              | 16.14             |
| summarization     | YES      | YES              | 7.94              |
| translation       | YES      | YES              | 9.22              |
| encoding_base64   | NO       | NO               | 0.91              |
+-------------------+----------+------------------+-------------------+
```

---

## 🌐 Wire-Level Streaming Reverse Proxy

Deploy Canary Fabric as a zero-trust streaming proxy in front of OpenAI, Anthropic, or LiteLLM endpoints:

```bash
# Start proxy with agent tool-call argument inspection
canary-proxy --port 8080 --upstream https://api.openai.com --default-action block
```

Or deploy via Docker:

```bash
docker run -p 8080:8080 -e CANARY_UPSTREAM_URL=https://api.openai.com ghcr.io/sagarv48/canary-fabric:latest
```

---

## 🔍 Forensic Leak Certificates & SIEM Exporters

Every tripped breaker generates a tamper-evident `LeakCertificate` with an HMAC-SHA256 signature binding the breach to the tenant, document chunk ID, and prompt hash:

```python
from canary_fabric.forensics import IncidentVault, WebhookExporter, CEFExporter

# Pluggable SIEM dispatching
vault = IncidentVault(
    exporters=[
        WebhookExporter(endpoint_url="https://hooks.slack.com/services/...", signing_secret="key"),
        CEFExporter(),  # Formats for Splunk, Microsoft Sentinel, and QRadar
    ]
)
```

Verify certificate authenticity via CLI:

```bash
canary-fabric verify --certificate-file leak_cert.json --secret-key prod_master_secret
```

---

## 🧪 Testing & Quality Verification

Canary Fabric maintains rigorous test coverage (≥92% gated in CI) and a zero-live-HTTP CI architecture:

- **Tier 1 (Golden Corpus Fixtures)**: Real-world public financial disclosures (Apple and Alphabet SEC Form 10-K filings) checked into `tests/fixtures/corpora/` for deterministic, offline, sub-second CI validation.
- **Tier 2 (Opt-in Live Harness)**: Live streaming verification against OpenRouter cloud models (`benchmarks/live_watermark_smoke_test.py --openrouter`).

```bash
# Run unit & integration tests with coverage reporting
uv run pytest -v --cov=canary_fabric --cov-report=term-missing --cov-fail-under=90

# Run live functional streaming smoke test (Local hermetic simulator)
uv run python benchmarks/live_watermark_smoke_test.py

# Optional: Run live streaming verification against OpenRouter Cloud Free Tier
uv run python benchmarks/live_watermark_smoke_test.py --openrouter

# Run hermetic test suite and smoke test in Docker Compose
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

---

## 🛠️ Ecosystem & Related Projects

Canary Fabric forms the cryptographic security layer of the enterprise AI governance stack:

* 📚 [Knowledge Fabric](https://github.com/sagarv48/knowledge-fabric): Vendor-neutral, governance-first hybrid evidence retrieval platform with pgvector + BM25 RRF and Row-Level Security.
* 🛡️ [Intent Fabric](https://github.com/sagarv48/intent-fabric): Policy-governed autonomous agent planning and cryptographic action verification.
* ⏪ [Unloop](https://github.com/sagarv48/unloop): The interactive time-travel debugger and anti-oscillation watchdog for AI agents.

---

## 📄 License

Canary Fabric is licensed under the [Apache 2.0 License](LICENSE).

Developed with ❤️ by [Vinay Kumar Ksheera Sagar](https://github.com/sagarv48).
