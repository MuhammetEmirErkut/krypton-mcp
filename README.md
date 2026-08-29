<div align="center">

<img src="assets/krypton_logo.png" alt="KryptonMCP Logo" width="220" />

# 🛡️ KryptonMCP

**The Zero-Trust Security & Privacy Gateway for AI Agents**

*Deterministic PII Masking • Prompt Injection Guardrails • JIT Ephemeral Credentials • Signed Merkle Audit Ledger*

[![Release](https://img.shields.io/badge/Release-v0.1.0--alpha-blue.svg)](https://github.com/MuhammetEmirErkut/krypton-mcp/releases)
[![CI](https://github.com/MuhammetEmirErkut/krypton-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/MuhammetEmirErkut/krypton-mcp/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.23%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![MCP Compliant](https://img.shields.io/badge/MCP-2024--11--05-8A2BE2)](https://modelcontextprotocol.io)
[![Zero Dependency](https://img.shields.io/badge/Dependencies-Zero%20External-brightgreen)](go.mod)

<br />

<img src="assets/krypton_demo.gif" alt="KryptonMCP Terminal Demo" width="800" />

</div>

---

## 🤖 Instant Project Integration with AI

> **Integrating into an existing project?**
> We provide a drop-in AI prompt in [**`KRYPTON_INTEGRATION_PROMPT.md`**](KRYPTON_INTEGRATION_PROMPT.md). 
> 
> Simply copy and paste the entire prompt into **Claude Code, Cursor Composer, Windsurf, or Antigravity** in your project, and your AI assistant will automatically audit your tools, generate `krypton.yaml`, create Ed25519 audit keys, and wire up all MCP clients transparently!

---

## ⚡ Why KryptonMCP?

Connecting AI models (like Claude, Cursor, Windsurf, LangChain, AutoGen) directly to databases, Redis instances, and enterprise APIs presents catastrophic security challenges:
1. **PII & Data Leakage**: Cleartext customer credit cards, emails, SSNs, and private API keys are sent directly to cloud LLM providers in prompt contexts.
2. **Prompt Injection & Hijacking**: Malicious users or indirect content injections trick models into executing destructive tools (`DROP TABLE`, `rm -rf`, exfiltration).
3. **Static Long-Lived Credentials**: Granting database passwords or admin tokens to AI agents creates persistent backdoors.
4. **Lack of Verifiable Compliance**: Traditional logging can be altered or erased, failing SOC2, HIPAA, and ISO27001 audit standards.

**KryptonMCP is a standalone, single-binary Zero-Trust Gateway** that sits transparently between your AI clients and downstream MCP tools without requiring external agents like HashiCorp Vault.

---

## 🌟 Core Pillars

```mermaid
flowchart TD
    Client["🤖 AI Client (Claude / Cursor / Windsurf / LangChain)"]

    subgraph InboundPipeline["🔒 Inbound Security Pipeline"]
        G["1. Prompt-Injection Guardrails & RBAC"]
        D["2. Inbound Detokenization Engine"]
        B["3. JIT Ephemeral Credential Broker"]
        A1["4. Merkle Audit Signer (Ed25519)"]
        G --> D --> B --> A1
    end

    Downstream[("🗄️ Downstream Services (Postgres, Redis, Remote APIs)")]

    subgraph OutboundPipeline["🎭 Outbound Privacy Pipeline"]
        M["5. In-Flight PII Masker (AES-256-GCM Vault)"]
        A2["6. Merkle Leaf Digest & JSONL Sync"]
        M --> A2
    end

    Client -->|"1. JSON-RPC Tool Request (stdio / SSE)"| G
    A1 -->|"2. Sanitized Cleartext Request"| Downstream
    Downstream -->|"3. Raw Database / API Result"| M
    A2 -->|"4. Protected Result with Surrogate Tokens ([EMAIL_REF_...])"| Client
```

### 1. 🎭 In-Flight Deterministic PII Masking
- **Transparent Redaction**: Replaces sensitive data (Credit Cards, SSNs, Emails, API Keys, JWTs, Phone Numbers, IPv4/IPv6) with reversible surrogate tokens (`[EMAIL_REF_a1b2c3d4]`, `[CREDIT_CARD_REF_8f9e0a1b]`) before payloads reach the LLM.
- **Algorithmic Validation**: High-precision scanning with Luhn Mod 10 checksums, SSA area checks, and zero false positives on standard code.
- **Reversible Detokenization**: When the LLM calls a downstream tool with a surrogate token, Krypton detokenizes the parameter back to cleartext in-flight.
- **In-Memory Cryptographic Vault**: Zero plaintext disk storage; all surrogate mappings are protected in memory with ephemeral AES-256-GCM keys.

### 2. 🛡️ Prompt-Injection & Tool Execution Guardrails
- **Multi-Vector Threat Detection**: Blocks instruction overrides, DAN/developer mode jailbreaks, delimiter injections (`<|im_start|>`, `<<SYS>>`), and Base64-obfuscated payloads.
- **Declarative Tool RBAC**: Wildcard allowlists (`query_*`) and denylists (`drop_*`, `execute_shell`).
- **Parameter Constraints**: Field-level validation (regex patterns, min/max length, numeric bounds).
- **Sliding-Window Rate Limiting**: Prevents runaway recursive execution loops.

### 3. 🔑 Just-In-Time (JIT) Ephemeral Credentials
- **Dynamic Micro-Credentials**: Generates short-lived database and cache users on demand with sub-hour TTLs.
- **Automated Revocation**: Precision background timers automatically terminate backend sessions and drop temporary roles upon lease expiration.
- **Built-in Drivers**: Native drivers for **PostgreSQL** (`CREATE ROLE ... VALID UNTIL`, `pg_terminate_backend`, `DROP ROLE`) and **Redis** (`ACL SETUSER`, `CLIENT KILL USER`, `ACL DELUSER`).
- **Native MCP Tools**: Exposes `krypton_request_credential`, `krypton_revoke_credential`, and `krypton_list_leases`.

### 4. 🔏 Cryptographically Signed Merkle Audit Ledger
- **RFC 6962 Domain Separation**: Append-only binary Merkle tree logging every request, response, tool call, and credential lease.
- **Ed25519 Asymmetric Signatures**: Mathematically signs Merkle root checkpoints.
- **Tamper Detection**: Alteration or deletion of past log records immediately breaks cryptographic verification.
- **CLI Verifier & Proof Exporter**: `krypton audit verify` and `krypton audit proof` for compliance auditors.

---

## 🚀 Quickstart (30 Seconds)

### Installation

```bash
# Option 1: Install with Go (Zero dependencies)
go install github.com/krypton-mcp/krypton/cmd/krypton@v0.1.0-alpha

# Option 2: Pull the production Docker image
docker pull ghcr.io/muhammetemirerkut/krypton-mcp:latest

# Option 3: Build from source
git clone https://github.com/MuhammetEmirErkut/krypton-mcp.git
cd krypton-mcp
go build -o krypton ./cmd/krypton
```

### Initialize Configuration & Audit Keys

```bash
# 1. Generate production configuration template
krypton config init --out krypton.yaml

# 2. Generate Ed25519 cryptographic audit signing keypair
krypton audit keygen --out-dir ./security-keys
```

---

## ⚙️ Client Integration

### 1. Claude Desktop Configuration (Stdio Proxy Mode)
Add Krypton as a transparent proxy in `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "postgres-secure": {
      "command": "/usr/local/bin/krypton",
      "args": [
        "start",
        "--config", "/path/to/krypton.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://admin:password@localhost:5432/mydb"
      ]
    }
  }
}
```

### 2. Cursor IDE / Remote MCP Integration (HTTP & SSE Mode)
For containerized or remote setups, launch Krypton as a secure network gateway:

```bash
# Launch SSE gateway on port 8080 proxying a remote MCP service
krypton start --transport sse --host 0.0.0.0 --port 8080 --downstream-url http://downstream-service:8001/rpc
```

Add to `.cursor/mcp.json` in your workspace:

```json
{
  "mcpServers": {
    "secure-gateway": {
      "command": "krypton",
      "args": ["start", "--config", "./krypton.yaml"]
    }
  }
}
```

---

## 📋 Configuration Specification (`krypton.yaml`)

```yaml
version: "v1"

server:
  transport: "stdio" # "stdio" or "sse"
  host: "127.0.0.1"
  port: 8080
  log_level: "info"

downstream:
  transport: "stdio" # "stdio" or "http"
  # url: "http://localhost:8001/rpc"
  command: ""
  args: []

security:
  masking_enabled: true
  guardrails_enabled: true
  audit_enabled: true
  ephemeral_creds_enabled: true

masking:
  mode: "tokenize" # "tokenize", "redact", or "hash"
  builtin_rules:
    - "email"
    - "credit_card"
    - "ssn"
    - "api_key"
    - "jwt"
    - "phone"
    - "ip_address"

guardrails:
  block_injection: true
  block_exfiltration: true
  max_prompt_size_bytes: 1048576 # 1 MB
  # Declarative Tool RBAC
  allowed_tools:
    - "*"
  denied_tools:
    - "drop_*"
    - "delete_database"
    - "execute_raw_shell"

audit:
  log_path: "./audit.jsonl"
  sign_enabled: true
  signing_key_path: "./krypton_audit.key"
  public_key_path: "./krypton_audit.pub"
```

---

## 💻 CLI Commands Matrix

| Command | Description |
| :--- | :--- |
| `krypton start [--config krypton.yaml] [-- <cmd> <args>]` | Launch gateway proxy or stand-alone server |
| `krypton config init [--out krypton.yaml]` | Generate production configuration template |
| `krypton config validate [--config krypton.yaml]` | Validate configuration syntax and schema rules |
| `krypton audit keygen [--out-dir .]` | Generate Ed25519 keypair for cryptographic audit signing |
| `krypton audit verify --log-file audit.jsonl` | Cryptographically verify Merkle ledger integrity |
| `krypton audit proof --log-file audit.jsonl --index 0` | Export cryptographic inclusion proof for a leaf |
| `krypton version [--json]` | Print binary build version and commit metadata |

---

## 📊 Performance Benchmarks

Measured on Apple M2 (arm64, Go 1.26):

| Benchmark Operation | Throughput | Latency | Memory Allocs |
| :--- | :--- | :--- | :--- |
| **In-Flight PII Masking & Tokenization** | ~30,000 ops/sec | **33.4 μs / op** | 20 allocs / op |
| **Prompt Injection & Guardrail Scan** | ~33,000 ops/sec | **30.3 μs / op** | 3 allocs / op |
| **RFC 6962 Merkle Tree Leaf Append** | ~2,000 ops/sec | **489 μs / op** | 5,074 allocs / op |
| **Full Gateway Pipeline End-to-End** | ~1,800 ops/sec | **550 μs / op** | 5,110 allocs / op |

---

## 🔒 Security & Vulnerability Disclosure

KryptonMCP takes security vulnerabilities seriously. If you discover a vulnerability, please report it via GitHub Private Vulnerability Reporting or email `security@krypton-mcp.org`. Do not open public issues for zero-day vulnerabilities.

---

## 📄 License

Apache License 2.0. See [LICENSE](LICENSE) for details.
