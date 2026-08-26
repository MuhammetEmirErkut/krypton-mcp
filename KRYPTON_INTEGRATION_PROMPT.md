# 🛡️ KryptonMCP Integration Master Prompt

> **Usage:** Copy the entire content of this file and paste it directly to any AI Agent (Claude Code, Cursor Composer, Windsurf, Antigravity, Cline, Copilot, etc.) in any external project that needs to integrate **KryptonMCP**.

---

# 🛡️ SYSTEM TASK: KryptonMCP Zero-Trust Security & Privacy Gateway Integration

You are an expert DevSecOps and AI Systems Engineer. Your goal is to understand, install, configure, and integrate **KryptonMCP** into this codebase.

---

## 1. What is KryptonMCP? (Context & Architecture)

**KryptonMCP** is a standalone, single-binary, zero-dependency **Zero-Trust Security & Privacy Gateway** designed for Model Context Protocol (MCP) clients (such as Claude Desktop, Cursor, Windsurf, LangChain, AutoGen) and downstream servers (PostgreSQL, Redis, GitHub, AWS, custom APIs).

It sits transparently between the AI Client and Downstream MCP Servers:
`[ AI Client (Claude / Cursor) ] <───> [ KryptonMCP Gateway ] <───> [ Downstream MCP Server / DB ]`

### Core Security Subsystems:
1. **🎭 In-Flight Deterministic PII Masking & Reversible Detokenization**:
   - Outbound data from databases/APIs is scanned in-flight. PII (Emails, Credit Cards with Luhn check, SSNs, API Keys, JWTs, IPs, Phones) is replaced with surrogate tokens (`[EMAIL_REF_a1b2c3d4]`, `[CREDIT_CARD_REF_8f9e0a1b]`) before reaching the LLM.
   - Values are stored in an in-memory session vault encrypted with **AES-256-GCM**.
   - When the LLM issues a downstream tool call containing surrogate tokens, Krypton automatically detokenizes them back to cleartext before reaching the backend. The LLM never sees cleartext PII!
2. **🛡️ Multi-Vector Prompt-Injection & Tool Execution Guardrails**:
   - Detects and blocks instruction overrides, jailbreaks (DAN/developer mode), delimiter injections, and Base64-obfuscated attacks.
   - Declarative Tool RBAC (allowlists/denylists like `query_*`, blocking `drop_*` or destructive shell tools).
   - Argument validation (regex constraints, length, numeric bounds, rate limiting).
3. **🔑 Just-In-Time (JIT) Ephemeral Credentials Broker**:
   - Eliminates static long-lived database passwords for AI agents.
   - Generates temporary micro-credentials with sub-hour TTLs for **PostgreSQL** (`CREATE ROLE ... VALID UNTIL`) and **Redis** (`ACL SETUSER`).
   - Automatically revokes them and drops active sessions upon expiration. Exposes native MCP tools: `krypton_request_credential`, `krypton_revoke_credential`, `krypton_list_leases`.
4. **🔏 Cryptographically Signed RFC 6962 Merkle Audit Ledger**:
   - Append-only binary Merkle tree recording every tool call, parameter, response, and credential lease in `audit.jsonl`.
   - Signed using asymmetric **Ed25519** keys for tamper-evident SOC2/HIPAA/ISO27001 compliance. Verification via CLI: `krypton audit verify`.

---

## 2. Your Integration Mission

Follow these steps sequentially to audit, configure, and integrate KryptonMCP into this project:

### Step 1: Project Discovery & Architecture Audit
1. Inspect the workspace for:
   - Existing MCP configurations (e.g., `.cursor/mcp.json`, `claude_desktop_config.json`, `.vscode/`, `docker-compose.yml`, or agent configs).
   - Database connections, API keys, or tools exposed to AI agents (Postgres, Redis, GitHub, REST APIs, etc.).
   - Sensitive data flows that require PII masking or prompt injection protection.

### Step 2: Binary Installation & Audit Key Generation
1. Check if Go is installed (`go version`) or Docker is available.
2. Provide / run the installation commands:
   - **From Source**:
     ```bash
     git clone https://github.com/MuhammetEmirErkut/krypton-mcp.git /tmp/krypton-mcp
     cd /tmp/krypton-mcp && go build -o /usr/local/bin/krypton ./cmd/krypton
     ```
   - **Or Docker**: `ghcr.io/muhammetemirerkut/krypton-mcp:latest`
3. Generate the cryptographic Ed25519 audit keypair for the project:
   ```bash
   krypton audit keygen --out-dir ./security/krypton-keys
   ```

### Step 3: Create `krypton.yaml` Configuration
Create a production-ready `krypton.yaml` (or `./config/krypton.yaml`) tailored to this project:
```yaml
version: "v1"

server:
  transport: "stdio" # "stdio" for process proxy, "sse" for HTTP server
  log_level: "info"

security:
  masking_enabled: true
  guardrails_enabled: true
  audit_enabled: true
  ephemeral_creds_enabled: true

masking:
  mode: "tokenize" # "tokenize" (reversible via vault), "redact", or "hash"
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
  max_prompt_size_bytes: 1048576 # 1 MB
  # Tool RBAC policies
  allowed_tools:
    - "*"
  denied_tools:
    - "drop_*"
    - "delete_database"
    - "execute_raw_shell"

audit:
  log_path: "./logs/krypton-audit.jsonl"
  sign_enabled: true
  signing_key_path: "./security/krypton-keys/krypton_audit.key"
  public_key_path: "./security/krypton-keys/krypton_audit.pub"
```

Validate the config:
```bash
krypton config validate --config ./krypton.yaml
```

### Step 4: Client & Tool Proxy Wiring
Wrap existing downstream MCP servers with `krypton start --config <path> -- <downstream_command> <args>`.

#### A. Cursor IDE (`.cursor/mcp.json`):
```json
{
  "mcpServers": {
    "secure-db-gateway": {
      "command": "krypton",
      "args": [
        "start",
        "--config", "./krypton.yaml",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://user:pass@localhost:5432/dbname"
      ]
    }
  }
}
```

#### B. Claude Desktop (`claude_desktop_config.json`):
```json
{
  "mcpServers": {
    "secure-gateway": {
      "command": "/usr/local/bin/krypton",
      "args": [
        "start",
        "--config", "/absolute/path/to/krypton.yaml",
        "--",
        "<your-downstream-mcp-server-command>"
      ]
    }
  }
}
```

#### C. Docker Compose / Backend Service (if applicable):
Add Krypton as a secure sidecar or standalone gateway container.

### Step 5: Verification & Tamper-Proof Audit Check
1. Start the gateway and execute a test tool call (e.g. retrieving records with mock PII like email/credit card).
2. Confirm the AI client only receives `[EMAIL_REF_...]` / `[CREDIT_CARD_REF_...]` tokens.
3. Test a tool call utilizing the surrogate token to verify transparent reverse detokenization.
4. Verify Merkle ledger integrity:
   ```bash
   krypton audit verify --log-file ./logs/krypton-audit.jsonl --public-key ./security/krypton-keys/krypton_audit.pub
   ```

---

## 3. Output Expected from You

1. **Audit Summary**: Identify which MCP servers / databases in this project should be protected by Krypton.
2. **Files Created/Modified**: Show the exact `krypton.yaml`, audit keys location, and updated MCP client configuration files.
3. **Verification Guide**: Provide exact CLI commands to run and verify that PII masking, guardrails, and signed audit logging are fully functional.
