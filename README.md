# agent-audit

> Security scanner for AI agents and MCP servers. Find vulnerabilities in 30 seconds.

Two modes: scan your **local codebase** for agent security issues, or audit a **remote MCP server** for tool-level risks.

## Quick start

```bash
# Scan local codebase
npx @authora/agent-audit

# Scan a remote MCP server
npx @authora/agent-audit mcp https://mcp.example.com

# With authentication
npx @authora/agent-audit mcp https://mcp.example.com --api-key YOUR_KEY
```

## MCP server scanning

Connects to any MCP server, discovers all tools, and classifies each one by risk level.

```bash
npx @authora/agent-audit mcp <url> [options]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--api-key <key>` | Authenticate with an API key (sent as `api-key` header) |
| `--bearer <token>` | Authenticate with a Bearer token |
| `--json` | Output raw JSON (for CI pipelines) |
| `--fail-below <grade>` | Exit with code 1 if grade is below threshold (A+, A, B+, B, C, D) |

**Examples:**

```bash
# Scan with API key authentication
npx @authora/agent-audit mcp https://mcp.authora.dev --api-key authora_live_xxx

# JSON output for CI
npx @authora/agent-audit mcp https://my-server.com --bearer sk-xxx --json

# Fail CI if grade drops below B
npx @authora/agent-audit mcp https://my-server.com --api-key xxx --fail-below B
```

**Sample output:**

```
  MCP Security Audit  via REST /tools
  --------------------------------------------------

    B   Grade  65/100  AUTH

  128 tools  63 safe  45 review  20 dangerous

  Dangerous tools:
  * authora_suspend_agent -- Suspend an active agent
  * authora_revoke_agent -- Permanently revoke an agent
  * authora_delete_role -- Delete a role by ID
  ...

  Needs review:
  * authora_create_agent -- Create a new Authora agent in a workspace
  * authora_update_agent -- Update an existing agent
  ...

  README badge:
  ![MCP Security: B](https://img.shields.io/badge/MCP_Security-B-yellow)
```

**Tool classification:**

| Level | Keywords | Meaning |
|-------|----------|---------|
| Safe | get, list, search, verify, audit, health, describe... | Read-only operations |
| Needs Review | create, update, assign, configure, send, rotate... | State-changing mutations |
| Dangerous | delete, revoke, suspend, destroy, kill, force, reset... | Destructive or privilege-escalating |

**Scoring:**

Score is based on the ratio of safe vs dangerous tools, not absolute counts. A server with many tools but few dangerous ones scores well. Authentication adds 10 points.

| Grade | Score | Typical server |
|-------|-------|----------------|
| A+ | 90-100 | Read-only analytics, monitoring |
| A | 80-89 | Well-scoped API with auth |
| B+/B | 60-79 | Full CRUD platform with auth |
| C | 50-59 | Broad API, no auth |
| D/F | 0-49 | Mostly destructive, undocumented |

## Local codebase scanning

Scans your project files for agent security issues.

```bash
npx @authora/agent-audit [directory] [options]
```

**Options:**

| Flag | Description |
|------|-------------|
| `--json` | Output as JSON |
| `--badge` | Generate README badge markdown |

**What it checks:**

| Category | What it finds |
|----------|--------------|
| **Credentials** | Shared API keys across agents, hardcoded secrets in code |
| **Identity** | Missing agent identity layer, no cryptographic verification |
| **MCP** | MCP servers without authentication, unprotected tool endpoints |
| **Permissions** | Overly broad agent permissions, admin/root access |
| **Delegation** | Missing delegation chains, agents inheriting full user permissions |
| **Audit** | No audit logging for agent actions |
| **Approvals** | No human-in-the-loop for sensitive operations |
| **Resilience** | Missing timeouts, no error handling on tool calls |

**Sample output:**

```
  Agent Security Audit
  by Authora -- https://authora.dev

  Scanning current directory...

  Scanned 47 files
  Found 3 agent(s), 2 MCP server(s)

  CRITICAL  Shared API key may be used by 3 agent files (.env)
  CRITICAL  No agent identity layer detected
  WARNING   MCP server without visible auth configuration (mcp/server.ts)
  WARNING   No delegation chains

  Agent Security Score: 1.5/10  Grade: F
```

## CI integration

```yaml
# GitHub Actions
- name: MCP Security Gate
  run: npx @authora/agent-audit mcp ${{ secrets.MCP_URL }} --api-key ${{ secrets.MCP_KEY }} --fail-below B
```

## Web inspector

Prefer a browser UI? Use the [MCP Security Inspector](https://mcp.authora.dev/inspect) -- same scanner, visual interface.

## Learn more

- [awesome-agent-security](https://github.com/authora-dev/awesome-agent-security) -- curated resources
- [Authora](https://authora.dev) -- identity, coordination, and security for AI agents
- [Authora MCP docs](https://authora.dev/developers/mcp) -- securing MCP with Authora

## License

MIT
