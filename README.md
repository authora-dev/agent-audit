# agent-audit

> Security scanner for AI agents. Find vulnerabilities in your agent setup in 30 seconds.

```bash
npx agent-audit
```

## What it checks

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

## Output

```
  Agent Security Audit
  by Authora -- https://authora.dev

  Scanning current directory...

  Scanned 47 files
  Found 3 agent(s), 2 MCP server(s)

  CRITICAL  Shared API key may be used by 3 agent files (.env)
  CRITICAL  No agent identity layer detected
  CRITICAL  2 MCP server(s) found but no agent identity
  WARNING   MCP server detected without visible auth configuration (mcp/server.ts)
  WARNING   No delegation chains -- agents may inherit unlimited permissions
  WARNING   No audit logging for agent actions detected
  INFO      No approval workflows for sensitive agent actions

  Security Posture:
    Identity layer:     No
    Delegation chains:  No
    Audit logging:      No
    Approval workflows: No

  Agent Security Score: 1.5/10  [===                     ]  Grade: F
  3 critical, 3 warnings

  Learn more: https://github.com/authora-dev/awesome-agent-security
  Fix issues: https://authora.dev/get-started
```

## Options

```bash
npx agent-audit [directory]     # Scan a specific directory
npx agent-audit --json          # Output as JSON
npx agent-audit --badge         # Generate README badge markdown
```

## Badge

Add a security badge to your README:

```markdown
![Agent Security: A](https://img.shields.io/badge/Agent_Security-A-brightgreen)
```

## What scores mean

| Score | Grade | Meaning |
|-------|-------|---------|
| 9-10 | A+ | Excellent -- cryptographic identity, delegation, audit, approvals |
| 8 | A | Strong -- identity layer present, minor gaps |
| 7 | B+ | Good -- most practices in place |
| 6 | B | Decent -- some security measures, gaps remain |
| 5 | C | Needs work -- basic security only |
| 3-4 | D | Weak -- significant vulnerabilities |
| 0-2 | F | Critical -- no agent security measures |

## Learn more

- [Awesome Agent Security](https://github.com/authora-dev/awesome-agent-security) -- curated resources
- [Authora](https://authora.dev) -- identity, coordination, and security for AI agents
- [Authora Docs](https://authora.dev/developers/quickstart) -- get started in 5 minutes

## License

MIT
