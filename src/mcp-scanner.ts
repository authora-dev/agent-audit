/**
 * MCP Server Security Scanner
 *
 * Connects to a remote MCP server, discovers tools,
 * classifies them by risk level, and produces a security grade.
 */

export interface McpTool {
  name: string;
  description: string;
  level: "safe" | "warn" | "danger";
}

export interface McpAuditResult {
  tools: McpTool[];
  total: number;
  safe: number;
  review: number;
  dangerous: number;
  score: number;
  letter: string;
  method: string;
  authenticated: boolean;
}

// Dangerous: destructive or privilege-escalating operations
const DANGEROUS = [
  "delete", "remove", "drop", "exec", "execute", "shell", "command",
  "run_command", "kill", "terminate", "destroy", "purge", "wipe", "force",
  "override", "revoke", "suspend", "deactivate", "disable", "deny", "reject",
  "reset", "unregister", "detach", "disconnect",
];

// Safe: read-only, observability, and query operations
const SAFE = [
  "read", "get", "list", "search", "query", "fetch", "check", "verify",
  "status", "health", "describe", "count", "view", "show", "inspect", "find",
  "lookup", "validate", "export", "audit", "log", "monitor", "history",
  "report", "resolve", "whoami", "me", "info", "version", "ping", "echo",
  "help", "capabilities", "schema", "metadata", "stats", "summary",
  "discover", "enumerate", "batch_get", "batch_list",
];

// Review: mutations that change state but are not destructive
const REVIEW = [
  "create", "write", "modify", "send", "deploy", "publish", "update",
  "assign", "grant", "approve", "set", "add", "configure", "delegate",
  "escalate", "notify", "alert", "rotate", "renew", "generate", "import",
  "register", "trigger", "enable", "activate", "reactivate", "connect",
  "attach", "invite", "enroll", "submit", "request", "initiate", "provision",
  "emit", "push", "post", "put", "patch", "insert", "upsert", "merge",
  "sync", "transfer", "move", "copy", "clone", "fork", "sign", "issue",
  "mint", "encode", "encrypt", "authorize", "consent", "accept",
  "acknowledge", "confirm", "start", "stop", "pause", "resume", "schedule",
  "cancel", "retry", "replay", "release", "promote", "demote", "tag",
  "label", "annotate", "comment", "flag", "pin", "bookmark", "subscribe",
  "unsubscribe", "follow", "unfollow", "mute", "unmute", "archive", "restore",
];

function wordBoundaryMatch(text: string, word: string): boolean {
  return new RegExp(`(^|[_\\-\\s.])${word}([_\\-\\s.]|$)`).test(text);
}

function classifyTool(name: string, description?: string): "safe" | "warn" | "danger" {
  const text = `${name} ${description ?? ""}`.toLowerCase();

  for (const kw of DANGEROUS) {
    if (wordBoundaryMatch(text, kw)) return "danger";
  }
  for (const kw of SAFE) {
    if (wordBoundaryMatch(text, kw)) return "safe";
  }
  for (const kw of REVIEW) {
    if (wordBoundaryMatch(text, kw)) return "warn";
  }
  return "warn";
}

function gradeLetter(score: number): string {
  if (score >= 90) return "A+";
  if (score >= 80) return "A";
  if (score >= 70) return "B+";
  if (score >= 60) return "B";
  if (score >= 50) return "C";
  if (score >= 30) return "D";
  return "F";
}

export async function scanMcpServer(
  url: string,
  headers: Record<string, string>,
  authenticated: boolean,
): Promise<McpAuditResult> {
  const base = url.replace(/\/sse\/?$/, "").replace(/\/$/, "");
  let rawTools: Array<{ name: string; description?: string }> = [];
  let method = "";

  // Try REST /tools
  try {
    const res = await fetch(`${base}/tools`, {
      headers,
      signal: AbortSignal.timeout(15000),
    });
    if (res.ok) {
      const data = (await res.json()) as any;
      rawTools = data.tools ?? [];
      method = "REST /tools";
    } else if (res.status === 401) {
      throw new Error(
        "Server returned 401 Unauthorized. Provide --api-key or --bearer.",
      );
    }
  } catch (e: any) {
    if (e.message.includes("401")) throw e;
  }

  // Fallback: JSON-RPC tools/list
  if (rawTools.length === 0) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", method: "tools/list", id: 1 }),
        signal: AbortSignal.timeout(15000),
      });
      if (res.ok) {
        const data = (await res.json()) as any;
        rawTools = data.result?.tools ?? data.tools ?? [];
        method = "JSON-RPC";
      }
    } catch {
      // fall through
    }
  }

  if (rawTools.length === 0) {
    throw new Error(
      "Could not retrieve tools. Check the URL and authentication.",
    );
  }

  // Deduplicate by name
  const seen = new Set<string>();
  const tools: McpTool[] = [];
  let safe = 0, review = 0, dangerous = 0;

  for (const t of rawTools) {
    if (seen.has(t.name)) continue;
    seen.add(t.name);
    const level = classifyTool(t.name, t.description);
    if (level === "safe") safe++;
    else if (level === "warn") review++;
    else dangerous++;
    tools.push({ name: t.name, description: t.description ?? "", level });
  }

  // Sort: dangerous first, then review, then safe
  tools.sort((a, b) => {
    const order = { danger: 0, warn: 1, safe: 2 };
    return order[a.level] - order[b.level];
  });

  // Score: ratio-based
  const total = tools.length;
  const safeRatio = safe / total;
  const dangerRatio = dangerous / total;
  let score = Math.round(safeRatio * 60 + (1 - dangerRatio) * 30);
  if (authenticated) score += 10;
  if (dangerRatio > 0.3) score -= 15;
  else if (dangerRatio > 0.2) score -= 5;
  const undocDanger = tools.filter((t) => t.level === "danger" && !t.description).length;
  if (dangerous > 0 && undocDanger / dangerous > 0.5) score -= 10;
  score = Math.max(0, Math.min(100, score));

  return {
    tools,
    total,
    safe,
    review,
    dangerous,
    score,
    letter: gradeLetter(score),
    method,
    authenticated,
  };
}
