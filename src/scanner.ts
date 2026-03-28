import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import { join, extname } from "path";

export interface Finding {
  severity: "critical" | "warning" | "info" | "pass";
  category: string;
  message: string;
  file?: string;
  line?: number;
  fix?: string;
}

export interface ScanResult {
  findings: Finding[];
  score: number;
  agents: number;
  mcpServers: number;
  hasIdentityLayer: boolean;
  hasDelegation: boolean;
  hasAuditLog: boolean;
  hasApprovals: boolean;
  scannedFiles: number;
}

const CODE_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rs", ".java", ".rb",
  ".json", ".yaml", ".yml", ".toml", ".env",
]);

const MAX_FILES = 500;
const MAX_FILE_SIZE = 100_000; // 100KB

function walkDir(dir: string, files: string[] = [], depth = 0): string[] {
  if (depth > 8 || files.length > MAX_FILES) return files;

  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      if (entry.startsWith(".") || entry === "node_modules" || entry === "dist" ||
          entry === "build" || entry === "__pycache__" || entry === "venv" ||
          entry === ".git" || entry === "vendor") continue;

      const fullPath = join(dir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          walkDir(fullPath, files, depth + 1);
        } else if (stat.isFile() && CODE_EXTENSIONS.has(extname(entry)) && stat.size < MAX_FILE_SIZE) {
          files.push(fullPath);
        }
      } catch {
        // Skip inaccessible files
      }
    }
  } catch {
    // Skip inaccessible directories
  }

  return files;
}

function readFile(path: string): string {
  try {
    return readFileSync(path, "utf-8");
  } catch {
    return "";
  }
}

export async function scanDirectory(dir: string): Promise<ScanResult> {
  const findings: Finding[] = [];
  let agents = 0;
  let mcpServers = 0;
  let hasIdentityLayer = false;
  let hasDelegation = false;
  let hasAuditLog = false;
  let hasApprovals = false;

  const files = walkDir(dir);

  for (const file of files) {
    const content = readFile(file);
    if (!content) continue;
    const lower = content.toLowerCase();
    const relPath = file.replace(dir + "/", "");

    // Detect agents
    if (/\bagent\b/i.test(content) && (/\bcreate.*agent|agent.*config|new.*agent|agent.*class\b/i.test(content))) {
      agents++;
    }

    // Detect MCP servers
    if (/mcp.*server|mcpserver|model.*context.*protocol/i.test(lower)) {
      mcpServers++;
    }

    // Check for identity layer
    if (/authora|@authora\/sdk|agent.*identity|ed25519.*agent|agent.*keypair/i.test(lower)) {
      hasIdentityLayer = true;
    }

    // Check for delegation
    if (/delegation.*chain|delegate.*permission|token.*exchange|rfc.*8693/i.test(lower)) {
      hasDelegation = true;
    }

    // Check for audit logging
    if (/audit.*log|agent.*audit|action.*log.*agent/i.test(lower)) {
      hasAuditLog = true;
    }

    // Check for approvals
    if (/approval.*workflow|human.*in.*loop|require.*approval/i.test(lower)) {
      hasApprovals = true;
    }

    // --- CRITICAL: Shared API keys ---
    const apiKeyPattern = /(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_API_KEY|API_KEY)\s*[=:]\s*["']?[A-Za-z0-9_-]{20,}/g;
    const envFile = extname(file) === ".env";
    if (envFile) {
      const keys = content.match(apiKeyPattern);
      if (keys && keys.length > 0) {
        // Check if multiple agents might share this key
        const agentFiles = files.filter((f) => {
          const fc = readFile(f);
          return /\bagent\b/i.test(fc) && /API_KEY|api_key|apiKey/i.test(fc);
        });
        if (agentFiles.length > 1) {
          findings.push({
            severity: "critical",
            category: "credentials",
            message: `Shared API key may be used by ${agentFiles.length} agent files`,
            file: relPath,
            fix: "Give each agent its own credentials with scoped permissions",
          });
        }
      }
    }

    // --- CRITICAL: Hardcoded secrets in code ---
    if (!envFile) {
      const hardcodedSecrets = content.match(/(?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xoxb-[0-9]+-[a-zA-Z0-9]+)/g);
      if (hardcodedSecrets) {
        findings.push({
          severity: "critical",
          category: "credentials",
          message: `Hardcoded secret found in source code`,
          file: relPath,
          fix: "Move secrets to environment variables and use a secrets manager",
        });
      }
    }

    // --- WARNING: MCP server without auth ---
    if (/mcp.*server|createServer/i.test(content) && !/auth|authentication|authorization|token|apiKey/i.test(content)) {
      findings.push({
        severity: "warning",
        category: "mcp",
        message: "MCP server detected without visible auth configuration",
        file: relPath,
        fix: "Add authentication to your MCP server (API key, JWT, or Ed25519 signature verification)",
      });
    }

    // --- WARNING: Broad agent permissions ---
    if (/\*.*permission|admin.*role|full.*access|sudo|root/i.test(content) && /agent/i.test(content)) {
      findings.push({
        severity: "warning",
        category: "permissions",
        message: "Agent may have overly broad permissions",
        file: relPath,
        fix: "Apply least-privilege: give agents only the permissions they need for their specific task",
      });
    }

    // --- WARNING: No error handling on tool calls ---
    if (/tool.*call|callTool|execute.*tool/i.test(content) && !/try|catch|error/i.test(content)) {
      findings.push({
        severity: "warning",
        category: "resilience",
        message: "Agent tool calls without error handling",
        file: relPath,
        fix: "Wrap tool calls in try/catch with proper error reporting and fallback behavior",
      });
    }

    // --- INFO: Agent without timeout ---
    if (/agent/i.test(content) && /async|await|fetch|request/i.test(content) && !/timeout|AbortSignal|signal/i.test(content)) {
      findings.push({
        severity: "info",
        category: "resilience",
        message: "Agent operations without timeout -- could run indefinitely",
        file: relPath,
        fix: "Add timeouts to agent operations to prevent runaway processes",
      });
    }
  }

  // --- Structural findings ---
  if (!hasIdentityLayer) {
    findings.push({
      severity: "critical",
      category: "identity",
      message: "No agent identity layer detected",
      fix: "Add cryptographic agent identities so each agent has a verifiable, unique identity. See: https://authora.dev/get-started",
    });
  }

  if (!hasDelegation && agents > 1) {
    findings.push({
      severity: "warning",
      category: "delegation",
      message: "No delegation chains -- agents may inherit unlimited permissions",
      fix: "Implement delegation chains (RFC 8693) so agents receive scoped, time-bound authority",
    });
  }

  if (!hasAuditLog) {
    findings.push({
      severity: "warning",
      category: "audit",
      message: "No audit logging for agent actions detected",
      fix: "Log every agent action with: who (agent ID), what (action), when (timestamp), authorized by (delegation chain)",
    });
  }

  if (!hasApprovals && agents > 0) {
    findings.push({
      severity: "info",
      category: "approvals",
      message: "No approval workflows for sensitive agent actions",
      fix: "Add human-in-the-loop approval for high-risk operations (production deploys, data access, secret rotation)",
    });
  }

  if (mcpServers > 0 && !hasIdentityLayer) {
    findings.push({
      severity: "critical",
      category: "mcp",
      message: `${mcpServers} MCP server(s) found but no agent identity -- any client can call any tool`,
      fix: "Add agent identity verification to your MCP servers. See: https://authora.dev/developers/mcp",
    });
  }

  // Calculate score (0-10) based on CATEGORIES not raw count
  // This prevents large codebases from being penalized for having many files
  const criticalCategories = new Set(findings.filter((f) => f.severity === "critical").map((f) => f.category));
  const warningCategories = new Set(findings.filter((f) => f.severity === "warning").map((f) => f.category));
  const infoCategories = new Set(findings.filter((f) => f.severity === "info").map((f) => f.category));

  let score = 10;
  score -= criticalCategories.size * 2.5;
  score -= warningCategories.size * 1.5;
  score -= infoCategories.size * 0.5;

  // Bonus for good practices (max +4)
  if (hasIdentityLayer) score += 1;
  if (hasDelegation) score += 1;
  if (hasAuditLog) score += 1;
  if (hasApprovals) score += 1;

  score = Math.max(0, Math.min(10, Math.round(score * 10) / 10));

  return {
    findings,
    score,
    agents,
    mcpServers,
    hasIdentityLayer,
    hasDelegation,
    hasAuditLog,
    hasApprovals,
    scannedFiles: files.length,
  };
}
