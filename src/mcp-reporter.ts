import type { McpAuditResult } from "./mcp-scanner.js";

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[90m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
};

const gradeColors: Record<string, string> = {
  "A+": c.green, A: c.green,
  "B+": c.green, B: c.green,
  C: c.yellow,
  D: c.red,
  F: c.red,
};

export function formatMcpReport(result: McpAuditResult): string {
  const gc = gradeColors[result.letter] ?? c.reset;
  const lines: string[] = [];

  lines.push("");
  lines.push(`  ${c.bold}MCP Security Audit${c.reset}  ${c.dim}via ${result.method}${c.reset}`);
  lines.push(`  ${c.dim}${"─".repeat(50)}${c.reset}`);
  lines.push("");
  lines.push(
    `  ${gc}${c.bold}  ${result.letter}  ${c.reset}  ${c.dim}Grade${c.reset}  ${c.bold}${result.score}${c.reset}${c.dim}/100${c.reset}  ${result.authenticated ? `${c.green}AUTH${c.reset}` : `${c.red}NO AUTH${c.reset}`}`,
  );
  lines.push("");
  lines.push(
    `  ${c.bold}${result.total}${c.reset} tools  ${c.green}${result.safe}${c.reset} safe  ${c.yellow}${result.review}${c.reset} review  ${c.red}${result.dangerous}${c.reset} dangerous`,
  );
  lines.push("");

  // Dangerous tools
  const dangerTools = result.tools.filter((t) => t.level === "danger");
  if (dangerTools.length > 0) {
    lines.push(`  ${c.red}${c.bold}Dangerous tools:${c.reset}`);
    for (const t of dangerTools) {
      lines.push(
        `  ${c.red}*${c.reset} ${c.bold}${t.name}${c.reset}${t.description ? c.dim + " -- " + t.description.slice(0, 60) + c.reset : ""}`,
      );
    }
    lines.push("");
  }

  // Review tools (collapsed)
  const reviewTools = result.tools.filter((t) => t.level === "warn");
  if (reviewTools.length > 0) {
    const show = reviewTools.slice(0, 5);
    const remaining = reviewTools.length - show.length;
    lines.push(`  ${c.yellow}${c.bold}Needs review:${c.reset}`);
    for (const t of show) {
      lines.push(
        `  ${c.yellow}*${c.reset} ${t.name}${t.description ? c.dim + " -- " + t.description.slice(0, 60) + c.reset : ""}`,
      );
    }
    if (remaining > 0) {
      lines.push(`  ${c.dim}  ... and ${remaining} more${c.reset}`);
    }
    lines.push("");
  }

  // Badge
  const badgeColor = result.score >= 70 ? "brightgreen" : result.score >= 50 ? "yellow" : "red";
  lines.push(`  ${c.dim}README badge:${c.reset}`);
  lines.push(
    `  ${c.dim}![MCP Security: ${result.letter}](https://img.shields.io/badge/MCP_Security-${encodeURIComponent(result.letter)}-${badgeColor})${c.reset}`,
  );
  lines.push("");
  lines.push(`  ${c.dim}Web inspector: https://mcp.authora.dev/inspect${c.reset}`);
  lines.push("");

  return lines.join("\n");
}
