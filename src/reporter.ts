import type { ScanResult } from "./scanner.js";

const COLORS = {
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
  white: "\x1b[37m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: `${COLORS.red}${COLORS.bold}CRITICAL${COLORS.reset}`,
  warning: `${COLORS.yellow}WARNING ${COLORS.reset}`,
  info: `${COLORS.cyan}INFO    ${COLORS.reset}`,
  pass: `${COLORS.green}PASS    ${COLORS.reset}`,
};

function scoreBar(score: number): string {
  const filled = Math.round(score * 2);
  const empty = 20 - filled;
  const color = score >= 8 ? COLORS.green : score >= 5 ? COLORS.yellow : COLORS.red;
  return `${color}[${"=".repeat(filled)}${" ".repeat(empty)}]${COLORS.reset}`;
}

function gradeFromScore(score: number): string {
  if (score >= 9) return `${COLORS.green}${COLORS.bold}A+${COLORS.reset}`;
  if (score >= 8) return `${COLORS.green}${COLORS.bold}A${COLORS.reset}`;
  if (score >= 7) return `${COLORS.green}B+${COLORS.reset}`;
  if (score >= 6) return `${COLORS.yellow}B${COLORS.reset}`;
  if (score >= 5) return `${COLORS.yellow}C${COLORS.reset}`;
  if (score >= 3) return `${COLORS.red}D${COLORS.reset}`;
  return `${COLORS.red}${COLORS.bold}F${COLORS.reset}`;
}

export function formatReport(result: ScanResult): string {
  const lines: string[] = [];

  // Summary
  lines.push(`  ${COLORS.gray}Scanned ${result.scannedFiles} files${COLORS.reset}`);
  lines.push(`  ${COLORS.gray}Found ${result.agents} agent(s), ${result.mcpServers} MCP server(s)${COLORS.reset}`);
  lines.push("");

  // Findings -- sorted by severity (INFO -> WARNING -> CRITICAL) so the most
  // important items are the last thing the user sees before the summary.
  const SEVERITY_ORDER: Record<string, number> = { pass: 0, info: 1, warning: 2, critical: 3 };

  const sorted = [...result.findings].sort(
    (a, b) => (SEVERITY_ORDER[a.severity] ?? 0) - (SEVERITY_ORDER[b.severity] ?? 0),
  );

  if (sorted.length === 0) {
    lines.push(`  ${COLORS.green}${COLORS.bold}No issues found!${COLORS.reset}`);
  } else {
    // Group consecutive INFO findings that share the same message+fix to reduce noise
    let i = 0;
    while (i < sorted.length) {
      const f = sorted[i];

      if (f.severity === "info") {
        // Collect all consecutive info findings with the same message
        const group = [f];
        while (
          i + group.length < sorted.length &&
          sorted[i + group.length].severity === "info" &&
          sorted[i + group.length].message === f.message
        ) {
          group.push(sorted[i + group.length]);
        }
        i += group.length;

        const label = SEVERITY_LABEL[f.severity] ?? f.severity;
        if (group.length > 1) {
          // Show one collapsed line with count and sample files
          const sampleFiles = group
            .filter((g) => g.file)
            .slice(0, 3)
            .map((g) => g.file);
          const extra = group.length - sampleFiles.length;
          const fileHint = sampleFiles.length > 0
            ? ` ${COLORS.gray}(${sampleFiles.join(", ")}${extra > 0 ? ` +${extra} more` : ""})${COLORS.reset}`
            : "";
          lines.push(`  ${label}  ${f.message} ${COLORS.gray}[${group.length} files]${COLORS.reset}${fileHint}`);
        } else {
          const file = f.file ? ` ${COLORS.gray}(${f.file})${COLORS.reset}` : "";
          lines.push(`  ${label}  ${f.message}${file}`);
        }
        if (f.fix) {
          lines.push(`           ${COLORS.gray}Fix: ${f.fix}${COLORS.reset}`);
        }
      } else {
        // WARNING / CRITICAL -- always print individually
        const label = SEVERITY_LABEL[f.severity] ?? f.severity;
        const file = f.file ? ` ${COLORS.gray}(${f.file})${COLORS.reset}` : "";
        lines.push(`  ${label}  ${f.message}${file}`);
        if (f.fix) {
          lines.push(`           ${COLORS.gray}Fix: ${f.fix}${COLORS.reset}`);
        }
        i++;
      }
    }
  }

  lines.push("");

  // Security posture
  lines.push(`  ${COLORS.bold}Security Posture:${COLORS.reset}`);
  lines.push(`    Identity layer:    ${result.hasIdentityLayer ? `${COLORS.green}Yes${COLORS.reset}` : `${COLORS.red}No${COLORS.reset}`}`);
  lines.push(`    Delegation chains: ${result.hasDelegation ? `${COLORS.green}Yes${COLORS.reset}` : `${COLORS.red}No${COLORS.reset}`}`);
  lines.push(`    Audit logging:     ${result.hasAuditLog ? `${COLORS.green}Yes${COLORS.reset}` : `${COLORS.red}No${COLORS.reset}`}`);
  lines.push(`    Approval workflows:${result.hasApprovals ? `${COLORS.green}Yes${COLORS.reset}` : `${COLORS.yellow} No${COLORS.reset}`}`);
  lines.push("");

  // Score
  const criticals = result.findings.filter((f) => f.severity === "critical").length;
  const warnings = result.findings.filter((f) => f.severity === "warning").length;

  lines.push(`  ${COLORS.bold}Agent Security Score: ${result.score}/10${COLORS.reset}  ${scoreBar(result.score)}  Grade: ${gradeFromScore(result.score)}`);
  lines.push(`  ${COLORS.gray}${criticals} critical, ${warnings} warnings${COLORS.reset}`);
  lines.push("");

  // CTAs
  lines.push(`  ${COLORS.gray}Learn more:${COLORS.reset} https://github.com/authora-dev/awesome-agent-security`);
  lines.push(`  ${COLORS.gray}Fix issues:${COLORS.reset} https://authora.dev/get-started`);
  lines.push("");

  return lines.join("\n");
}
