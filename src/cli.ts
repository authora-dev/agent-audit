#!/usr/bin/env node

import { scanDirectory } from "./scanner.js";
import { formatReport } from "./reporter.js";
import { scanMcpServer } from "./mcp-scanner.js";
import { formatMcpReport } from "./mcp-reporter.js";

const args = process.argv.slice(2);
const jsonOutput = args.includes("--json");
const badgeOutput = args.includes("--badge");

function getFlag(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 && idx + 1 < args.length ? args[idx + 1] : undefined;
}

// -- MCP subcommand -----------------------------------------------------------

async function mcpMain() {
  const positionals = args.filter((a) => !a.startsWith("--") && a !== "mcp");
  // Also grab positional after a --flag value
  let url = positionals[0];

  if (!url || args.includes("--help")) {
    console.log(`
  \x1b[1m@authora/agent-audit mcp\x1b[0m -- MCP Server Security Scanner

  \x1b[1mUsage:\x1b[0m
    npx @authora/agent-audit mcp <url> [options]

  \x1b[1mOptions:\x1b[0m
    --api-key <key>      API key (sent as api-key header)
    --bearer <token>     Bearer token (sent as Authorization header)
    --json               Output JSON for CI pipelines
    --fail-below <grade> Exit 1 if grade is below threshold (A+, A, B+, B, C, D)
    --help               Show this help

  \x1b[1mExamples:\x1b[0m
    npx @authora/agent-audit mcp https://mcp.authora.dev --api-key authora_live_xxx
    npx @authora/agent-audit mcp https://my-server.com --bearer sk-xxx --json
    npx @authora/agent-audit mcp https://my-server.com --fail-below B

  \x1b[90mBy Authora -- https://authora.dev\x1b[0m
`);
    process.exit(0);
  }

  if (!url.startsWith("http")) url = `https://${url}`;

  const headers: Record<string, string> = {};
  const apiKey = getFlag("--api-key");
  const bearer = getFlag("--bearer");
  const authenticated = !!(apiKey || bearer);
  if (apiKey) headers["api-key"] = apiKey;
  if (bearer) headers["Authorization"] = `Bearer ${bearer}`;

  if (!jsonOutput) {
    process.stdout.write(`  \x1b[90mScanning ${url} ...\x1b[0m`);
  }

  const result = await scanMcpServer(url, headers, authenticated);

  if (jsonOutput) {
    process.stdout.write("\r" + " ".repeat(60) + "\r");
    console.log(JSON.stringify(result, null, 2));
  } else {
    process.stdout.write("\r" + " ".repeat(60) + "\r");
    console.log(formatMcpReport(result));
  }

  // CI gate
  const failBelow = getFlag("--fail-below");
  if (failBelow) {
    const threshold = failBelow.toUpperCase();
    const order = ["F", "D", "C", "B", "B+", "A", "A+"];
    const resultIdx = order.indexOf(result.letter);
    const thresholdIdx = order.indexOf(threshold);
    if (resultIdx >= 0 && thresholdIdx >= 0 && resultIdx < thresholdIdx) {
      if (!jsonOutput) {
        console.log(
          `  \x1b[31m\x1b[1mFAILED:\x1b[0m Grade ${result.letter} is below threshold ${threshold}`,
        );
        console.log();
      }
      process.exit(1);
    }
  }
}

// -- Local scan (original) ----------------------------------------------------

async function localMain() {
  const targetDir = args.filter((a) => !a.startsWith("--"))[0] ?? ".";

  if (args.includes("--help")) {
    console.log(`
  \x1b[1m@authora/agent-audit\x1b[0m -- Agent Security Scanner

  \x1b[1mUsage:\x1b[0m
    npx @authora/agent-audit [directory]     Scan local codebase
    npx @authora/agent-audit mcp <url>       Scan remote MCP server

  \x1b[1mOptions:\x1b[0m
    --json     Output JSON
    --badge    Show README badge
    --help     Show this help

  \x1b[90mBy Authora -- https://authora.dev\x1b[0m
`);
    process.exit(0);
  }

  if (!jsonOutput) {
    console.log("");
    console.log("  \x1b[1m\x1b[36mAgent Security Audit\x1b[0m");
    console.log("  \x1b[90mby Authora -- https://authora.dev\x1b[0m");
    console.log("");
    console.log(`  Scanning ${targetDir === "." ? "current directory" : targetDir}...`);
    console.log("");
  }

  const findings = await scanDirectory(targetDir);

  if (jsonOutput) {
    console.log(JSON.stringify(findings, null, 2));
    return;
  }

  const report = formatReport(findings);
  console.log(report);

  if (badgeOutput) {
    const score = findings.score;
    const color = score >= 8 ? "brightgreen" : score >= 6 ? "yellow" : score >= 4 ? "orange" : "red";
    const grade = score >= 9 ? "A+" : score >= 8 ? "A" : score >= 7 ? "B+" : score >= 6 ? "B" : score >= 5 ? "C" : score >= 3 ? "D" : "F";
    console.log("");
    console.log(`  \x1b[1mREADME Badge:\x1b[0m`);
    console.log(`  ![Agent Security: ${grade}](https://img.shields.io/badge/Agent_Security-${grade}-${color})`);
  }

  process.exit(findings.score >= 6 ? 0 : 1);
}

// -- Router -------------------------------------------------------------------

async function main() {
  if (args[0] === "mcp") {
    await mcpMain();
  } else {
    await localMain();
  }
}

main().catch((err) => {
  console.error("  \x1b[31mError:\x1b[0m", (err as Error).message);
  process.exit(2);
});
