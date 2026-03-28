#!/usr/bin/env node

import { scanDirectory } from "./scanner.js";
import { formatReport } from "./reporter.js";

const args = process.argv.slice(2);
const targetDir = args[0] ?? ".";
const jsonOutput = args.includes("--json");
const badgeOutput = args.includes("--badge");

console.log("");
console.log("  \x1b[1m\x1b[36mAgent Security Audit\x1b[0m");
console.log("  \x1b[90mby Authora -- https://authora.dev\x1b[0m");
console.log("");
console.log(`  Scanning ${targetDir === "." ? "current directory" : targetDir}...`);
console.log("");

async function main() {
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

main().catch((err) => {
  console.error("  \x1b[31mError:\x1b[0m", (err as Error).message);
  process.exit(2);
});
