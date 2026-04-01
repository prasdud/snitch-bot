#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const exporterPath = path.join(repoRoot, "scripts", "export-packages.mjs");
const projectsRoot = path.join(__dirname, "projects");

const CASES = [
  {
    manager: "npm",
    projectDir: "npm-project",
    installCommand: ["npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund"]],
    mustContain: [
      { name: "axios", version: "1.6.0" },
      { name: "lodash", version: "4.17.21" },
      { name: "zod", version: "3.23.8" },
    ],
  },
  {
    manager: "pnpm",
    projectDir: "pnpm-project",
    installCommand: ["pnpm", ["install", "--ignore-scripts"]],
    mustContain: [
      { name: "axios", version: "1.6.0" },
      { name: "lodash", version: "4.17.21" },
      { name: "zod", version: "3.23.8" },
    ],
  },
  {
    manager: "yarn",
    projectDir: "yarn-project",
    installCommand: ["corepack", ["yarn", "install", "--ignore-scripts", "--non-interactive"]],
    mustContain: [
      { name: "axios", version: "1.6.0" },
      { name: "lodash", version: "4.17.21" },
      { name: "zod", version: "3.23.8" },
    ],
  },
  {
    manager: "bun",
    projectDir: "bun-project",
    installCommand: ["bun", ["install", "--ignore-scripts"]],
    mustContain: [
      { name: "axios", version: "1.6.0" },
      { name: "lodash", version: "4.17.21" },
      { name: "zod", version: "3.23.8" },
    ],
  },
];

function run(command, args, cwd) {
  execFileSync(command, args, {
    cwd,
    stdio: "pipe",
    encoding: "utf8",
    env: process.env,
    maxBuffer: 100 * 1024 * 1024,
  });
}

function isExactVersion(version) {
  return typeof version === "string" && version.length > 0 && !/[\^~*><=|xX\s]/.test(version);
}

function runCase(testCase) {
  const sourceDir = path.join(projectsRoot, testCase.projectDir);
  const tempDir = mkdtempSync(path.join(os.tmpdir(), `snitch-${testCase.manager}-`));
  const workDir = path.join(tempDir, testCase.projectDir);
  cpSync(sourceDir, workDir, { recursive: true });

  try {
    run(testCase.installCommand[0], testCase.installCommand[1], workDir);

    run(process.execPath, [exporterPath, "--manager", testCase.manager, "--out", "packages.json"], workDir);
    const output = JSON.parse(readFileSync(path.join(workDir, "packages.json"), "utf8"));

    assert.ok(Array.isArray(output), `${testCase.manager}: output must be array`);
    assert.ok(output.length > 0, `${testCase.manager}: output is empty`);

    for (const entry of output) {
      assert.equal(typeof entry.name, "string", `${testCase.manager}: name must be string`);
      assert.equal(typeof entry.version, "string", `${testCase.manager}: version must be string`);
      assert.ok(isExactVersion(entry.version), `${testCase.manager}: non-exact version ${entry.version}`);
    }

    for (const dep of testCase.mustContain) {
      const found = output.some((item) => item.name === dep.name && item.version === dep.version);
      assert.ok(found, `${testCase.manager}: missing ${dep.name}@${dep.version}`);
    }

    process.stdout.write(`PASS ${testCase.manager}\n`);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

function main() {
  for (const testCase of CASES) {
    runCase(testCase);
  }
  process.stdout.write("All real exporter tests passed.\n");
}

try {
  main();
} catch (error) {
  process.stderr.write(`FAIL ${error.message}\n`);
  process.exit(1);
}
