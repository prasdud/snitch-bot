#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";

function parseArgs(argv) {
  const args = { out: "packages.json", manager: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--out") {
      args.out = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--manager") {
      args.manager = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      args.help = true;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }
  return args;
}

function detectManager(explicitManager) {
  const supported = ["npm", "pnpm", "yarn", "bun"];
  if (explicitManager) {
    if (!supported.includes(explicitManager)) {
      throw new Error(`Unsupported manager: ${explicitManager}. Use one of: ${supported.join(", ")}`);
    }
    return explicitManager;
  }

  if (existsSync("bun.lock") || existsSync("bun.lockb")) return "bun";
  if (existsSync("pnpm-lock.yaml")) return "pnpm";
  if (existsSync("yarn.lock")) return "yarn";
  if (existsSync("package-lock.json") || existsSync("npm-shrinkwrap.json")) return "npm";

  throw new Error(
    "Could not detect package manager from lockfiles. Use --manager npm|pnpm|yarn|bun"
  );
}

function runJsonCommand(command, args, parseNdjson = false) {
  const raw = execFileSync(command, args, {
    encoding: "utf8",
    maxBuffer: 30 * 1024 * 1024,
  });

  if (!parseNdjson) {
    return JSON.parse(raw);
  }

  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

function runTextCommand(command, args) {
  return execFileSync(command, args, {
    encoding: "utf8",
    maxBuffer: 30 * 1024 * 1024,
  });
}

function isExactVersion(version) {
  if (typeof version !== "string" || version.length === 0) return false;
  return !/[\^~*><=|xX]/.test(version) && !version.includes(" ");
}

function parseNameVersionSpec(spec) {
  if (typeof spec !== "string") return null;

  const npmProtocol = spec.match(/^(?<name>.+)@npm:(?<version>.+)$/);
  if (npmProtocol && isExactVersion(npmProtocol.groups.version)) {
    return { name: npmProtocol.groups.name, version: npmProtocol.groups.version };
  }

  const idx = spec.lastIndexOf("@");
  if (idx <= 0) return null;

  const name = spec.slice(0, idx);
  const version = spec.slice(idx + 1);
  if (!name || !isExactVersion(version)) return null;
  return { name, version };
}

function collectDependencies(root) {
  const seen = new Set();
  const out = [];

  function walk(node) {
    if (!node || typeof node !== "object") return;
    const deps = node.dependencies;
    if (!deps || typeof deps !== "object") return;

    for (const [name, dep] of Object.entries(deps)) {
      const version = dep && dep.version;
      if (isExactVersion(version)) {
        const key = `${name}@${version}`;
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ name, version });
        }
      }
      walk(dep);
    }
  }

  walk(root);

  out.sort((a, b) => {
    const byName = a.name.localeCompare(b.name);
    if (byName !== 0) return byName;
    return a.version.localeCompare(b.version);
  });

  return out;
}

function collectFromNodes(nodes) {
  const out = [];
  const seen = new Set();

  function add(name, version) {
    if (typeof name !== "string" || !isExactVersion(version)) return;
    const key = `${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, version });
  }

  function walk(node, isRoot = false) {
    if (!node || typeof node !== "object") return;

    if (!isRoot && typeof node.name === "string" && typeof node.version === "string") {
      add(node.name, node.version);
    }

    const deps = node.dependencies;
    if (deps && typeof deps === "object" && !Array.isArray(deps)) {
      for (const [depName, depNode] of Object.entries(deps)) {
        const depVersion = depNode && depNode.version;
        if (isExactVersion(depVersion)) {
          add(depName, depVersion);
        }
        walk(depNode, false);
      }
    }

    if (Array.isArray(node)) {
      for (const item of node) walk(item, isRoot);
      return;
    }

    if (!isRoot && node.name && typeof node.name === "string") {
      const parsed = parseNameVersionSpec(node.name);
      if (parsed) add(parsed.name, parsed.version);
    }

    for (const value of Object.values(node)) {
      if (value && typeof value === "object") walk(value, false);
    }
  }

  walk(nodes);

  out.sort((a, b) => {
    const byName = a.name.localeCompare(b.name);
    if (byName !== 0) return byName;
    return a.version.localeCompare(b.version);
  });
  return out;
}

function collectFromText(raw) {
  const out = [];
  const seen = new Set();

  function add(name, version) {
    if (typeof name !== "string" || !isExactVersion(version)) return;
    const key = `${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, version });
  }

  const lines = raw.split("\n");
  for (const line of lines) {
    const tokens = line
      .split(/\s+/)
      .map((part) => part.replace(/^[\|`+\\-]+/, "").trim())
      .filter(Boolean);

    for (const token of tokens) {
      const parsed = parseNameVersionSpec(token);
      if (parsed) add(parsed.name, parsed.version);
    }
  }

  out.sort((a, b) => {
    const byName = a.name.localeCompare(b.name);
    if (byName !== 0) return byName;
    return a.version.localeCompare(b.version);
  });
  return out;
}

function loadNpmPackages() {
  const npmTree = runJsonCommand("npm", ["ls", "--all", "--json"]);
  return collectDependencies(npmTree);
}

function loadPnpmPackages() {
  const tree = runJsonCommand("pnpm", ["list", "--depth", "Infinity", "--json"]);
  return collectFromNodes(tree);
}

function loadYarnPackages() {
  try {
    const events = runJsonCommand("yarn", ["list", "--json"], true);
    return collectFromNodes(events);
  } catch (_error) {
    const events = runJsonCommand("corepack", ["yarn", "list", "--json"], true);
    return collectFromNodes(events);
  }
}

function loadBunPackages() {
  const text = runTextCommand("bun", ["list", "--all"]);
  return collectFromText(text);
}

function exportPackages(manager) {
  if (manager === "npm") return loadNpmPackages();
  if (manager === "pnpm") return loadPnpmPackages();
  if (manager === "yarn") return loadYarnPackages();
  if (manager === "bun") return loadBunPackages();
  throw new Error(`Unsupported manager: ${manager}`);
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stdout.write(
      [
        "Usage:",
        "  node scripts/export-packages.mjs [--manager npm|pnpm|yarn|bun] [--out packages.json]",
        "",
        "Examples:",
        "  node scripts/export-packages.mjs",
        "  node scripts/export-packages.mjs --manager bun --out ./packages.json",
      ].join("\n") + "\n"
    );
    return;
  }

  const manager = detectManager(args.manager);
  const packages = exportPackages(manager);
  if (packages.length === 0) {
    throw new Error(`No packages exported for manager ${manager}. Check lockfile/install state.`);
  }

  writeFileSync(args.out, `${JSON.stringify(packages, null, 2)}\n`, "utf8");
  process.stdout.write(
    `[export-packages] manager=${manager} wrote ${packages.length} packages to ${args.out}\n`
  );
}

try {
  main();
} catch (error) {
  process.stderr.write(`[export-packages] ERROR: ${error.message}\n`);
  process.exit(1);
}
