#!/usr/bin/env node
/**
 * M7 CLI — the full command surface (contract §1).
 *
 *   render     local artifacts → generated/<name>/
 *   sub        print the subscription (local, no SSH)
 *   deploy     full fresh-VPS pipeline (preflight → hardening → xray → nginx)
 *   update     no-disruption redeploy (xray deploy/verify + nginx)
 *   status     live TUI (ink) over SSH; plain snapshot when not a TTY
 *   rotate     full credential rotation (old subscription dies) + redeploy
 *   teardown   remove viper's xray + nginx artifacts
 *
 * All SSH commands take `--name <server>` and `--ip <ip>` (a per-run
 * override of the config ip — no file writes; the config + state remain
 * the source of truth). Host-key handling: the server key captured in
 * `state.hostKey` on the first deploy is verified on every later connect
 * (the `.scratch/live-m6/live.ts` connectAndVerifyHostKey pattern, wired
 * properly here); a mismatch aborts BEFORE any pipeline step runs.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import React from "react";
import { render } from "ink";
import { assertValidIpv4, ConfigError, loadServers, resolveServerName, type ServerConfig } from "./config.js";
import { ensureState, loadState, saveState, statePath, type State } from "./state.js";
import { rotateState } from "./rotate.js";
import { loadHeroBase64 } from "./hero.js";
import { connect, type SshConn } from "./ssh.js";
import { runSteps, type Step, type StepCtx } from "./steps/runner.js";
import { deploySteps, updateSteps, teardownSteps, type PipelineStepOptions } from "./pipeline.js";
import { collectStatus, renderStatusSnapshot, type StatusData } from "./status.js";
import { StatusTui } from "./status-tui.js";
import { renderNginx } from "./render/nginx.js";
import { renderPage } from "./render/page.js";
import { renderSub } from "./render/sub.js";
import { renderXray } from "./render/xray.js";

/** v1 assumption (AGENTS.md): a freshly provisioned VPS with root access. */
const SSH_USER = "root";

export interface CliFlags {
  name?: string;
  ip?: string;
  help?: boolean;
}

export function usage(): string {
  return [
    "viper — Xray/VLESS/REALITY config generator and deploy harness",
    "",
    "Usage:",
    "  viper <command> [--name <server>] [--ip <ip>]",
    "",
    "Commands:",
    "  render     render all artifacts to generated/<name>/ (local)",
    "  sub        print the subscription URL + lines (local)",
    "  deploy     full fresh-VPS pipeline (idempotent — safe to re-run)",
    "  update     no-disruption redeploy (re-render + xray + nginx)",
    "  status     live status TUI over SSH (plain snapshot when not a TTY)",
    "  rotate     rotate all credentials + redeploy (OLD SUBSCRIPTION DIES)",
    "  teardown   remove viper's xray + nginx artifacts from the server",
    "",
    "Flags:",
    "  --name <server>  target server (default: the sole server, when exactly one)",
    "  --ip <ip>        per-run IPv4 override for the SSH target + DNS check",
    "                   (no file writes; a notice is printed when it differs",
    "                   from the config value)",
    "  -h, --help       show this help",
  ].join("\n");
}

export function parseArgs(argv: string[]): { command: string | undefined; flags: CliFlags } {
  const flags: CliFlags = {};
  let command: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] as string;
    if (arg === "-h" || arg === "--help") {
      flags.help = true;
    } else if (arg === "--name") {
      const value = argv[++i];
      if (value === undefined) throw new ConfigError("cli: --name requires a value");
      flags.name = value;
    } else if (arg.startsWith("--name=")) {
      flags.name = arg.slice("--name=".length);
    } else if (arg === "--ip") {
      const value = argv[++i];
      if (value === undefined) throw new ConfigError("cli: --ip requires a value");
      flags.ip = value;
    } else if (arg.startsWith("--ip=")) {
      flags.ip = arg.slice("--ip=".length);
    } else if (arg.startsWith("-")) {
      throw new ConfigError(`cli: unknown flag "${arg}" (see --help)`);
    } else if (command === undefined) {
      command = arg;
    } else {
      throw new ConfigError(`cli: unexpected argument "${arg}"`);
    }
  }
  return { command, flags };
}

/** Pure artifact assembly — split out so it is trivially testable. */
export function buildArtifacts(
  config: ServerConfig,
  state: State,
  heroBase64: string,
): {
  files: Record<string, string>;
  sub: { url: string; lines: string[]; routingLine?: string };
} {
  const sub = renderSub(config, state);
  const nginx = renderNginx(config, state);
  return {
    files: {
      "config.json": renderXray(config, state),
      "sub.txt": sub.base64 + "\n",
      "index.html": renderPage(heroBase64),
      ...nginx,
    },
    sub: {
      url: sub.url,
      lines: sub.lines,
      ...(sub.routingLine !== undefined ? { routingLine: sub.routingLine } : {}),
    },
  };
}

/**
 * Shared preamble for every server-targeting command: load configs,
 * resolve the name, apply the `--ip` override (validated; the config
 * file is NEVER rewritten — a shallow copy carries the effective ip).
 */
export async function openServer(
  projectDir: string,
  flags: CliFlags,
): Promise<{ name: string; config: ServerConfig; ip: string }> {
  const servers = await loadServers(projectDir);
  const name = resolveServerName(flags.name, servers);
  const base = servers.get(name);
  if (base === undefined) throw new Error("cli: internal error: server not found");
  if (flags.ip !== undefined) {
    assertValidIpv4(flags.ip, "cli");
    if (flags.ip !== base.ip) {
      console.log(`cli: using --ip ${flags.ip} (config says ${base.ip}) — no file changes`);
    }
    return { name, config: { ...base, ip: flags.ip }, ip: flags.ip };
  }
  return { name, config: base, ip: base.ip };
}

/**
 * Connect to the server and verify the host key against state (the
 * live.ts reference pattern). Aborts on a mismatch BEFORE any step runs
 * — a changed key means re-provisioning or an active MITM.
 */
export async function connectServer(
  config: ServerConfig,
  ip: string,
  state: State,
  label: string,
): Promise<SshConn> {
  const conn = await connect({
    host: ip,
    port: config.sshPort,
    username: SSH_USER,
    ...(config.sshKey !== undefined ? { privateKeyPath: config.sshKey } : {}),
  });
  const fingerprint = conn.hostKeyFingerprint();
  const expected = state.hostKey?.fingerprint;
  if (expected !== undefined && fingerprint !== undefined && fingerprint !== expected) {
    await conn.close();
    throw new ConfigError(
      `cli: HOST KEY MISMATCH for ${label} — expected ${expected}, got ${fingerprint}. ` +
        `The server was re-provisioned or something is intercepting the connection. ` +
        `If you deliberately re-imaged the box, delete state/${config.name}.yml to re-key.`,
    );
  }
  return conn;
}

/** Render artifacts to generated/<name>/ and build the step ctx. */
async function buildAndStage(
  projectDir: string,
  config: ServerConfig,
  state: State,
  ip: string,
): Promise<StepCtx> {
  const heroBase64 = await loadHeroBase64(projectDir);
  const { files } = buildArtifacts(config, state, heroBase64);
  const outDir = join(projectDir, "generated", config.name);
  await mkdir(outDir, { recursive: true });
  const artifacts: Record<string, string> = {};
  for (const [filename, content] of Object.entries(files)) {
    artifacts[filename] = join(outDir, filename);
    await writeFile(join(outDir, filename), content, "utf8");
  }
  return { name: config.name, ip, config, state, artifacts };
}

function pipelineOpts(projectDir: string, name: string, heroBase64: string): PipelineStepOptions {
  return {
    persistState: (state: State) => saveState(statePath(projectDir, name), state),
    heroBase64,
  };
}

/** Print the subscription tail (shared by `render` and `sub`); the routing
 *  line is printed only when the config ships one (M8). */
function printSubscription(sub: { url: string; lines: string[]; routingLine?: string }): void {
  console.log(`Subscription: ${sub.url}`);
  for (const line of sub.lines) {
    console.log(`${line}`);
  }
  if (sub.routingLine !== undefined) {
    console.log(`${sub.routingLine}`);
  }
}

/** Connect (host key verified), run the composed pipeline, report. */
async function runPipeline(ctx: StepCtx, steps: Step[], label: string): Promise<void> {
  const { config, ip, state } = ctx;
  const conn = await connectServer(config, ip, state, label);
  try {
    const report = await runSteps(steps, conn, ctx);
    if (report.failed) {
      if (report.unrun.length > 0) {
        console.error(`skipped (after failure): ${report.unrun.join(", ")}`);
      }
      process.exitCode = 1;
    }
  } finally {
    await conn.close();
  }
}

// ----------------------------------------------------------------- render

/**
 * The `render` command (M1):
 *  1. load + validate viper.<name>.yml
 *  2. ensure state/<name>.yml exists (chmod 600) — secrets are written
 *     locally BEFORE anything else (Meridian rule)
 *  3. render all artifacts into generated/<name>/ (idempotent overwrite)
 */
async function runRender(projectDir: string, flags: CliFlags): Promise<void> {
  const { name, config } = await openServer(projectDir, flags);
  // State first: never render/push credentials that are not persisted locally.
  const { state, created } = await ensureState(projectDir, config);
  const heroBase64 = await loadHeroBase64(projectDir);

  const { files, sub } = buildArtifacts(config, state, heroBase64);
  const outDir = join(projectDir, "generated", name);
  await mkdir(outDir, { recursive: true });
  for (const [filename, content] of Object.entries(files)) {
    await writeFile(join(outDir, filename), content, "utf8");
  }

  console.log(`rendered ${name} (${config.domain}) → ${join("generated", name)}/`);
  for (const filename of Object.keys(files)) {
    console.log(`  ${filename}`);
  }
  console.log(`  state/${name}.yml (${created ? "created" : "reused"})`);
  console.log("");
  printSubscription(sub);
}

// -------------------------------------------------------------------- sub

/** `sub` (D4): ensureState + renderSub, local only — no SSH, no VPS. */
async function runSub(projectDir: string, flags: CliFlags): Promise<void> {
  const { name, config } = await openServer(projectDir, flags);
  const { state, created } = await ensureState(projectDir, config);
  const sub = renderSub(config, state);
  console.log(`state/${name}.yml (${created ? "created" : "reused"})`);
  console.log("");
  printSubscription(sub);
}

// ---------------------------------------------------- deploy / update / rotate

/** `deploy` (D1): full fresh-VPS pipeline; idempotent by construction. */
async function runDeploy(projectDir: string, flags: CliFlags): Promise<void> {
  const { name, config, ip } = await openServer(projectDir, flags);
  const { state } = await ensureState(projectDir, config);
  const ctx = await buildAndStage(projectDir, config, state, ip);
  const opts = pipelineOpts(projectDir, name, await loadHeroBase64(projectDir));
  await runPipeline(ctx, deploySteps(ctx, config, opts), `${name} deploy`);
}

/** `update` (D3): no-disruption redeploy — xray deploy/verify + nginx only. */
async function runUpdate(projectDir: string, flags: CliFlags): Promise<void> {
  const { name, config, ip } = await openServer(projectDir, flags);
  const { state } = await ensureState(projectDir, config);
  const ctx = await buildAndStage(projectDir, config, state, ip);
  const opts = pipelineOpts(projectDir, name, await loadHeroBase64(projectDir));
  await runPipeline(ctx, updateSteps(ctx, config, opts), `${name} update`);
}

/**
 * `rotate` (D5): requires an existing state file; regenerates the keypair,
 * every client uuid and the sub path; persists locally FIRST (chmod 600),
 * then re-deploys via the update pipeline. The old subscription is
 * INVALID afterwards — the new one is printed with an explicit warning.
 */
async function runRotate(projectDir: string, flags: CliFlags): Promise<void> {
  const { name, config, ip } = await openServer(projectDir, flags);
  const path = statePath(projectDir, name);
  if (!existsSync(path)) {
    throw new ConfigError(
      `cli: rotate requires an existing state file (${path}) — ` +
        `rotate targets a deployed server; run "viper deploy" first`,
    );
  }
  const rotated = rotateState(await loadState(path));
  await saveState(path, rotated); // persist locally BEFORE anything remote
  console.log(`rotated credentials → state/${name}.yml (new keypair, uuids, sub path)`);
  console.log("");

  const ctx = await buildAndStage(projectDir, config, rotated, ip);
  const opts = pipelineOpts(projectDir, name, await loadHeroBase64(projectDir));
  await runPipeline(ctx, updateSteps(ctx, config, opts), `${name} rotate`);

  const sub = renderSub(config, rotated);
  console.log("");
  console.log("WARNING: the old subscription is INVALID (new key, new uuids, new path).");
  console.log(`Re-import the NEW subscription in your clients:`);
  console.log(`  ${sub.url}`);
  for (const line of sub.lines) {
    console.log(`  ${line}`);
  }
  if (sub.routingLine !== undefined) {
    console.log(`  ${sub.routingLine}`);
  }
}

// --------------------------------------------------------------- teardown

/**
 * `teardown` (D6): removes viper's xray + nginx artifacts. Deliberately
 * NOT touched: ufw/ssh/BBR hardening (un-hardening is out of scope), the
 * nginx package, `/root/.acme.sh/`. The local state file is kept
 * (re-deploy stays possible).
 */
async function runTeardown(projectDir: string, flags: CliFlags): Promise<void> {
  const { name, config, ip } = await openServer(projectDir, flags);
  const path = statePath(projectDir, name);
  if (!existsSync(path)) {
    throw new ConfigError(
      `cli: teardown requires an existing state file (${path}) — ` +
        `teardown targets a deployed server; nothing to remove`,
    );
  }
  const state = await loadState(path);
  const ctx = await buildAndStage(projectDir, config, state, ip);
  await runPipeline(ctx, teardownSteps(), `${name} teardown`);
  console.log("");
  console.log(`state/${name}.yml kept (re-deploy stays possible); hardening NOT undone.`);
}

// ----------------------------------------------------------------- status

/**
 * `status` (D7): one persistent SSH connection; a TTY gets the ink TUI
 * (5 s refresh, q quit, r re-run checks), a non-TTY gets a single
 * plain-text snapshot and exit (also the test path).
 */
async function runStatus(projectDir: string, flags: CliFlags): Promise<void> {
  const { name, config, ip } = await openServer(projectDir, flags);
  const { state } = await ensureState(projectDir, config);
  const conn = await connectServer(config, ip, state, `${name} status`);
  const collect = (opts?: { runChecks?: boolean; prev?: StatusData }): Promise<StatusData> =>
    collectStatus(conn, config, state, opts);

  if (process.stdout.isTTY !== true) {
    const data = await collect({ runChecks: true });
    await conn.close();
    process.stdout.write(renderStatusSnapshot(data));
    return;
  }

  const instance = render(React.createElement(StatusTui, { collect }), {
    exitOnCtrlC: false,
  });
  await new Promise<void>((resolve) => {
    instance
      .waitUntilExit()
      .then(() => resolve())
      .catch(() => resolve());
  });
  await conn.close();
}

// ------------------------------------------------------------------ main

export const COMMANDS: Record<string, (projectDir: string, flags: CliFlags) => Promise<void>> = {
  render: runRender,
  sub: runSub,
  deploy: runDeploy,
  update: runUpdate,
  status: runStatus,
  rotate: runRotate,
  teardown: runTeardown,
};

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));

  if (flags.help || command === undefined) {
    console.log(usage());
    process.exitCode = command === undefined && !flags.help ? 1 : 0;
    return;
  }

  const handler = COMMANDS[command];
  if (handler === undefined) {
    throw new ConfigError(
      `cli: unknown command "${command}" (available: ${Object.keys(COMMANDS).join(", ")})`,
    );
  }

  await handler(process.cwd(), flags);
}

// Main guard: the CLI only runs when executed directly (tsx src/cli.ts,
// node dist/index.js) — importing the module in tests stays side-effect
// free.
if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err: unknown) => {
    if (err instanceof ConfigError) {
      console.error(err.message);
    } else {
      console.error(`viper: ${(err as Error).stack ?? err}`);
    }
    process.exitCode = 1;
  });
}
