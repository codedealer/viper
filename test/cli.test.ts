import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ConfigError } from "../src/config.js";
import { parseArgs, openServer, COMMANDS, usage, type CliFlags } from "../src/cli.js";

const REPO_ROOT = join(import.meta.dirname, "..");

/** COMMANDS lookup that narrows away the index signature's undefined. */
function command(name: string): (projectDir: string, flags: CliFlags) => Promise<void> {
  const fn = COMMANDS[name];
  if (fn === undefined) throw new Error(`test: no command "${name}"`);
  return fn;
}

// ---------------------------------------------------------- parseArgs

test("parseArgs: command + --name + --ip (space and = forms)", () => {
  const r = parseArgs(["deploy", "--name", "main", "--ip=1.2.3.4"]);
  assert.equal(r.command, "deploy");
  assert.equal(r.flags.name, "main");
  assert.equal(r.flags.ip, "1.2.3.4");

  const r2 = parseArgs(["sub", "--name", "main", "--ip", "1.2.3.4", "--help"]);
  assert.equal(r2.command, "sub");
  assert.equal(r2.flags.name, "main");
  assert.equal(r2.flags.ip, "1.2.3.4");
  assert.equal(r2.flags.help, true);
});

test("parseArgs: unknown flag, missing value, unexpected argument", () => {
  assert.throws(() => parseArgs(["deploy", "--bogus"]), /unknown flag "--bogus"/);
  assert.throws(() => parseArgs(["deploy", "--name"]), /--name requires a value/);
  assert.throws(() => parseArgs(["deploy", "--ip"]), /--ip requires a value/);
  assert.throws(() => parseArgs(["deploy", "extra"]), /unexpected argument "extra"/);
});

test("usage: lists all seven commands", () => {
  for (const cmd of ["render", "sub", "deploy", "update", "status", "rotate", "teardown"]) {
    assert.ok(usage().includes(cmd), `usage missing ${cmd}`);
  }
});

// ------------------------------------------------------------ openServer

async function tempProject(files: Record<string, string> = {}): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "viper-cli-"));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content, "utf8");
  }
  return dir;
}

const CONFIG_YML = `ip: 203.0.113.10
domain: vpn.example.com
xray: v26.3.27
clients:
  - name: default
`;

test("openServer: --ip override applies to the effective ip, prints a notice, no file writes", async () => {
  const dir = await tempProject({ "viper.main.yml": CONFIG_YML });
  const logs: string[] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => logs.push(args.join(" "));
  try {
    const { config, ip } = await openServer(dir, { ip: "198.51.100.99" });
    assert.equal(ip, "198.51.100.99");
    assert.equal(config.ip, "198.51.100.99");
    assert.equal(config.domain, "vpn.example.com");
    assert.ok(logs.some((l) => l.includes("--ip 198.51.100.99") && l.includes("203.0.113.10")));
    // no file writes: the config file is byte-identical
    assert.equal(await readFile(join(dir, "viper.main.yml"), "utf8"), CONFIG_YML);
  } finally {
    console.log = original;
    await rm(dir, { recursive: true, force: true });
  }
});

test("openServer: invalid --ip is a ConfigError (reuses the config.ts validation)", async () => {
  const dir = await tempProject({ "viper.main.yml": CONFIG_YML });
  try {
    await assert.rejects(
      openServer(dir, { ip: "999.1.2.3" }),
      (err: unknown) => err instanceof ConfigError && /not a valid IPv4/.test(err.message),
    );
    await assert.rejects(
      openServer(dir, { ip: "not-an-ip" }),
      (err: unknown) => err instanceof ConfigError && /not a valid IPv4/.test(err.message),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("openServer: unknown --name is a ConfigError", async () => {
  const dir = await tempProject({ "viper.main.yml": CONFIG_YML });
  try {
    await assert.rejects(
      openServer(dir, { name: "ghost" }),
      (err: unknown) => err instanceof ConfigError && /no server named "ghost"/.test(err.message),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ----------------------------------------------------------------- sub

test("sub: prints the subscription (local only) and creates state 600", async () => {
  const dir = await tempProject({ "viper.main.yml": CONFIG_YML });
  const logs: string[] = [];
  const original = console.log;
  console.log = (...args: unknown[]) => logs.push(args.join(" "));
  try {
    await command("sub")(dir, {});
    const out = logs.join("\n");
    assert.ok(out.includes("state/main.yml (created)"), out);
    assert.ok(out.includes("Subscription: https://vpn.example.com/"), out);
    assert.ok(/\/sub\.txt$/.test(out.split("Subscription: ")[1]?.split("\n")[0] ?? ""), out);
    assert.ok(out.includes("vless://"), out);
    assert.ok(out.includes("security=reality"), out);

    // state file exists with mode 0600
    const st = await stat(join(dir, "state", "main.yml"));
    assert.equal(st.mode & 0o777, 0o600);

    // idempotent second run: state reused
    logs.length = 0;
    await command("sub")(dir, {});
    assert.ok(logs.join("\n").includes("state/main.yml (reused)"), logs.join("\n"));
  } finally {
    console.log = original;
    await rm(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------------------------- rotate

test("rotate: requires an existing state file", async () => {
  const dir = await tempProject({ "viper.main.yml": CONFIG_YML });
  try {
    await assert.rejects(
      command("rotate")(dir, {}),
      (err: unknown) =>
        err instanceof ConfigError && /rotate requires an existing state file/.test(err.message),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("teardown: requires an existing state file", async () => {
  const dir = await tempProject({ "viper.main.yml": CONFIG_YML });
  try {
    await assert.rejects(
      command("teardown")(dir, {}),
      (err: unknown) =>
        err instanceof ConfigError && /teardown requires an existing state file/.test(err.message),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

// ------------------------------------------- entry point (real process)

function runCli(args: string[]): Promise<{ code: number; out: string; err: string }> {
  return new Promise((resolve) => {
    execFile("pnpm", ["viper", ...args], { cwd: REPO_ROOT, timeout: 60_000 }, (error, stdout, stderr) => {
      resolve({
        code: error instanceof Error ? Number((error as NodeJS.ErrnoException).code ?? 1) : 0,
        out: stdout,
        err: stderr,
      });
    });
  });
}

test("entry point: --help exits 0 with the usage", async () => {
  const r = await runCli(["--help"]);
  assert.equal(r.code, 0, r.err);
  assert.ok(r.out.includes("viper — Xray/VLESS/REALITY"), r.out);
  assert.ok(r.out.includes("rotate"));
});

test("entry point: unknown command exits 1 with a clear error", async () => {
  const r = await runCli(["frobnicate"]);
  assert.equal(r.code, 1);
  assert.ok(r.err.includes('unknown command "frobnicate"'), r.err);
});

test("entry point: unknown flag exits 1", async () => {
  const r = await runCli(["sub", "--warp"]);
  assert.equal(r.code, 1);
  assert.ok(r.err.includes('unknown flag "--warp"'), r.err);
});
