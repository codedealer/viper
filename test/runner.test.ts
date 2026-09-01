import assert from "node:assert/strict";
import { test } from "node:test";
import {
  runSteps,
  type RunStepsReport,
  type Step,
  type StepCtx,
  type StepResult,
} from "../src/steps/runner.js";
import type { SshConn } from "../src/ssh.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";

/**
 * Runner semantics tests with a fake conn (the pattern M4+ steps will use:
 * steps take the conn as a parameter typed by the minimal SshConn surface).
 */

interface FakeConn extends SshConn {
  runCalls: string[];
}

function makeFakeConn(): FakeConn {
  const conn: FakeConn = {
    runCalls: [],
    run: async (cmd: string) => {
      conn.runCalls.push(cmd);
      return { stdout: "", stderr: "", code: 0 };
    },
    upload: async () => {},
    close: async () => {},
    hostKeyFingerprint: () => undefined,
  };
  return conn;
}

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: fixtureState,
    artifacts: { "config.json": "/tmp/gen/config.json" },
  };
}

/** Build a step that records its name; scripted result or throw. */
function makeStep(
  name: string,
  record: string[],
  behavior: () => StepResult | never,
): Step {
  return {
    name,
    run(conn, c) {
      record.push(name);
      assert.equal(conn, conn); // no-op: keeps params referenced
      void c;
      return behavior();
    },
  };
}

async function run(record: string[], steps: Step[], opts?: { quiet?: boolean }): Promise<RunStepsReport> {
  return runSteps(steps, makeFakeConn(), ctx(), opts);
}

/** Capture console output per stream. */
async function withCapturedConsole<T>(
  fn: () => Promise<T>,
): Promise<{ out: string[]; err: string[]; result: T }> {
  const out: string[] = [];
  const err: string[] = [];
  const origLog = console.log;
  const origErr = console.error;
  console.log = (...a: unknown[]) => out.push(a.join(" "));
  console.error = (...a: unknown[]) => err.push(a.join(" "));
  try {
    const result = await fn();
    return { out, err, result };
  } finally {
    console.log = origLog;
    console.error = origErr;
  }
}

test("sequential order, all ok — nothing unrun", async () => {
  const record: string[] = [];
  const report = await run(record, [
    makeStep("a", record, () => ({ status: "ok" })),
    makeStep("b", record, () => ({ status: "changed", detail: "installed 3 pkgs" })),
    makeStep("c", record, () => ({ status: "skipped", detail: "already set" })),
  ]);
  assert.deepEqual(record, ["a", "b", "c"]);
  assert.equal(report.failed, false);
  assert.deepEqual(report.unrun, []);
  assert.deepEqual(
    report.results.map((r) => [r.name, r.status]),
    [
      ["a", "ok"],
      ["b", "changed"],
      ["c", "skipped"],
    ],
  );
  assert.equal(report.results[1]?.detail, "installed 3 pkgs");
});

test("stop on first failure: later steps unrun and reported", async () => {
  const record: string[] = [];
  const report = await run(record, [
    makeStep("a", record, () => ({ status: "ok" })),
    makeStep("b", record, () => ({ status: "failed", detail: "apt exit 100" })),
    makeStep("c", record, () => ({ status: "ok" })),
    makeStep("d", record, () => ({ status: "ok" })),
  ]);
  assert.deepEqual(record, ["a", "b"], "steps after the failure never run");
  assert.equal(report.failed, true);
  assert.deepEqual(report.unrun, ["c", "d"]);
  assert.equal(report.results.length, 2);
});

test("trace: ✓/– lines to stdout, ✗ line to stderr, contract formats", async () => {
  const record: string[] = [];
  const { out, err, result } = await withCapturedConsole(() =>
    run(record, [
      makeStep("install xray", record, () => ({ status: "changed", detail: "v26.3.27" })),
      makeStep("set timezone", record, () => ({ status: "skipped", detail: "already UTC" })),
      makeStep("start service", record, () => ({ status: "ok" })),
      makeStep("enable ufw", record, () => ({ status: "failed", detail: "ufw: command failed" })),
    ]),
  );
  assert.deepEqual(out, [
    "✓ install xray (v26.3.27)",
    "– set timezone (skipped: already UTC)",
    "✓ start service",
  ]);
  assert.deepEqual(err, ["✗ enable ufw (ufw: command failed)"]);
  assert.equal(result.failed, true);
});

test("quiet: no trace output", async () => {
  const record: string[] = [];
  const { out, err, result } = await withCapturedConsole(() =>
    run(record, [makeStep("a", record, () => ({ status: "failed", detail: "x" }))], { quiet: true }),
  );
  assert.deepEqual(out, []);
  assert.deepEqual(err, []);
  assert.equal(result.failed, true);
});

test("step exception → failed with message; runner never crashes", async () => {
  const record: string[] = [];
  const report = await run(record, [
    makeStep("ok-step", record, () => ({ status: "ok" })),
    makeStep("throwing", record, () => {
      throw new Error("boom: ssh: upload to /etc/xray/config.json failed");
    }),
    makeStep("never", record, () => ({ status: "ok" })),
  ]);
  assert.equal(report.failed, true);
  assert.deepEqual(report.unrun, ["never"]);
  assert.equal(report.results[1]?.status, "failed");
  assert.match(report.results[1]?.detail ?? "", /boom: ssh: upload/);
});

test("steps receive the conn and ctx; sync StepResult works", async () => {
  const conn = makeFakeConn();
  const seen: Array<{ conn: SshConn; ip: string; artifact: string | undefined }> = [];
  const steps: Step[] = [
    {
      name: "probe",
      run: async (c, x) => {
        seen.push({ conn: c, ip: x.ip, artifact: x.artifacts["config.json"] });
        await c.run("uname -a"); // async usage through the conn
        return { status: "ok" };
      },
    },
  ];
  const report = await runSteps(steps, conn, ctx());
  assert.equal(report.failed, false);
  assert.deepEqual(conn.runCalls, ["uname -a"]);
  assert.equal(seen[0]?.conn, conn, "the exact conn instance is passed through");
  assert.equal(seen[0]?.ip, fixtureConfig.ip);
  assert.equal(seen[0]?.artifact, "/tmp/gen/config.json");
});

test("first step fails: unrun lists everything after it", async () => {
  const record: string[] = [];
  const report = await run(record, [
    makeStep("one", record, () => ({ status: "failed" })),
    makeStep("two", record, () => ({ status: "ok" })),
  ]);
  assert.equal(report.failed, true);
  assert.deepEqual(report.unrun, ["two"]);
  assert.equal(report.results[0]?.detail, undefined, "no detail → no detail field");
});