import assert from "node:assert/strict";
import { test } from "node:test";
import { readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { noRecordOrRethrow, uploadRendered, defaultDnsResolver } from "../src/steps/common.js";
import { autoUpgradesStep, AUTO_UPGRADES_PATH } from "../src/steps/hardening.js";
import { runSteps, type StepCtx } from "../src/steps/runner.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState },
    artifacts: {},
  };
}

/** Build a getaddrinfo-style Error with the given code. */
const withCode = (code: string): NodeJS.ErrnoException =>
  Object.assign(new Error(`getaddrinfo ${code} vpn.example.com`), { code });

// ------------------------------------------------- noRecordOrRethrow (R4)

test("noRecordOrRethrow: ENOTFOUND/ENODATA → [] (no A record)", () => {
  assert.deepEqual(noRecordOrRethrow(withCode("ENOTFOUND")), []);
  assert.deepEqual(noRecordOrRethrow(withCode("ENODATA")), []);
});

test("noRecordOrRethrow: EAI_AGAIN is a TRANSIENT resolver failure — re-thrown", () => {
  assert.throws(
    () => noRecordOrRethrow(withCode("EAI_AGAIN")),
    (e: NodeJS.ErrnoException) => e.code === "EAI_AGAIN",
  );
});

test("noRecordOrRethrow: other codes and plain errors are re-thrown", () => {
  assert.throws(
    () => noRecordOrRethrow(withCode("ECONNREFUSED")),
    (e: NodeJS.ErrnoException) => e.code === "ECONNREFUSED",
  );
  assert.throws(() => noRecordOrRethrow(new Error("boom")));
});

// defaultDnsResolver delegates to the same mapping (smoke: no network in
// unit tests — only the mapping behavior is asserted above).
assert.equal(typeof defaultDnsResolver, "function");

// -------------------------------------------------------- uploadRendered

const viperTmpDirs = (): string[] => readdirSync(tmpdir()).filter((n) => n.startsWith("viper-up-"));
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/**
 * Assert that uploadRendered left no temp dir behind. Test files run in
 * PARALLEL processes that also create/remove viper-up-* dirs in the shared
 * tmpdir, so a plain before/after count races: assert convergence instead
 * (our dir is removed before uploadRendered resolves; dirs from parallel
 * processes are removed by their own owners, so any unknown dir must
 * disappear within moments).
 */
async function assertNoTmpLeak(beforeDirs: Set<string>, what: string): Promise<void> {
  for (let i = 0; i < 30; i++) {
    const unknown = viperTmpDirs().filter((d) => !beforeDirs.has(d));
    if (unknown.length === 0) return;
    await sleep(100);
  }
  assert.fail(`temp dir leak after ${what}: ${viperTmpDirs().join(", ")}`);
}

test("uploadRendered: uploads the exact content and cleans up the temp dir", async () => {
  const remote = new FakeRemote();
  const before = new Set(viperTmpDirs());
  await uploadRendered(remote, "line1\nline2\n", "/tmp/dest.conf", "dest.conf");
  assert.equal(remote.files.get("/tmp/dest.conf"), "line1\nline2\n");
  await assertNoTmpLeak(before, "success");
});

test("uploadRendered: SFTP failure → throws, temp dir still cleaned up (R11.1)", async () => {
  const remote = new FakeRemote({ uploadFails: "sftp: session closed" });
  const before = new Set(viperTmpDirs());
  await assert.rejects(uploadRendered(remote, "x", "/tmp/dest.conf", "dest.conf"), /sftp: session closed/);
  await assertNoTmpLeak(before, "failure");
});

test("auto-upgrades: SFTP failure surfaces as a failed step (runSteps)", async () => {
  const remote = new FakeRemote({ uploadFails: "sftp: session closed" });
  const report = await runSteps([autoUpgradesStep()], remote, ctx(), { quiet: true });
  assert.equal(report.failed, true);
  assert.equal(report.results[0]?.status, "failed");
  assert.match(report.results[0]?.detail ?? "", /sftp: session closed/);
  assert.equal(remote.files.has(AUTO_UPGRADES_PATH), false);
});
