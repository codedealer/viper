import assert from "node:assert/strict";
import { test } from "node:test";
import { packagesStep } from "../src/steps/packages.js";
import { REQUIRED_PACKAGES } from "../src/steps/common.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";
import type { State } from "../src/state.js";

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
  };
}

async function runStep(remote: FakeRemote, c: StepCtx, persist?: (s: State) => Promise<void> | void) {
  const step = packagesStep(persist !== undefined ? { persistState: persist } : {});
  return step.run(remote, c);
}

test("packages: fresh box — updates, installs all four, records + persists", async () => {
  const remote = new FakeRemote();
  const c = ctx();
  const persisted: State[] = [];
  const res = await runStep(remote, c, (s) => {
    persisted.push(s);
  });
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /installed/);
  // regression pin (live run-2 anomaly): the showformat MUST carry
  // ${Package}, otherwise dpkg-query prints nameless status lines and the
  // step can never recognize installed packages.
  const checkCmd = remote.commands.find((x) => x.startsWith("dpkg-query")) ?? "";
  assert.match(checkCmd, /\$\{Package\}/);
  assert.match(checkCmd, /\$\{Status\}/);
  for (const p of REQUIRED_PACKAGES) assert.match(res.detail ?? "", new RegExp(p));
  // update ran before install
  const updateIdx = remote.commands.findIndex((x) => x.includes("apt-get update"));
  const installIdx = remote.commands.findIndex((x) => x.includes("apt-get install"));
  assert.ok(updateIdx >= 0 && installIdx >= 0 && updateIdx < installIdx);
  // install listed all four
  const install = remote.commands[installIdx] ?? "";
  for (const p of REQUIRED_PACKAGES) assert.match(install, new RegExp(`\\b${p}\\b`));
  // recorded in state and persisted exactly once
  assert.deepEqual([...c.state.installedPackages], [...REQUIRED_PACKAGES]);
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0], c.state);
  assert.deepEqual([...c.state.installedPackages], [...REQUIRED_PACKAGES]);
});

test("packages: second run — everything present AND recorded, no mutating calls, no persist", async () => {
  const remote = new FakeRemote({ packages: [...REQUIRED_PACKAGES] });
  const c: StepCtx = {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [...REQUIRED_PACKAGES] },
    artifacts: {},
  };
  const persisted: State[] = [];
  const res = await runStep(remote, c, (s) => {
    persisted.push(s);
  });
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /packages present/);
  assert.deepEqual(remote.mutatingCommands(), []);
  assert.equal(persisted.length, 0);
});

test("packages: all present but not yet recorded → ok + records + persists once", async () => {
  const remote = new FakeRemote({ packages: [...REQUIRED_PACKAGES] });
  const c = ctx(); // installedPackages: []
  const persisted: State[] = [];
  const res = await runStep(remote, c, (s) => {
    persisted.push(s);
  });
  assert.equal(res.status, "ok");
  assert.deepEqual([...c.state.installedPackages].sort(), [...REQUIRED_PACKAGES].sort());
  assert.equal(persisted.length, 1);
});

test("packages: partially present — installs only the missing ones", async () => {
  const remote = new FakeRemote({ packages: ["nginx", "ufw"] });
  const c = ctx();
  const res = await runStep(remote, c);
  assert.equal(res.status, "changed");
  const install = remote.commands.find((x) => x.includes("apt-get install"));
  assert.ok(install !== undefined);
  assert.match(install, /\bfail2ban\b/);
  assert.match(install, /\bunattended-upgrades\b/);
  assert.doesNotMatch(install, /\bnginx\b/);
  assert.doesNotMatch(install, /\bufw\b/);
  assert.deepEqual([...c.state.installedPackages].sort(), [...REQUIRED_PACKAGES].sort());
});

test("packages: apt-get update fails → failed, no install attempted", async () => {
  const remote = new FakeRemote({ aptUpdateFails: "W: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/noble/InRelease 404 Not Found" });
  const c = ctx();
  const res = await runStep(remote, c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /apt-get update failed/);
  assert.ok(!remote.commands.some((x) => x.includes("apt-get install")));
  assert.deepEqual(c.state.installedPackages, []);
});

test("packages: apt-get install fails → failed, nothing recorded", async () => {
  const remote = new FakeRemote({ aptInstallFails: "E: Unable to fetch some archives" });
  const c = ctx();
  const persisted: State[] = [];
  const res = await runStep(remote, c, (s) => {
    persisted.push(s);
  });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /apt-get install failed/);
  assert.deepEqual(c.state.installedPackages, []);
  assert.equal(persisted.length, 0, "no persistence on failure");
});

test("packages: dpkg-query error (no packages at all) → treats as none installed", async () => {
  // covered by the fresh-box test: dpkg-query exits 1 with no output there
  const remote = new FakeRemote();
  const res = await runStep(remote, ctx());
  assert.equal(res.status, "changed");
});