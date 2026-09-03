import assert from "node:assert/strict";
import { test } from "node:test";
import { xrayDeployStep, XRAY_CONFIG_PATH, XRAY_CONFIG_TMP } from "../src/steps/xray-deploy.js";
import { renderXrayUnit } from "../src/steps/xray-install.js";
import { renderXray } from "../src/render/xray.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
  };
}

const FAST = { attempts: 3, intervalMs: 1 };
const rendered = () => renderXray(fixtureConfig, fixtureState);

test("deploy: fresh — tmp → -test → mv → restart → active", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayUnitFile: renderXrayUnit() });
  const res = await xrayDeployStep(FAST).run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /config deployed/);

  const cmds = remote.commands;
  const idx = (frag: string) => cmds.findIndex((c) => c.includes(frag));
  // Staged file ends in .json (Xray infers config format from the suffix).
  assert.ok(idx("xray -test -c /etc/xray/config.new.json") > idx("mkdir -p /var/log/xray"));
  assert.ok(idx("mv /etc/xray/config.new.json") > idx("xray -test"));
  assert.ok(idx("systemctl restart xray") > idx("mv"));
  assert.ok(idx("systemctl is-active xray") > idx("systemctl restart xray"));
  // Stale legacy staged file (pre-fix name) is cleaned up on the change path.
  assert.ok(cmds.includes("rm -f /etc/xray/config.json.tmp"));
  assert.ok(idx("rm -f /etc/xray/config.json.tmp") < idx("xray -test"));

  // The tmp upload carried the full render; it now lives at the real path.
  const tmpUpload = remote.uploads.find((u) => u.remote === XRAY_CONFIG_TMP);
  assert.equal(tmpUpload?.content, rendered());
  assert.equal(remote.files.get(XRAY_CONFIG_PATH), rendered());
  assert.equal(remote.files.has(XRAY_CONFIG_TMP), false);
});

test("deploy: config unchanged — ok, zero mutating calls", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayConfigFile: rendered() });
  const res = await xrayDeployStep(FAST).run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /config unchanged/);
  assert.equal(remote.mutatingCommands().length, 0);
  assert.equal(remote.uploads.length, 0);
  assert.ok(!remote.commands.includes("systemctl restart xray"));
});

test("deploy: -test rejects new config — live config untouched, tmp removed", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayTestFails: 'Error: "realitySettings": field "clients" is not allowed',
  });
  const res = await xrayDeployStep(FAST).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /xray -test rejected/);
  assert.equal(remote.files.has(XRAY_CONFIG_PATH), false, "no live config ever existed");
  assert.equal(remote.files.has(XRAY_CONFIG_TMP), false, "tmp cleaned up");
  assert.ok(!remote.commands.includes("mv /etc/xray/config.new.json"));
  assert.ok(!remote.commands.includes("systemctl restart xray"));
});

test("deploy: stale legacy .tmp on the change path is removed", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayUnitFile: renderXrayUnit() });
  remote.files.set("/etc/xray/config.json.tmp", "stale");
  const res = await xrayDeployStep(FAST).run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.equal(remote.files.has("/etc/xray/config.json.tmp"), false, "stale legacy tmp removed");
});

test("deploy: -test failure with an EXISTING live config — old config preserved", async () => {
  const oldConfig = rendered() + "// old\n";
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayConfigFile: oldConfig,
    xrayTestFails: "Error: bad config",
  });
  const res = await xrayDeployStep(FAST).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.equal(remote.files.get(XRAY_CONFIG_PATH), oldConfig, "old config byte-identical");
});

test("deploy: restart fails — failed", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayUnitFile: renderXrayUnit(),
    xrayRestartFails: true,
  });
  const res = await xrayDeployStep(FAST).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /restart/);
});

test("deploy: restart ok but unit never active — failed after poll", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayUnitFile: renderXrayUnit(),
    xrayStaysInactive: true,
  });
  const res = await xrayDeployStep({ attempts: 3, intervalMs: 1 }).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /did not become active/);
});

test("deploy: xray not installed — -test fails clearly", async () => {
  const remote = new FakeRemote(); // no xray binary
  const res = await xrayDeployStep(FAST).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /xray -test rejected/);
});
