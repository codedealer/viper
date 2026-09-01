import assert from "node:assert/strict";
import { test } from "node:test";
import { xrayTeardownStep } from "../src/steps/xray-teardown.js";
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

test("teardown: fully installed — unit, binary, geo, config removed", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayActive: true,
    xrayUnitFile: renderXrayUnit(),
    xrayConfigFile: renderXray(fixtureConfig, fixtureState),
  });
  const res = await xrayTeardownStep().run(remote, ctx());
  assert.equal(res.status, "changed");

  const cmds = remote.commands;
  // Stop BEFORE removing (no lockout-style ordering surprise for xray).
  assert.ok(
    cmds.findIndex((c) => c.includes("disable --now")) < cmds.findIndex((c) => c.includes("rm -f /usr/local/bin/xray")),
  );
  assert.ok(cmds.includes("rm -f /etc/systemd/system/xray.service"));
  assert.ok(cmds.includes("systemctl daemon-reload"));
  assert.ok(cmds.includes("rm -f /usr/local/bin/xray"));
  assert.ok(cmds.includes("rm -rf /usr/local/share/xray"));
  assert.ok(cmds.includes("rm -rf /etc/xray"));
  // nginx is M6's scope — teardown must not touch it.
  assert.ok(!cmds.some((c) => c.includes("nginx")));
  // Logs left in place for forensics.
  assert.ok(!cmds.some((c) => c.includes("/var/log/xray")));
});

test("teardown: nothing present — ok, zero mutating calls", async () => {
  const remote = new FakeRemote();
  const res = await xrayTeardownStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /not present/);
  assert.equal(remote.mutatingCommands().length, 0);
});

test("teardown: second run — ok (idempotent)", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayUnitFile: renderXrayUnit(),
    xrayConfigFile: renderXray(fixtureConfig, fixtureState),
  });
  const first = await xrayTeardownStep().run(remote, ctx());
  assert.equal(first.status, "changed");
  const second = await xrayTeardownStep().run(remote, ctx());
  assert.equal(second.status, "ok");
});

test("teardown: config file only — still removed", async () => {
  const remote = new FakeRemote({
    xrayConfigFile: renderXray(fixtureConfig, fixtureState),
  });
  const res = await xrayTeardownStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("rm -rf /etc/xray"));
});