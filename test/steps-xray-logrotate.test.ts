import assert from "node:assert/strict";
import { test } from "node:test";
import {
  xrayLogrotateStep,
  renderXrayLogrotateDropin,
  XRAY_LOGROTATE_PATH,
} from "../src/steps/xray-logrotate.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";
import { assertGolden } from "./golden.js";

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState },
    artifacts: {},
  };
}

test("logrotate: fresh box → SFTP upload of golden content + chmod + logrotate -d → changed", async () => {
  const remote = new FakeRemote();
  const c = ctx();
  const step = xrayLogrotateStep();
  const first = await step.run(remote, c);
  assert.equal(first.status, "changed");

  const up = remote.uploads.find((u) => u.remote === XRAY_LOGROTATE_PATH);
  assert.ok(up !== undefined, "uploaded via SFTP, not heredoc");
  assert.equal(up?.content, renderXrayLogrotateDropin());
  assertGolden(import.meta.url, "xray-logrotate.conf", renderXrayLogrotateDropin());

  const cmds = remote.commands;
  const chmodIdx = cmds.indexOf(`chmod 644 ${XRAY_LOGROTATE_PATH}`);
  const validateIdx = cmds.indexOf(`logrotate -d ${XRAY_LOGROTATE_PATH}`);
  assert.ok(chmodIdx >= 0, "chmod issued");
  assert.ok(validateIdx > chmodIdx, "logrotate -d verify runs after the write");

  const second = await step.run(remote, c);
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /already configured/);
  assert.equal(remote.uploads.length, 1, "no re-upload on the idempotent run");
  // run 2 issues zero mutations (no chmod, no re-upload, no re-validate).
  const run2 = remote.commands.slice(cmds.length);
  assert.ok(!run2.some((x) => x.startsWith("chmod ")), "no re-chmod");
  assert.ok(!run2.includes(`logrotate -d ${XRAY_LOGROTATE_PATH}`), "no re-validate on the ok path");
});

test("logrotate: already matching → ok, zero mutations", async () => {
  const remote = new FakeRemote();
  remote.files.set(XRAY_LOGROTATE_PATH, renderXrayLogrotateDropin());
  const res = await xrayLogrotateStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.equal(remote.uploads.length, 0);
  assert.deepEqual(remote.mutatingCommands(), []);
});

test("logrotate: pre-existing different content → replaced (changed)", async () => {
  const remote = new FakeRemote();
  remote.files.set(XRAY_LOGROTATE_PATH, "/var/log/xray/*.log {\n    daily\n}\n");
  const res = await xrayLogrotateStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.equal(remote.files.get(XRAY_LOGROTATE_PATH), renderXrayLogrotateDropin());
});

test("logrotate: logrotate -d rejects the drop-in → failed with detail, no silent success", async () => {
  const remote = new FakeRemote({
    logrotateValidateFails: "error: /etc/logrotate.d/xray:1 unknown option 'copytruncat'",
  });
  const res = await xrayLogrotateStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /logrotate -d rejected the drop-in/);
  assert.match(res.detail ?? "", /unknown option/);
});

test("logrotate: drop-in uses copytruncate (no create) — the fd-holding rationale", () => {
  const content = renderXrayLogrotateDropin();
  assert.match(content, /copytruncate/);
  assert.ok(!/\bcreate\b/.test(content), "no `create` line alongside copytruncate");
  assert.match(content, /\/var\/log\/xray\/\*\.log/);
  assert.match(content, /missingok/);
  assert.match(content, /notifempty/);
});
