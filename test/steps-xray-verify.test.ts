import assert from "node:assert/strict";
import { test } from "node:test";
import { xrayUnitActiveStep, xrayListeningStep, xrayHandshakeProbeStep } from "../src/steps/xray-verify.js";
import { renderXrayProbeClient } from "../src/render/xray-probe.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState, multiClientConfig, multiClientState } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";

function ctx(overrides: Partial<StepCtx> = {}): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
    ...overrides,
  };
}

const FAST = { attempts: 3, intervalMs: 1 };

test("verify: unit active — ok", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayActive: true });
  const res = await xrayUnitActiveStep().run(remote, ctx());
  assert.equal(res.status, "ok");
});

test("verify: unit not active — failed", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayActive: false });
  const res = await xrayUnitActiveStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /not active/);
});

test("verify: listening on :443 — ok", async () => {
  const remote = new FakeRemote({ listeningPorts: [22, 443] });
  const res = await xrayListeningStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /listening on :443/);
});

test("verify: nothing on :443 — failed", async () => {
  const remote = new FakeRemote({ listeningPorts: [22] });
  const res = await xrayListeningStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /nothing listening on :443/);
});

test("probe: success — 204, sandbox fully cleaned up", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayActive: true });
  const res = await xrayHandshakeProbeStep(FAST).run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /HTTP 204/);

  const cmds = remote.commands;
  // Client config uploaded, validated, run, then ALWAYS cleaned up.
  const upload = remote.uploads.find((u) => u.remote === "/tmp/viper-probe/config.json");
  assert.equal(upload?.content, renderXrayProbeClient(fixtureConfig, fixtureState));
  assert.ok(cmds.includes("cd /usr/local/share/xray && xray -test -c /tmp/viper-probe/config.json"));
  // Launch backgrounds the whole job with job-level redirections (a bare
  // `cd … && nohup … &` would hold the SSH pipe open for the probe's life).
  assert.ok(
    cmds.includes(
      "(cd /usr/local/share/xray && exec nohup xray run -c /tmp/viper-probe/config.json > /tmp/viper-probe/xray.log 2>&1 < /dev/null) & echo $!",
    ),
  );
  assert.ok(cmds.includes("kill 12345 2>/dev/null"), "probe pid killed");
  const killIdx = cmds.findIndex((c) => c.startsWith("kill "));
  assert.ok(cmds[killIdx + 1] === "rm -rf /tmp/viper-probe", "sandbox removed after kill");
});

test("probe: orphan from a previously failed run is reaped before start", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayActive: true, orphanProbe: true });
  const res = await xrayHandshakeProbeStep(FAST).run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /HTTP 204/);
  const cmds = remote.commands;
  const pkillIdx = cmds.findIndex((c) => c.startsWith("pkill -f "));
  assert.ok(pkillIdx >= 0, "pkill reap issued");
  assert.ok(pkillIdx < cmds.findIndex((c) => c.includes("exec nohup xray run")), "reap happens before start");
});

test("probe: curl does not return 204 — failed, log tailed, cleaned up", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, probeCurlCode: "000" });
  const res = await xrayHandshakeProbeStep(FAST).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /HTTP 000/);
  assert.ok(remote.commands.includes("tail -n 30 /tmp/viper-probe/xray.log 2>/dev/null"));
  assert.ok(remote.commands.includes("rm -rf /tmp/viper-probe"), "cleaned up on failure");
});

test("probe: client config rejected by -test — failed, never started", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayTestClientFails: 'Error: "outbounds[0]": protocol "vless" invalid settings',
  });
  const res = await xrayHandshakeProbeStep(FAST).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /rejected by xray -test/);
  assert.ok(!remote.commands.some((c) => c.includes("nohup xray run")));
  assert.ok(remote.commands.includes("rm -rf /tmp/viper-probe"), "cleaned up");
});

test("probe: socks port never opens — failed with log tail", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, probeComesUp: false });
  const res = await xrayHandshakeProbeStep({ attempts: 3, intervalMs: 1 }).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /did not open SOCKS port 10809/);
  assert.match(res.detail ?? "", /address already in use/);
  assert.ok(remote.commands.includes("rm -rf /tmp/viper-probe"));
});

test("probe: multi-client — EVERY client is probed (R10.4)", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayActive: true });
  const c = ctx({ config: multiClientConfig, state: multiClientState });
  const res = await xrayHandshakeProbeStep(FAST).run(remote, c);
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /3 clients/);

  // One probe config upload per client, each carrying that client's uuid.
  const uploads = remote.uploads.filter((u) => u.remote === "/tmp/viper-probe/config.json");
  assert.equal(uploads.length, 3);
  for (const cl of multiClientState.clients) {
    assert.ok(
      uploads.some((u) => u.content.includes(cl.uuid)),
      `probe config for client "${cl.name}" carries its uuid`,
    );
  }
  // Three full probe cycles: 3 curls, 3 pid kills, 3 sandbox removals.
  assert.equal(remote.commands.filter((x) => x.startsWith("curl --socks5-hostname")).length, 3);
  assert.equal(remote.commands.filter((x) => x.startsWith("kill ")).length, 3);
  assert.equal(remote.commands.filter((x) => x === "rm -rf /tmp/viper-probe").length, 3);
});

test("probe: multi-client — first client failure stops the loop", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, probeCurlCode: "000" });
  const c = ctx({ config: multiClientConfig, state: multiClientState });
  const res = await xrayHandshakeProbeStep(FAST).run(remote, c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /client "default"/);
  assert.match(res.detail ?? "", /HTTP 000/);
  assert.equal(
    remote.commands.filter((x) => x.startsWith("curl --socks5-hostname")).length,
    1,
    "only the failing client was probed",
  );
  assert.ok(remote.commands.includes("rm -rf /tmp/viper-probe"), "cleaned up");
});

test("probe: xray binary missing — failed (nohup error surfaced)", async () => {
  const remote = new FakeRemote(); // no xray
  const res = await xrayHandshakeProbeStep({ attempts: 3, intervalMs: 1 }).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /did not open SOCKS port 10809/);
  assert.ok(remote.commands.includes("rm -rf /tmp/viper-probe"));
});
