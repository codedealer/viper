import assert from "node:assert/strict";
import { test } from "node:test";
import { preflightStep } from "../src/steps/preflight.js";
import type { DnsResolver, HardeningStepOptions } from "../src/steps/common.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState, knobConfig } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";
import type { State } from "../src/state.js";

function ctx(overrides: Partial<StepCtx> = {}): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState },
    artifacts: {},
    ...overrides,
  };
}

const resolveTo = (ip: string): DnsResolver => async () => [ip];
const noRecord: DnsResolver = async () => [];
const resolverFails: DnsResolver = async () => {
  throw new Error("getaddrinfo EAI_AGAIN vpn.example.com");
};

async function runStep(remote: FakeRemote, c: StepCtx, opts: HardeningStepOptions = {}) {
  const step = preflightStep(opts);
  return step.run(remote, c);
}

test("preflight: all checks pass — host key captured on first deploy + persisted", async () => {
  const remote = new FakeRemote();
  const state: State = { ...fixtureState, hostKey: null };
  const persisted: State[] = [];
  const c = ctx({ state });
  const res = await runStep(remote, c, {
    dnsResolver: resolveTo(fixtureConfig.ip),
    persistState: (s) => {
      persisted.push(s);
    },
  });
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /host key captured/);
  assert.match(res.detail ?? "", /^host key captured \(SHA256:[A-Za-z0-9+/]{43}\)$/);
  // captured into the (in-place) state and persisted exactly once
  assert.equal(state.hostKey?.fingerprint, c.state.hostKey?.fingerprint);
  assert.ok(state.hostKey?.fingerprint?.startsWith("SHA256:"));
  assert.equal(persisted.length, 1);
  assert.equal(persisted[0], c.state);
});

test("preflight: second deploy verifies the captured host key (no persist)", async () => {
  const remote = new FakeRemote();
  const c = ctx(); // fixtureState.hostKey is null — set the captured one first
  const first = await runStep(remote, c, { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(first.status, "ok");
  const fp = c.state.hostKey?.fingerprint;
  assert.ok(fp !== undefined);

  const persisted: State[] = [];
  const second = await runStep(remote, c, {
    dnsResolver: resolveTo(fixtureConfig.ip),
    persistState: (s) => {
      persisted.push(s);
    },
  });
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /all OK/);
  assert.equal(persisted.length, 0, "verify path never persists");
});

test("preflight: host key mismatch → failed with re-key guidance", async () => {
  const remote = new FakeRemote();
  const c = ctx();
  await runStep(remote, c, { dnsResolver: resolveTo(fixtureConfig.ip) }); // capture

  const other = new FakeRemote({ hostKey: Buffer.from("a-completely-different-key") });
  const res = await runStep(other, c, { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /host key CHANGED/);
  assert.match(res.detail ?? "", /re-provisioned or something is intercepting/);
  assert.match(res.detail ?? "", /delete state\/main\.yml to re-key/);
});

test("preflight: unsupported OS → failed, names the OS (fail fast)", async () => {
  const remote = new FakeRemote({ osId: "centos", osVersion: "9" });
  const res = await runStep(remote, ctx(), { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /unsupported OS \(found centos\)/);
  assert.match(res.detail ?? "", /v1 supports Ubuntu\/Debian/);
  // fail fast: nothing after the OS check ran
  assert.equal(remote.commands.length, 1);
});

test("preflight: debian is accepted", async () => {
  const remote = new FakeRemote({ osId: "debian", osVersion: "12" });
  const res = await runStep(remote, ctx(), { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "ok");
});

test("preflight: disk shortfall → failed with the free number", async () => {
  const remote = new FakeRemote({ diskFreeMb: 900 });
  const res = await runStep(remote, ctx(), { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /only 900MB free on \/, need 2048MB/);
});

test("preflight: unparseable df output → failed", async () => {
  const remote = new FakeRemote();
  const realRun = remote.run.bind(remote);
  remote.run = async (cmd, opts) => {
    if (cmd === "df -BM --output=avail / | tail -1") {
      return { stdout: "???\n", stderr: "", code: 0 };
    }
    return realRun(cmd, opts);
  };
  const res = await runStep(remote, ctx(), { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /could not check free disk space/);
});

test("preflight: connected port not in sshd ports → failed with fix", async () => {
  const remote = new FakeRemote({ sshdPorts: [2222] });
  const res = await runStep(remote, ctx(), { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "failed");
  assert.match(
    res.detail ?? "",
    /connected on 22 but sshd listens on 2222 — set sshPort in viper\.main\.yml/,
  );
});

test("preflight: multiple sshd ports are all reported", async () => {
  const remote = new FakeRemote({ sshdPorts: [22, 2222] });
  const c = ctx({ config: { ...fixtureConfig, sshPort: 2222 } });
  const res = await runStep(remote, c, { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "ok");
});

test("preflight: no ports detectable at all → failed (never assume 22)", async () => {
  const remote = new FakeRemote({ sshdPorts: [] });
  const res = await runStep(remote, ctx(), { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /could not detect sshd listen ports/);
});

test("preflight: DNS no A record → failed 'create an A record'", async () => {
  const remote = new FakeRemote();
  const res = await runStep(remote, ctx(), { dnsResolver: noRecord });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /vpn\.example\.com does not resolve — create an A record for vpn\.example\.com → 203\.0\.113\.10/);
});

test("preflight: DNS wrong IP → failed with grey-cloud hint", async () => {
  const remote = new FakeRemote();
  const res = await runStep(remote, ctx(), { dnsResolver: resolveTo("198.51.100.99") });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /does not resolve to this server's IP \(203\.0\.113\.10\)/);
  assert.match(res.detail ?? "", /DNS returned: 198\.51\.100\.99/);
  assert.match(res.detail ?? "", /A record vpn\.example\.com → 203\.0\.113\.10/);
  assert.match(res.detail ?? "", /"DNS only" \(grey cloud, unproxied\)/);
});

test("preflight: multiple A records including the target → pass", async () => {
  const remote = new FakeRemote();
  const resolver: DnsResolver = async () => ["198.51.100.99", fixtureConfig.ip];
  const res = await runStep(remote, ctx(), { dnsResolver: resolver });
  assert.equal(res.status, "ok");
});

test("preflight: resolver error (network) → failed distinctly from no-record", async () => {
  const remote = new FakeRemote();
  const res = await runStep(remote, ctx(), { dnsResolver: resolverFails });
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /DNS lookup for vpn\.example\.com failed/);
  assert.match(res.detail ?? "", /EAI_AGAIN/);
});

test("preflight: read-only — no mutating commands, no uploads", async () => {
  const remote = new FakeRemote();
  await runStep(remote, ctx(), { dnsResolver: resolveTo(fixtureConfig.ip) });
  assert.deepEqual(remote.mutatingCommands(), []);
  assert.equal(remote.uploads.length, 0);
});

test("preflight: uses the configured sshPort for the port check", async () => {
  // knobConfig: sshPort 2222 — must connect-port-check against 2222
  const remote = new FakeRemote({ sshdPorts: [2222] });
  const c = ctx({ name: "alt", ip: knobConfig.ip, config: knobConfig });
  const res = await runStep(remote, c, { dnsResolver: resolveTo(knobConfig.ip) });
  assert.equal(res.status, "ok");
});