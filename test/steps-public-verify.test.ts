import assert from "node:assert/strict";
import { test } from "node:test";
import { access, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  digestMatches,
  parseSha256,
  publicVerifyStep,
  PUBLIC_VERIFY_STEP_NAME,
  ProbeConfigError,
  type LocalProbeRunner,
} from "../src/steps/public-verify.js";
import type { DnsResolver } from "../src/steps/common.js";
import type { StepCtx } from "../src/steps/runner.js";
import { PROBE_SOCKS_PORT } from "../src/render/xray-probe.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState, multiClientConfig, multiClientState } from "./fixtures.js";

/** Local sandbox of the step under test (fresh per run, pid-scoped). */
const SANDBOX = join(tmpdir(), `viper-public-probe-${process.pid}`);

async function exists(p: string): Promise<boolean> {
  try {
    await access(p);
    return true;
  } catch {
    return false;
  }
}

const GOOD_DNS: DnsResolver = async () => [fixtureConfig.ip];
const GOOD_TCP: (ip: string, port: number) => Promise<boolean> = async () => true;

function ctx(overrides: Partial<StepCtx> = {}): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: fixtureState,
    artifacts: {},
    ...overrides,
  };
}

/**
 * Fake local probe runner: records every call (so tests can assert the
 * call order and that the runner was/wasn't invoked) and captures the
 * rendered config content at runClient time (the sandbox is real, the
 * config file is deleted afterwards).
 */
class FakeProbeRunner implements LocalProbeRunner {
  calls: string[] = [];
  cfgPaths: string[] = [];
  cfgContents: string[] = [];

  constructor(private behavior: (clientIndex: number) => string | Error = () => "204") {}

  async ensureBinary(version: string): Promise<string> {
    this.calls.push(`ensureBinary:${version}`);
    return "/fake/xray";
  }

  async reapOrphans(sandbox: string): Promise<void> {
    this.calls.push(`reapOrphans:${sandbox}`);
  }

  async runClient(cfgPath: string, port: number): Promise<string> {
    this.calls.push(`runClient:${cfgPath}:${port}`);
    this.cfgPaths.push(cfgPath);
    this.cfgContents.push(await readFile(cfgPath, "utf8"));
    const result = this.behavior(this.cfgPaths.length - 1);
    if (result instanceof Error) throw result;
    return result;
  }
}

function setup(
  opts: {
    runner?: FakeProbeRunner;
    dns?: DnsResolver;
    tcp?: (ip: string, port: number) => Promise<boolean>;
    skip?: boolean;
    c?: StepCtx;
  } = {},
): {
  step: ReturnType<typeof publicVerifyStep>;
  runner: FakeProbeRunner;
  c: StepCtx;
  dnsCalls: () => number;
} {
  const runner = opts.runner ?? new FakeProbeRunner();
  let dnsCalls = 0;
  const dns =
    opts.dns ??
    (async (domain: string) => {
      dnsCalls++;
      return GOOD_DNS(domain);
    });
  const step = publicVerifyStep({
    ...(opts.skip !== undefined ? { skip: opts.skip } : {}),
    dnsResolver: dns,
    tcpCheck: opts.tcp ?? GOOD_TCP,
    runner,
  });
  return { step, runner, c: opts.c ?? ctx(), dnsCalls: () => dnsCalls };
}

// ----------------------------------------------------------------- success

test("public verify: success — 204 for every client, sandbox cleaned up", async () => {
  const { step, runner, c } = setup({ c: ctx({ config: multiClientConfig, state: multiClientState }) });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /HTTP 204 via gstatic, 3 clients/);

  // ensureBinary → orphan reap → one probe per client, in that order.
  assert.deepEqual(runner.calls.slice(0, 2), [
    `ensureBinary:${fixtureConfig.xray}`,
    `reapOrphans:${SANDBOX}`,
  ]);
  assert.equal(runner.cfgPaths.length, 3);
  assert.equal(runner.calls[2], `runClient:${join(SANDBOX, "config.json")}:${PROBE_SOCKS_PORT}`);
  // Each probe config dials the domain (not 127.0.0.1) with its own uuid.
  for (const cl of multiClientState.clients) {
    assert.ok(
      runner.cfgContents.some((content) => {
        const cfg = JSON.parse(content) as Record<string, unknown>;
        const outbound = (cfg.outbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
        const settings = outbound.settings as Record<string, unknown>;
        return settings.address === multiClientConfig.domain && settings.id === cl.uuid;
      }),
      `probe config for client "${cl.name}" dials the domain with its uuid`,
    );
  }
  assert.equal(await exists(SANDBOX), false, "sandbox removed after the run");
});

test("public verify: single client — detail says '1 client'", async () => {
  const { step, c } = setup();
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /1 client\b/);
});

// ------------------------------------------------------------ failure classes

test("public verify: DNS mismatch — failed with the DNS message, runner never invoked", async () => {
  const { step, runner, c } = setup({ dns: async () => ["198.51.100.99"] });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(
    res.detail ?? "",
    /DNS: vpn\.example\.com resolves to 198\.51\.100\.99, expected 203\.0\.113\.10/,
  );
  assert.match(res.detail ?? "", /fix DNS; tunnel not tested/);
  assert.equal(runner.calls.length, 0, "no probe side effects on a DNS failure");
});

test("public verify: domain has no A record — failed with '(none)', runner never invoked", async () => {
  const { step, runner, c } = setup({ dns: async () => [] });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /resolves to \(none\), expected 203\.0\.113\.10/);
  assert.match(res.detail ?? "", /fix DNS; tunnel not tested/);
  assert.equal(runner.calls.length, 0);
});

test("public verify: DNS resolver error (transient) — failed with the resolver message", async () => {
  const err = new Error("getaddrinfo EAI_AGAIN vpn.example.com") as Error & { code?: string };
  err.code = "EAI_AGAIN";
  const { step, c } = setup({
    dns: async () => {
      throw err;
    },
  });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /EAI_AGAIN/);
});

test("public verify: TCP connect fails — failed with the path-blocked message, runner never invoked", async () => {
  const { step, runner, c } = setup({ tcp: async () => false });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /TCP connect to 203\.0\.113\.10:443 failed/);
  assert.match(res.detail ?? "", /path blocked or port closed/);
  assert.equal(runner.calls.length, 0);
});

test("public verify: egress 000 after pre-checks pass — the per-IP-DPI message (M7 E2E headline)", async () => {
  const { step, c } = setup({ runner: new FakeProbeRunner(() => "000") });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /HTTP 000 via gstatic/);
  assert.match(res.detail ?? "", /TLS to 203\.0\.113\.10 is being killed/);
  assert.match(res.detail ?? "", /per-IP DPI block; server is healthy/);
  assert.match(res.detail ?? "", /Provision a different server IP/);
  assert.equal(await exists(SANDBOX), false, "cleaned up on failure");
});

test("public verify: egress 004 after pre-checks pass — same DPI failure class", async () => {
  const { step, c } = setup({ runner: new FakeProbeRunner(() => "004") });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /HTTP 004 via gstatic/);
  assert.match(res.detail ?? "", /per-IP DPI block; server is healthy/);
});

test("public verify: probe config rejected by xray -test — config error, not a path error", async () => {
  const { step, c } = setup({
    runner: new FakeProbeRunner(
      () => new ProbeConfigError('Error: "outbounds[0]": protocol "vless" invalid settings'),
    ),
  });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /config rejected by xray -test/);
  assert.match(res.detail ?? "", /protocol "vless" invalid settings/);
  assert.ok(!/per-IP DPI/.test(res.detail ?? ""), "not misreported as a DPI failure");
  assert.equal(await exists(SANDBOX), false, "cleaned up on failure");
});

test("public verify: generic runner failure — failed with the runner message", async () => {
  const { step, c } = setup({
    runner: new FakeProbeRunner(
      () => new Error("public probe xray did not open SOCKS port 10809 — log: address already in use"),
    ),
  });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /did not open SOCKS port 10809/);
  assert.equal(await exists(SANDBOX), false);
});

// ------------------------------------------------------------- multi-client

test("public verify: second client fails — step fails, first client's sandbox still cleaned up", async () => {
  const runner = new FakeProbeRunner((i) => (i === 1 ? "000" : "204"));
  const { step, c } = setup({
    runner,
    c: ctx({ config: multiClientConfig, state: multiClientState }),
  });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /client "phone"/);
  assert.equal(runner.cfgPaths.length, 2, "the failing client stopped the loop");
  // The first client's probe already ran (204) and its sandbox cycle
  // completed: the sandbox is gone even though the step failed.
  assert.equal(await exists(SANDBOX), false, "sandbox cleaned up after the failed client");
});

// -------------------------------------------------------------------- skip

test("public verify: skip — reported as skipped, zero side effects", async () => {
  const { step, runner, c, dnsCalls } = setup({ skip: true });
  const res = await step.run(new FakeRemote(), c);
  assert.equal(res.status, "skipped");
  assert.equal(res.detail, "--skip-public-verify");
  assert.equal(dnsCalls(), 0);
  assert.equal(runner.calls.length, 0);
  assert.equal(await exists(SANDBOX), false);
});

// ----------------------------------------------------------------- platform

test("public verify: non-Linux host — failed with a clear message, zero side effects", async () => {
  const original = process.platform;
  try {
    Object.defineProperty(process, "platform", { value: "darwin" });
    const { step, runner, c, dnsCalls } = setup();
    const res = await step.run(new FakeRemote(), c);
    assert.equal(res.status, "failed");
    assert.match(res.detail ?? "", /requires a Linux x64\/arm64 host \(got darwin\//);
    assert.equal(dnsCalls(), 0);
    assert.equal(runner.calls.length, 0);
  } finally {
    Object.defineProperty(process, "platform", { value: original });
  }
});

// ------------------------------------------------------------------ digest

const HEX = "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae";

test("parseSha256: Xray release .dgst line format", () => {
  assert.equal(parseSha256(`SHA2-256=${HEX}  Xray-linux-64.zip\n`), HEX);
});

test("parseSha256: sha256sum format and uppercase", () => {
  assert.equal(parseSha256(`${HEX.toUpperCase()}  xray\n`), HEX);
  assert.equal(parseSha256(`${HEX}  Xray-linux-arm64.zip\n`), HEX);
});

test("parseSha256: malformed → undefined", () => {
  assert.equal(parseSha256(""), undefined);
  assert.equal(parseSha256("SHA2-256=not-a-digest  Xray-linux-64.zip\n"), undefined);
  assert.equal(parseSha256("garbage\nline\n"), undefined);
});

test("digestMatches: valid (case-insensitive) and mismatch", () => {
  assert.equal(digestMatches(HEX, HEX), true);
  assert.equal(digestMatches(HEX.toUpperCase(), HEX), true);
  assert.equal(digestMatches(`${HEX}  Xray-linux-64.zip`.slice(0, 40), HEX), false);
  const other = "0".repeat(64);
  assert.equal(digestMatches(other, HEX), false);
});

// ------------------------------------------------------------------ naming

test("public verify: step name (wiring regression)", () => {
  assert.equal(PUBLIC_VERIFY_STEP_NAME, "Verify public reachability (local probe)");
  assert.equal(publicVerifyStep().name, PUBLIC_VERIFY_STEP_NAME);
});
