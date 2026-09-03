import { test } from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { render as inkRender } from "ink-testing-library";
import {
  collectStatus,
  renderStatusSnapshot,
  formatBytes,
  userStatName,
  statsApiFromRendered,
  type StatusData,
} from "../src/status.js";
import type { SshConn } from "../src/ssh.js";
import { StatusTui } from "../src/status-tui.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";

/**
 * A fake-remote wired the way a healthy deployed VPS looks after M6:
 * xray installed + active on :443, probe curl 204, cert issued,
 * sub.txt deployed, stats present.
 */
function healthyRemote(opts: ConstructorParameters<typeof FakeRemote>[0] = {}) {
  return new FakeRemote({
    xrayInstalled: true,
    xrayActive: true,
    listeningPorts: [443],
    probeCurlCode: "204",
    certIssued: true,
    subFile: "c3Vi",
    xrayActiveEnter: "Mon 2026-08-31 22:14:03 UTC",
    stats: { default: { uplink: 1048576, downlink: 1073741824 } },
    ...opts,
  });
}

const POLL_FAST = { attempts: 3, intervalMs: 1 };

test("collectStatus: full snapshot with checks (M7 D7)", async () => {
  const conn = healthyRemote();
  const data = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: true,
    poll: POLL_FAST,
  });

  assert.equal(data.name, "main");
  assert.equal(data.ip, fixtureConfig.ip);
  assert.equal(data.domain, fixtureConfig.domain);
  assert.equal(data.xrayVersion, "26.3.27");
  assert.equal(data.unitActive, true);
  assert.equal(data.unitUptime, "Mon 2026-08-31 22:14:03 UTC");
  assert.equal(data.hostUptime, "up 3 hours, 12 minutes");
  assert.equal(data.cpu, "5.0% used");
  assert.equal(data.ram, "1234 MB / 7828 MB");
  assert.equal(data.disk, "5120 MB / 40900 MB");

  const c = data.clients[0] as (typeof data.clients)[number];
  assert.equal(c.name, "default");
  assert.equal(c.uuid, fixtureState.clients[0]?.uuid);
  assert.equal(c.uplink, 1048576);
  assert.equal(c.downlink, 1073741824);

  assert.equal(data.handshake.ok, true);
  assert.match(data.handshake.detail, /REALITY handshake OK/);

  assert.ok(data.cert !== null);
  assert.equal(data.cert?.subject, "CN = viper.example");
  assert.equal(data.cert?.issuer, "C = US, O = Let's Encrypt, CN = R3");
  assert.equal(data.cert?.validTo, "Sep 30 00:00:00 2026 GMT");

  assert.equal(data.subPath, `/${fixtureState.subHash}/sub.txt`);
  assert.match(data.subMtime, /^2026-09-01 01:00:00/);
  assert.equal(typeof data.fetchedAt, "number");
});

test("collectStatus: refresh without checks carries check results from prev", async () => {
  const conn = healthyRemote();
  const first = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: true,
    poll: POLL_FAST,
  });
  const second = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: false,
    prev: first,
  });
  assert.deepEqual(second.handshake, first.handshake);
  assert.deepEqual(second.cert, first.cert);

  // without a prev, checks are reported as not run
  const third = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: false,
  });
  assert.equal(third.handshake.ok, null);
  assert.match(third.handshake.detail, /not run yet/);
  assert.equal(third.cert, null);
});

test("collectStatus: stats failure degrades to nulls, not a crash", async () => {
  const conn = healthyRemote({ statsFails: true });
  const data = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: false,
  });
  const c = data.clients[0] as (typeof data.clients)[number];
  assert.equal(c.uplink, null);
  assert.equal(c.downlink, null);
});

test("collectStatus: xray unit inactive is surfaced", async () => {
  const conn = healthyRemote({ xrayActive: false, probeCurlCode: "000" });
  const data = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: true,
    poll: POLL_FAST,
  });
  assert.equal(data.unitActive, false);
  assert.equal(data.handshake.ok, false);
});

test("collectStatus: fully failed connection degrades to n/a, never rejects (R7)", async () => {
  const conn: SshConn = {
    run: async () => {
      throw new Error("socket closed");
    },
    upload: async () => {
      throw new Error("socket closed");
    },
    close: async () => {},
    hostKeyFingerprint: () => undefined,
  };
  const data = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: false,
  });
  assert.equal(data.cpu, "n/a");
  assert.equal(data.ram, "n/a");
  assert.equal(data.disk, "n/a");
  assert.equal(data.xrayVersion, "unavailable");
  assert.equal(data.unitActive, false);
  assert.equal(data.subMtime, "n/a");
});

test("statsApiFromRendered: port comes from the rendered config.json", () => {
  assert.equal(statsApiFromRendered(fixtureConfig, fixtureState), "127.0.0.1:10085");
});

test("userStatName: matches the pinned binary's naming (email = client name)", () => {
  assert.equal(userStatName("default", "uplink"), "user>>>default>>>traffic>>>uplink");
  assert.equal(userStatName("phone", "downlink"), "user>>>phone>>>traffic>>>downlink");
});

test("formatBytes: readable units + null", () => {
  assert.equal(formatBytes(null), "n/a");
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1024), "1 KiB");
  assert.equal(formatBytes(1073741824), "1 GiB");
  assert.equal(formatBytes(1048576), "1 MiB");
});

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

function fakeStatusData(): StatusData {
  return {
    name: "main",
    ip: "203.0.113.10",
    domain: "vpn.example.com",
    xrayVersion: "26.3.27",
    unitActive: true,
    unitUptime: "Mon 2026-08-31 22:14:03 UTC",
    hostUptime: "up 3 hours, 12 minutes",
    cpu: "5.0% used",
    ram: "1234 MB / 7828 MB",
    disk: "5120 MB / 40900 MB",
    clients: [
      {
        name: "default",
        uuid: "123e4567-e89b-42d3-a456-426614174000",
        uplink: 1024,
        downlink: 2048,
      },
    ],
    handshake: { ok: true, detail: "REALITY handshake OK (HTTP 204 via gstatic)" },
    cert: {
      subject: "CN = vpn.example.com",
      issuer: "C = US, O = Let's Encrypt, CN = R3",
      validTo: "Sep 30 00:00:00 2026 GMT",
    },
    subPath: "/deadbeefcafebabe1234567890abcdef/sub.txt",
    subMtime: "2026-09-01 01:00:00.000000000 +0000",
    fetchedAt: Date.now(),
  };
}

test("renderStatusSnapshot: plain-text panels (non-TTY path)", () => {
  const out = renderStatusSnapshot(fakeStatusData());
  for (const expected of [
    "Server",
    "name:    main",
    "ip:      203.0.113.10",
    "domain:  vpn.example.com",
    "xray:    26.3.27",
    "unit:    active",
    "Host",
    "cpu:     5.0% used",
    "ram:     1234 MB / 7828 MB",
    "disk /:  5120 MB / 40900 MB",
    "Clients",
    "default (123e4567-e89b-42d3-a456-426614174000): up 1 KiB, down 2 KiB",
    "handshake: OK",
    "cert:      CN = vpn.example.com",
    "path:    /deadbeefcafebabe1234567890abcdef/sub.txt",
    "mtime:   2026-09-01 01:00:00.000000000 +0000",
    "keys: q quit, r re-run checks",
  ]) {
    assert.ok(out.includes(expected), `snapshot missing: ${expected}\n${out}`);
  }
});

test("StatusTui: ink smoke — first frame renders, 5s-style refresh repeats", async () => {
  let calls = 0;
  let firstRunChecks: boolean | undefined;
  const collect = async (opts?: { runChecks?: boolean }): Promise<StatusData> => {
    if (calls === 0) firstRunChecks = opts?.runChecks;
    calls += 1;
    return fakeStatusData();
  };

  const { lastFrame, unmount } = inkRender(React.createElement(StatusTui, { collect, refreshMs: 20 }));

  try {
    // initial load runs with checks
    await sleep(50);
    assert.equal(firstRunChecks, true);
    const frame = lastFrame();
    if (frame === undefined) assert.fail("no frame rendered");
    assert.ok(frame.includes("Server"), `frame missing Server panel:\n${frame}`);
    assert.ok(frame.includes("main"));
    assert.ok(frame.includes("203.0.113.10"));
    assert.ok(frame.includes("26.3.27"));
    assert.ok(frame.includes("default"));
    assert.ok(frame.includes("1 KiB"));
    assert.ok(frame.includes("q quit"));

    const callsAfterLoad = calls;
    await sleep(60);
    assert.ok(calls > callsAfterLoad, `expected a refresh, calls=${calls}`);
  } finally {
    unmount();
  }
});

test("StatusTui: in-flight collect blocks overlapping refreshes (R8)", async () => {
  let inFlight = 0;
  let maxInFlight = 0;
  const collect = async (): Promise<StatusData> => {
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    await sleep(40);
    inFlight -= 1;
    return fakeStatusData();
  };

  const { unmount } = inkRender(React.createElement(StatusTui, { collect, refreshMs: 10 }));
  try {
    await sleep(120);
  } finally {
    unmount();
  }
  assert.ok(maxInFlight <= 1, `overlapping collects on one connection: max in flight = ${maxInFlight}`);
});

test("StatusTui: manual r during an in-flight collect defers exactly one refresh (L2)", async () => {
  const runChecksSeen: boolean[] = [];
  let calls = 0;
  const collect = async (opts?: { runChecks?: boolean }): Promise<StatusData> => {
    runChecksSeen.push(Boolean(opts?.runChecks));
    calls += 1;
    // The initial load's collect is slow; the deferred one is fast.
    if (calls === 1) await sleep(80);
    return fakeStatusData();
  };

  const { stdin, unmount } = inkRender(React.createElement(StatusTui, { collect, refreshMs: 10_000 }));
  try {
    // While the slow initial collect is in flight, press `r` twice in
    // quick succession — both must coalesce into a single deferred refresh.
    await sleep(20);
    stdin.write("r");
    await sleep(10);
    stdin.write("r");
    await sleep(150);
  } finally {
    unmount();
  }
  assert.equal(calls, 2, `expected initial + exactly one deferred collect, got ${calls}`);
  assert.deepEqual(runChecksSeen, [true, true], "initial load and the deferred refresh both run checks");
});

test("StatusTui: shows the error frame when the first collect fails", async () => {
  const { lastFrame, unmount } = inkRender(
    React.createElement(StatusTui, {
      collect: async () => {
        throw new Error("boom");
      },
      refreshMs: 1000,
    }),
  );
  try {
    await sleep(30);
    const frame = lastFrame();
    if (frame === undefined) assert.fail("no frame rendered");
    assert.ok(frame.includes("status: boom"), `frame:\n${frame}`);
  } finally {
    unmount();
  }
});
