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
  certDaysLeft,
  CERT_WARN_DAYS,
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
    // A deployed VPS has the M4 hardening pipeline behind it, which
    // enables fail2ban (the sshd jail warning degrades to unknown without it).
    fail2banActive: true,
    subFile: "c3Vi",
    xrayActiveEnter: "Mon 2026-08-31 22:14:03 UTC",
    stats: { default: { uplink: 1048576, downlink: 1073741824 } },
    ...opts,
  });
}

/** Format a Date the way openssl reports `notAfter` ("Sep 4 12:00:00 2027 GMT"). */
function opensslDate(ms: number): string {
  const d = new Date(ms);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${months[d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, " ")} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} ` +
    `${d.getUTCFullYear()} GMT`
  );
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

  // M8: the fake box has v6 enabled with a global address by default.
  assert.equal(data.ipv6, "enabled (global v6 on eth0)");

  // Warnings: the healthy box is quiet on all six signals.
  assert.deepEqual(data.warnings.xrayLog, { state: "ok", total: 0, recent: [] });
  assert.deepEqual(data.warnings.nginxLog, { state: "ok", total: 0, recent: [] });
  assert.deepEqual(data.warnings.failedUnits, { state: "ok", units: [] });
  assert.deepEqual(data.warnings.fail2ban, { state: "ok", banned: 0, totalFailed: 0 });
  assert.equal(data.warnings.cert.state, "ok");
  assert.ok(
    (data.warnings.cert.daysLeft ?? 0) >= CERT_WARN_DAYS,
    "fixture cert (Sep 30 2026) is past the 14-day threshold",
  );
  assert.deepEqual(data.warnings.disk, { state: "ok", percent: 13 }); // 5120/40900 = 12.5% → rounds up
});

test("collectStatus: ipv6 line reflects the actual kernel state (M8)", async () => {
  const disabled = new FakeRemote({
    xrayInstalled: true,
    ipv6Disabled: true,
    ipv6GlobalAddr: false,
  });
  const d = await collectStatus(disabled, fixtureConfig, fixtureState);
  assert.equal(d.ipv6, "disabled (v4-only)");

  const enabled = new FakeRemote({ xrayInstalled: true });
  const e = await collectStatus(enabled, fixtureConfig, fixtureState);
  assert.equal(e.ipv6, "enabled (global v6 on eth0)");

  // sysctls not 1/1 but no global v6 address (edge: flipped mid-way).
  const limbo = new FakeRemote({ xrayInstalled: true, ipv6GlobalAddr: false });
  const l = await collectStatus(limbo, fixtureConfig, fixtureState);
  assert.equal(l.ipv6, "enabled (no global v6 address)");
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
  assert.equal(data.ipv6, "unknown", "ipv6 degrades like every other probe");
  for (const key of ["xrayLog", "nginxLog", "failedUnits", "fail2ban", "cert", "disk"] as const) {
    assert.equal(
      data.warnings[key].state,
      "unknown",
      `warnings.${key} degrades to unknown like every other probe`,
    );
  }
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
    ipv6: "disabled (v4-only)",
    cert: {
      subject: "CN = vpn.example.com",
      issuer: "C = US, O = Let's Encrypt, CN = R3",
      validTo: "Sep 30 00:00:00 2026 GMT",
    },
    warnings: {
      xrayLog: { state: "ok", total: 0, recent: [] },
      nginxLog: { state: "ok", total: 0, recent: [] },
      failedUnits: { state: "ok", units: [] },
      fail2ban: { state: "ok", banned: 0, totalFailed: 0 },
      cert: { state: "ok", daysLeft: 30 },
      disk: { state: "ok", percent: 12 },
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
    // Warnings: all-quiet state — one calm line per watched signal.
    "Warnings",
    "xray:      ok",
    "nginx:     ok",
    "units:     ok",
    "fail2ban:  0 banned",
    "cert:      30 days left",
    "disk:      12% used",
    "handshake: OK",
    "ipv6:      disabled (v4-only)",
    "cert:      CN = vpn.example.com",
    "path:    /deadbeefcafebabe1234567890abcdef/sub.txt",
    "mtime:   2026-09-01 01:00:00.000000000 +0000",
    "keys: q quit, r re-run checks",
  ]) {
    assert.ok(out.includes(expected), `snapshot missing: ${expected}\n${out}`);
  }
});

test("certDaysLeft: openssl notAfter format, expired, unparseable", () => {
  assert.equal(certDaysLeft(opensslDate(Date.now() + 30 * 86_400_000)), 30);
  // openssl's two-space day padding (single-digit days).
  assert.ok((certDaysLeft("Mar  1 00:00:00 2027 GMT") ?? -1) >= CERT_WARN_DAYS);
  assert.equal(certDaysLeft("Jan 1 00:00:00 2020 GMT"), 0, "already past = 0 (still a warning)");
  assert.equal(certDaysLeft(""), null);
  assert.equal(certDaysLeft("garbage"), null);
});

test("collectStatus: warnings surface warning states per signal", async () => {
  const xrayErrors = Array.from(
    { length: 7 },
    (_, i) => `2026-09-01 02:00:0${i} WARNING proxy: connection error ${i}`,
  );
  const nginxErrors = [
    "2026/09/01 02:00:00 [error] 123#123: *4 connect() failed (111: Connection refused)",
    "2026/09/01 02:00:01 [emerg] 123#123: bind() failed",
  ];
  const unitLine = "xray.service   loaded failed failed   VLESS/REALITY proxy";
  const conn = healthyRemote({
    xrayErrorLog: xrayErrors.join("\n"),
    nginxErrorLog: nginxErrors.join("\n"),
    failedUnits: [unitLine],
    fail2banBanned: 3,
    fail2banTotalFailed: 41,
    certNotAfter: opensslDate(Date.now() + 10 * 86_400_000),
    diskTotalMb: 10_000,
    diskUsedMb: 9_000,
  });
  const data = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: true,
    poll: POLL_FAST,
  });

  assert.equal(data.warnings.xrayLog.state, "warn");
  assert.equal(data.warnings.xrayLog.total, 7);
  assert.deepEqual(data.warnings.xrayLog.recent, xrayErrors.slice(-5));
  assert.deepEqual(data.warnings.nginxLog, { state: "warn", total: 2, recent: nginxErrors });
  assert.deepEqual(data.warnings.failedUnits, { state: "warn", units: [unitLine] });
  assert.deepEqual(data.warnings.fail2ban, { state: "warn", banned: 3, totalFailed: 41 });
  assert.deepEqual(data.warnings.cert, { state: "warn", daysLeft: 10 });
  assert.deepEqual(data.warnings.disk, { state: "warn", percent: 90 });
  assert.equal(data.disk, "9000 MB / 10000 MB");
});

test("collectStatus: each warning probe degrades independently", async () => {
  const base = { runChecks: false } as const;

  // xray log missing: only xrayLog is unknown
  let d = await collectStatus(
    healthyRemote({ xrayErrorLogMissing: true }),
    fixtureConfig,
    fixtureState,
    base,
  );
  assert.equal(d.warnings.xrayLog.state, "unknown");
  assert.equal(d.warnings.nginxLog.state, "ok");
  assert.equal(d.cpu, "5.0% used", "other probes stay intact");
  assert.equal(d.warnings.disk.state, "ok");

  // nginx log missing: only nginxLog is unknown
  d = await collectStatus(healthyRemote({ nginxErrorLogMissing: true }), fixtureConfig, fixtureState, base);
  assert.equal(d.warnings.nginxLog.state, "unknown");
  assert.equal(d.warnings.xrayLog.state, "ok");

  // systemctl --failed fails: only units is unknown
  d = await collectStatus(healthyRemote({ failedUnitsFails: true }), fixtureConfig, fixtureState, base);
  assert.equal(d.warnings.failedUnits.state, "unknown");
  assert.equal(d.warnings.xrayLog.state, "ok");
  assert.equal(d.warnings.nginxLog.state, "ok");

  // fail2ban client call fails (checks path): only fail2ban is unknown
  d = await collectStatus(healthyRemote({ fail2banClientFails: true }), fixtureConfig, fixtureState, {
    runChecks: true,
    poll: POLL_FAST,
  });
  assert.equal(d.warnings.fail2ban.state, "unknown");
  assert.ok(d.cert !== null, "the cert check still ran");
  assert.equal(d.warnings.xrayLog.state, "ok");

  // df fails: disk metric + warning are n/a/unknown, cpu/ram intact
  d = await collectStatus(healthyRemote({ dfFails: true }), fixtureConfig, fixtureState, base);
  assert.equal(d.disk, "n/a");
  assert.equal(d.warnings.disk.state, "unknown");
  assert.equal(d.cpu, "5.0% used");
  assert.equal(d.ram, "1234 MB / 7828 MB");

  // cert probe fails (checks path): cert null + cert warning unknown, logs intact
  d = await collectStatus(healthyRemote({ certIssued: false }), fixtureConfig, fixtureState, {
    runChecks: true,
    poll: POLL_FAST,
  });
  assert.equal(d.cert, null);
  assert.equal(d.warnings.cert.state, "unknown");
  assert.equal(d.warnings.xrayLog.state, "ok");
});

test("collectStatus: checks-path warnings carry over from prev (fail2ban/cert)", async () => {
  const conn = healthyRemote({
    fail2banBanned: 3,
    fail2banTotalFailed: 41,
    certNotAfter: opensslDate(Date.now() + 10 * 86_400_000),
  });
  const first = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: true,
    poll: POLL_FAST,
  });
  assert.equal(first.warnings.fail2ban.state, "warn");
  assert.equal(first.warnings.cert.state, "warn");

  const second = await collectStatus(conn, fixtureConfig, fixtureState, {
    runChecks: false,
    prev: first,
  });
  assert.deepEqual(second.warnings.fail2ban, first.warnings.fail2ban);
  assert.deepEqual(second.warnings.cert, first.warnings.cert);
  // The refresh-path signals were re-probed, not carried.
  assert.equal(second.warnings.xrayLog.state, "ok");

  // without a prev, the checks-path signals report unknown
  const third = await collectStatus(conn, fixtureConfig, fixtureState, { runChecks: false });
  assert.equal(third.warnings.fail2ban.state, "unknown");
  assert.equal(third.warnings.cert.state, "unknown");
  assert.equal(third.warnings.xrayLog.state, "ok", "refresh-path signals are probed anyway");
});

test("renderStatusSnapshot: warnings section (populated, golden)", () => {
  const d = fakeStatusData();
  const xrayErrors = [
    "2026-09-01 02:00:03 WARNING proxy: connection error 3",
    "2026-09-01 02:00:04 WARNING proxy: connection error 4",
    "2026-09-01 02:00:05 WARNING proxy: connection error 5",
    "2026-09-01 02:00:06 WARNING proxy: connection error 6",
    "2026-09-01 02:00:07 WARNING proxy: connection error 7",
  ];
  d.warnings = {
    xrayLog: { state: "warn", total: 7, recent: xrayErrors },
    nginxLog: { state: "warn", total: 1, recent: ["2026/09/01 02:00:01 [emerg] 123#123: bind() failed"] },
    failedUnits: { state: "warn", units: ["xray.service   loaded failed failed   VLESS/REALITY proxy"] },
    fail2ban: { state: "warn", banned: 3, totalFailed: 41 },
    cert: { state: "warn", daysLeft: 10 },
    disk: { state: "warn", percent: 90 },
  };
  const out = renderStatusSnapshot(d);
  for (const expected of [
    "Warnings",
    "xray:      7 errors (last 5)",
    "           2026-09-01 02:00:03 WARNING proxy: connection error 3",
    "           2026-09-01 02:00:07 WARNING proxy: connection error 7",
    "nginx:     1 error (last 1)",
    "           2026/09/01 02:00:01 [emerg] 123#123: bind() failed",
    "units:     1 failed",
    "           xray.service   loaded failed failed   VLESS/REALITY proxy",
    "fail2ban:  3 banned (total failed: 41)",
    "cert:      10 days left",
    "disk:      90% used",
    // section order: Warnings sits between Clients and Checks
    "Clients",
    "Checks",
  ]) {
    assert.ok(out.includes(expected), `snapshot missing: ${expected}\n${out}`);
  }
});

test("renderStatusSnapshot: unknown warning lines stay calm and stable", () => {
  const d = fakeStatusData();
  d.warnings = {
    xrayLog: { state: "unknown", total: null, recent: [] },
    nginxLog: { state: "ok", total: 0, recent: [] },
    failedUnits: { state: "ok", units: [] },
    fail2ban: { state: "unknown", banned: null, totalFailed: null },
    cert: { state: "unknown", daysLeft: null },
    disk: { state: "ok", percent: 12 },
  };
  const out = renderStatusSnapshot(d);
  for (const expected of [
    "xray:      unknown",
    "nginx:     ok",
    "units:     ok",
    "fail2ban:  unknown (not run yet)",
    "cert:      unknown (not run yet)",
    "disk:      12% used",
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
    // Warnings panel: one line per watched signal (quiet state)
    assert.ok(frame.includes("Warnings"), `frame missing Warnings panel:\n${frame}`);
    assert.ok(frame.includes("fail2ban"));
    assert.ok(frame.includes("12% used"));
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
