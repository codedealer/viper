import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import tls from "node:tls";
import net from "node:net";
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkIp, formatCheck, probePayload, probePort } from "../src/check.js";
import { parseArgs } from "../src/cli.js";

const httpSrv = http.createServer((_req, res) => {
  res.writeHead(200);
  res.end("ok");
});
/** Accepts TCP then goes silent — the filtered/degraded-path simulation. */
const silentSrv = net.createServer(() => {});
let tlsSrv: tls.Server;
let openPort = 0;
let silentPort = 0;
let tlsPort = 0;
let closedPort = 0;
let dir: string;

function listen(server: net.Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") throw new Error("test: no port");
      resolve(addr.port);
    });
  });
}

before(async () => {
  dir = await mkdtemp(join(tmpdir(), "viper-check-"));
  openPort = await listen(httpSrv);
  silentPort = await listen(silentSrv);
  // throwaway self-signed cert: the probe must count a cert-invalid TLS
  // exchange as OK (records flowed — that is the signal, not validity)
  const key = join(dir, "key.pem");
  const cert = join(dir, "cert.pem");
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      key,
      "-out",
      cert,
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=127.0.0.1",
    ],
    { stdio: "ignore" },
  );
  tlsSrv = tls.createServer({ key: await readFile(key), cert: await readFile(cert) }, (sock) => {
    // minimal HTTP reply: handshake + records both ways
    sock.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
  });
  tlsPort = await listen(tlsSrv);
  // a port that was listening and is now not → RST → "closed"
  const tmp = net.createServer(() => {});
  closedPort = await listen(tmp);
  await new Promise<void>((res) => tmp.close(() => res()));
});

after(async () => {
  await Promise.all(
    [httpSrv, silentSrv, tlsSrv].map((s) => new Promise<void>((res) => s.close(() => res()))),
  );
  await rm(dir, { recursive: true, force: true });
});

// ------------------------------------------------------------ probePort

test("probePort: open port — open with connect time", async () => {
  const r = await probePort("127.0.0.1", openPort, 2_000);
  assert.equal(r.state, "open");
  assert.ok(r.ms !== undefined && r.ms >= 0);
});

test("probePort: closed port — RST classified closed, NOT filtered", async () => {
  const r = await probePort("127.0.0.1", closedPort, 2_000);
  assert.equal(r.state, "closed");
  assert.ok(r.failMs !== undefined && r.failMs < 2_000);
});

test("probePort: blackhole IP — timeout classified filtered", async () => {
  // A silent acceptor completes the TCP handshake (open) — the deinserver
  // lesson. "filtered" at the TCP layer means no answer at all: use a
  // non-routable TEST-NET address (timeout, or an unreachable error — both
  // classify filtered).
  const r = await probePort("192.0.2.1", 443, 400);
  assert.equal(r.state, "filtered");
});

// ------------------------------------------------------------ probePayload

test("probePayload http: healthy server — all iterations complete", async () => {
  const r = await probePayload("127.0.0.1", openPort, 3, 2_000, "http");
  assert.equal(r.ok, 3);
  assert.equal(r.total, 3);
  assert.ok(r.medianMs !== undefined && r.medianMs >= 0);
  assert.equal(r.errors.length, 0);
});

test("probePayload http: silent acceptor — 0 completed, errors recorded", async () => {
  const r = await probePayload("127.0.0.1", silentPort, 2, 400, "http");
  assert.equal(r.ok, 0);
  assert.ok(r.errors.length > 0);
});

test("probePayload tls: self-signed server — handshake counts as OK", async () => {
  const r = await probePayload("127.0.0.1", tlsPort, 3, 2_000, "tls");
  assert.equal(r.ok, 3);
  assert.equal(r.total, 3);
});

// ---------------------------------------------------------------- checkIp

test("checkIp: no filtered ports, mixed open/closed — clean verdict", async () => {
  const r = await checkIp({ ip: "127.0.0.1", ports: [openPort, closedPort], iters: 2, timeoutMs: 500 });
  assert.equal(r.verdict, "clean");
  const states = new Map(r.ports.map((p) => [p.port, p.state]));
  assert.equal(states.get(openPort), "open");
  assert.equal(states.get(closedPort), "closed");
  assert.equal(r.payloads.length, 0, "no 443/80 among the probed ports");
  const out = formatCheck(r);
  assert.match(out, /verdict: clean/);
  assert.match(out, /path clean/);
});

test("checkIp: all probed ports closed — clean (unprovisioned-box shape)", async () => {
  const r = await checkIp({ ip: "127.0.0.1", ports: [closedPort], iters: 1, timeoutMs: 500 });
  assert.equal(r.verdict, "clean");
  assert.match(formatCheck(r), /all probed ports closed/);
});

// -------------------------------------------------------------- parseArgs

test("parseArgs: check flags (--ip, --ports, --iters)", () => {
  const r = parseArgs(["check", "--ip", "1.2.3.4", "--ports", "22,443,2053", "--iters", "5"]);
  assert.equal(r.command, "check");
  assert.equal(r.flags.ip, "1.2.3.4");
  assert.equal(r.flags.ports, "22,443,2053");
  assert.equal(r.flags.iters, "5");

  const r2 = parseArgs(["check", "--ip=5.6.7.8", "--ports=80", "--iters=3"]);
  assert.equal(r2.flags.ip, "5.6.7.8");
  assert.equal(r2.flags.ports, "80");
  assert.equal(r2.flags.iters, "3");
});

test("parseArgs: check flag value validation errors", () => {
  assert.throws(() => parseArgs(["check", "--ports"]), /--ports requires a value/);
  assert.throws(() => parseArgs(["check", "--iters"]), /--iters requires a value/);
});
