/**
 * Pre-deploy path probe (`viper check --ip <ip>`) — run from the end
 * user's network BEFORE money moves to a host.
 *
 * Lesson encoded here (deinserver, 2026-09): `TcpTestSucceeded` is NOT a
 * sufficient host test. RKN/ISP degradation can leave the TCP handshake
 * alive (or kill it) while dropping protocol payload — a 443 that
 * "connects" at the TCP layer can still be useless for TLS. So the probe
 * is two-layer:
 *
 *  1. TCP classification per port — a FAILED connect is timed:
 *     fast failure (≈1 RTT, RST) = closed (no listener, path fine);
 *     timeout = filtered (the blocklist signature). On a fresh VPS most
 *     ports are closed, so "443 closed" is GOOD news and "443 filtered"
 *     is a listed-IP marker.
 *  2. Payload verification on open ports — repeated TLS (443) / HTTP (80)
 *     exchanges. Any completed TLS handshake counts, including
 *     self-signed/cert-mismatch: the point is that TLS records flow in
 *     both directions, not that the certificate is valid.
 *
 * Local only: no SSH, no project config — the candidate IP is the input.
 */
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { performance } from "node:perf_hooks";

type AttemptResult = { ok: boolean; ms: number; error: string | undefined };

export interface CheckOptions {
  ip: string;
  /** Ports to TCP-probe. Default: the management + VPN-relevant set. */
  ports: number[];
  /** Payload iterations per open TLS/HTTP port. */
  iters: number;
  /** Per-attempt timeout (TCP connect, TLS/HTTP exchange). */
  timeoutMs: number;
}

export type PortState = "open" | "closed" | "filtered";

export interface PortResult {
  port: number;
  state: PortState;
  /** Connect time in ms — present for `open`. */
  ms?: number;
  /** Failure time in ms — present for `closed` (fast RST) / `filtered` (timeout). */
  failMs?: number;
}

export interface PayloadResult {
  port: number;
  /** Completed exchanges (a TLS cert error still counts — records flowed). */
  ok: number;
  total: number;
  /** Median duration of successful exchanges, ms. */
  medianMs?: number;
  /** Distinct error messages from failed exchanges. */
  errors: string[];
}

export interface CheckResult {
  ip: string;
  ports: PortResult[];
  payloads: PayloadResult[];
  verdict: "clean" | "suspect" | "blocked";
  notes: string[];
}

export const DEFAULT_CHECK_PORTS = [22, 80, 443, 2053, 8443];

const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;

/** TCP-connect a port; classify open / closed (RST) / filtered (no answer). */
export function probePort(ip: string, port: number, timeoutMs: number): Promise<PortResult> {
  return new Promise((resolve) => {
    const started = performance.now();
    let settled = false;
    const finish = (r: PortResult) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };
    // ECONNREFUSED arrives in ~1 RTT: the packet made the round trip, so the
    // path is alive — the port is merely closed (no listener). Silence
    // (connect timeout) or a host-unreachable error means packets were eaten:
    // filtered. NOTE: destroying a timed-out socket surfaces ECONNRESET, so
    // the explicit `timedOut` flag decides — never the error code alone.
    const sock = net.connect({ host: ip, port, timeout: timeoutMs });
    sock.on("connect", () => {
      finish({ port, state: "open", ms: performance.now() - started });
      sock.destroy();
    });
    sock.on("timeout", () => {
      finish({ port, state: "filtered", failMs: performance.now() - started });
      sock.destroy();
    });
    sock.on("error", (err: NodeJS.ErrnoException) => {
      const failMs = performance.now() - started;
      const closed = err.code === "ECONNREFUSED" && failMs < timeoutMs;
      finish({ port, state: closed ? "closed" : "filtered", failMs });
    });
  });
}

/** One HTTPS exchange against `ip:port` (SNI = ip, cert validation off). */
function tlsAttempt(ip: string, port: number, timeoutMs: number): Promise<AttemptResult> {
  return new Promise((resolve) => {
    const started = performance.now();
    const req = https.request(
      {
        host: ip,
        port,
        path: "/",
        method: "GET",
        // no SNI for bare IPs (Node deprecates IP servernames; the probe
        // only needs TLS records to flow)
        ...(ipv4Re.test(ip) ? {} : { servername: ip }),
        rejectUnauthorized: false,
        timeout: timeoutMs,
      },
      () => {
        req.destroy();
        // A response OR a cert/protocol error after the handshake both prove
        // TLS records flowed both ways.
        resolve({ ok: true, ms: performance.now() - started, error: undefined });
      },
    );
    req.on("error", (err: Error & { code?: string }) => {
      // A TLS alert (handshake failed / no records) means the payload path
      // is dead even if the TCP layer connected.
      const ok = err.code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" || err.code === "DEPTH_ZERO_SELF_SIGNED_CERT";
      resolve({ ok, ms: performance.now() - started, error: ok ? undefined : `${err.code ?? err.message}` });
    });
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, ms: performance.now() - started, error: "timeout" });
    });
    req.end();
  });
}

/** One plain-HTTP exchange against `ip:port`. */
function httpAttempt(ip: string, port: number, timeoutMs: number): Promise<AttemptResult> {
  return new Promise((resolve) => {
    const started = performance.now();
    const req = http.request({ host: ip, port, path: "/", method: "GET", timeout: timeoutMs }, () => {
      req.destroy();
      resolve({ ok: true, ms: performance.now() - started, error: undefined });
    });
    req.on("error", (err: Error & { code?: string }) => {
      resolve({ ok: false, ms: performance.now() - started, error: `${err.code ?? err.message}` });
    });
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, ms: performance.now() - started, error: "timeout" });
    });
    req.end();
  });
}

export async function probePayload(
  ip: string,
  port: number,
  iters: number,
  timeoutMs: number,
  proto: "tls" | "http",
): Promise<PayloadResult> {
  const attempt = proto === "tls" ? tlsAttempt : httpAttempt;
  const results: AttemptResult[] = [];
  for (let i = 0; i < iters; i++) {
    results.push(await attempt(ip, port, timeoutMs));
  }
  const okMs = results
    .filter((r) => r.ok)
    .map((r) => r.ms)
    .sort((a, b) => a - b);
  const errors: string[] = [];
  for (const r of results) {
    if (r.error !== undefined && !errors.includes(r.error)) errors.push(r.error);
  }
  return {
    port,
    ok: okMs.length,
    total: results.length,
    ...(okMs.length > 0 ? { medianMs: okMs[Math.floor(okMs.length / 2)] } : {}),
    errors,
  };
}

function stateOf(result: CheckResult, port: number): PortState | undefined {
  return result.ports.find((p) => p.port === port)?.state;
}

export async function checkIp(opts: CheckOptions): Promise<CheckResult> {
  const ports = (await Promise.all(opts.ports.map((p) => probePort(opts.ip, p, opts.timeoutMs)))).sort(
    (a, b) => a.port - b.port,
  );
  const result: CheckResult = { ip: opts.ip, ports, payloads: [], verdict: "clean", notes: [] };

  // Payload-layer checks on the ports that matter for the stack.
  if (stateOf(result, 443) === "open") {
    result.payloads.push(await probePayload(opts.ip, 443, opts.iters, opts.timeoutMs, "tls"));
  }
  if (stateOf(result, 80) === "open") {
    result.payloads.push(await probePayload(opts.ip, 80, opts.iters, opts.timeoutMs, "http"));
  }

  // Verdict.
  const ssh = stateOf(result, 22);
  const tls443 = result.payloads.find((p) => p.port === 443);
  if (ssh === "filtered") {
    result.verdict = "blocked";
    result.notes.push(
      ":22 filtered — SSH management from this network is dead (tunnel route or another ssh port required). " +
        "On a looking-glass/test IP this is often the box's own default-deny firewall (RKN filters :443, not :80/:443) — re-check the actual VPS IP before ruling the host out.",
    );
  }
  if (stateOf(result, 443) === "filtered") {
    result.verdict = "blocked";
    result.notes.push(
      ":443 filtered — listed-IP signature; VLESS/REALITY on 443 will not work from this network.",
    );
  }
  if (tls443 !== undefined && tls443.ok < tls443.total) {
    result.verdict = tls443.ok === 0 ? "blocked" : "suspect";
    result.notes.push(
      `TLS payload on :443 degraded (${tls443.ok}/${tls443.total} completed — ${tls443.errors.join(", ") || "unknown"}) — handshake can be alive while payload is dropped.`,
    );
  }
  if (result.verdict === "clean") {
    const open = ports.filter((p) => p.state === "open").map((p) => `:${p.port}`);
    const closed = ports.filter((p) => p.state === "closed").length;
    if (open.length > 0) {
      result.notes.push(
        `path clean — open: ${open.join(", ")} (closed ports returning RST are expected on an unprovisioned box and are good news).`,
      );
    } else if (closed > 0) {
      result.notes.push(
        "path clean — all probed ports closed (RST, path alive): expected on an unprovisioned box.",
      );
    } else {
      result.notes.push("path clean but nothing is listening anywhere — verify the box is actually up.");
    }
  }
  return result;
}

/** Human-readable report (plain text, TUI-free by design). */
export function formatCheck(result: CheckResult): string {
  const lines: string[] = [`viper check ${result.ip}`, ""];
  for (const p of result.ports) {
    const timing =
      p.state === "open"
        ? `open (${Math.round(p.ms ?? 0)} ms)`
        : p.state === "closed"
          ? `closed (${Math.round(p.failMs ?? 0)} ms — RST, path alive)`
          : `filtered (no answer in ${Math.round(p.failMs ?? 0)} ms)`;
    lines.push(`  :${String(p.port).padEnd(5)} ${timing}`);
  }
  for (const p of result.payloads) {
    const med = p.medianMs !== undefined ? `, median ${Math.round(p.medianMs)} ms` : "";
    const errs = p.errors.length > 0 ? `, errors: ${p.errors.join(", ")}` : "";
    lines.push(`  payload :${p.port}  ${p.ok}/${p.total} completed${med}${errs}`);
  }
  lines.push("");
  lines.push(`verdict: ${result.verdict}`);
  for (const n of result.notes) lines.push(`  - ${n}`);
  return lines.join("\n");
}
