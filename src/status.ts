/**
 * M7 `status` — live data over SSH (contract D7).
 *
 * The collector is a pure-ish, unit-testable function:
 * `collectStatus(conn, config, state, opts) → StatusData`. It runs only
 * short, single-purpose commands over the persistent connection (the
 * plan's remote-execution rules) — the ink component renders `StatusData`
 * only, and the non-TTY path prints a plain-text snapshot and exits
 * (that is also the test path).
 *
 * Per-client traffic: the rendered `config.json` runs the Xray stats API
 * on loopback (`api.listen`, 127.0.0.1:10085). The API is gRPC — queried
 * with the pinned binary's own client:
 *   `xray api statsquery --server=127.0.0.1:<port>`
 * (refs/Xray-docs-next/docs/en/document/level-2/traffic_stats.md —
 * "xray api statsquery --server=127.0.0.1:10085 # 查看所有流量"; verified
 * against the pinned v26.3.27 binary during the M7 live check).
 *
 * Stat name matching: Xray names per-user stats
 * `user>>><email>>>traffic>>>uplink|downlink` (docs example:
 * `user>>>love@example.com>>>traffic>>>downlink`). The rendered
 * `config.json` sets each user's `email` to the client NAME
 * (`render/xray.ts`), so the stat names are matched against client
 * names — NOT the UUIDs (the contract's `user<<<uuid>>>...` example is
 * the older v2ray naming; the pinned source is the arbiter).
 */
import { renderXray } from "./render/xray.js";
import { parseXrayVersion, XRAY_BIN } from "./steps/xray-install.js";
import { xrayHandshakeProbeStep } from "./steps/xray-verify.js";
import type { SshConn } from "./ssh.js";
import type { ServerConfig } from "./config.js";
import type { State } from "./state.js";
import type { PollOptions } from "./steps/common.js";
import type { StepCtx } from "./steps/runner.js";

export interface ClientStatus {
  name: string;
  uuid: string;
  /** Bytes uploaded by this client since boot, or null when absent. */
  uplink: number | null;
  /** Bytes downloaded by this client since boot, or null when absent. */
  downlink: number | null;
}

export interface HandshakeCheck {
  /** null = not (yet) run. */
  ok: boolean | null;
  detail: string;
}

export interface CertInfo {
  subject: string;
  issuer: string;
  /** `notAfter` as reported by openssl. */
  validTo: string;
}

export interface StatusData {
  name: string;
  ip: string;
  domain: string;
  xrayVersion: string;
  unitActive: boolean;
  /** `systemctl show xray -p ActiveEnterTimestamp --value`. */
  unitUptime: string;
  hostUptime: string;
  cpu: string;
  ram: string;
  disk: string;
  clients: ClientStatus[];
  /** M5 probe logic, collectable (run on load + `r`, not every refresh). */
  handshake: HandshakeCheck;
  /** Borrowed LE cert (one-time on load is fine). */
  cert: CertInfo | null;
  subPath: string;
  subMtime: string;
  fetchedAt: number;
}

export interface CollectStatusOptions {
  /**
   * Run the expensive checks (REALITY handshake probe, cert probe).
   * Default false: the 5 s refresh only re-collects the cheap metrics,
   * and the check results are carried over from `prev`.
   */
  runChecks?: boolean;
  /** Previous snapshot — check results are carried from it when `runChecks` is false. */
  prev?: StatusData;
  /** Polling knobs for the handshake probe (tests only). */
  poll?: PollOptions;
}

/** Stat names for a client's per-user traffic (see file header). */
export function userStatName(email: string, direction: "uplink" | "downlink"): string {
  return `user>>>${email}>>>traffic>>>${direction}`;
}

/** The stats API listen address from the rendered config.json. */
export function statsApiFromRendered(config: ServerConfig, state: State): string {
  const rendered = JSON.parse(renderXray(config, state)) as {
    api?: { listen?: string };
  };
  const listen = rendered.api?.listen;
  if (typeof listen !== "string" || listen.length === 0) {
    throw new Error("status: rendered config.json has no api.listen — cannot query stats");
  }
  return listen;
}

function fmtBytes(bytes: number): string {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const u = units[unit] as string;
  return `${value >= 100 || value === Math.floor(value) ? Math.round(value) : value.toFixed(1)} ${u}`;
}

function parseTopCpu(output: string): string | undefined {
  // top -bn1: "Cpu(s):  2.1 us,  1.0 sy,  0.0 ni, 96.8 id, ..."
  // (some top versions print "%Cpu(s)" — match both)
  const line = output.split("\n").find((l) => /%?Cpu\(s\):/.test(l));
  if (line === undefined) return undefined;
  const m = line.match(/([\d.]+)\s+id/);
  if (m === null) return undefined;
  const idle = Number(m[1]);
  if (!Number.isFinite(idle)) return undefined;
  return `${Math.max(0, 100 - idle).toFixed(1)}% used`;
}

function parseFreeRam(output: string): string | undefined {
  // free -m: "Mem:   7828   1234   3456 ..."
  const line = output.split("\n").find((l) => l.startsWith("Mem:"));
  if (line === undefined) return undefined;
  const fields = line.trim().split(/\s+/);
  const total = Number(fields[1]);
  const used = Number(fields[2]);
  if (!Number.isFinite(total) || !Number.isFinite(used)) return undefined;
  return `${used} MB / ${total} MB`;
}

function parseDfRoot(output: string): string | undefined {
  // df -m /: "Filesystem 1M-blocks Used Available Use% Mounted on\n/dev/vda1 40900 5120 ..."
  const lines = output.trim().split("\n");
  const last = lines[lines.length - 1] ?? "";
  const fields = last.split(/\s+/);
  const total = Number(fields[1]);
  const used = Number(fields[2]);
  if (!Number.isFinite(total) || !Number.isFinite(used)) return undefined;
  return `${used} MB / ${total} MB`;
}

interface RawStat {
  name: string;
  value: string;
}

/**
 * Collect one status snapshot. Every command is short and read-only
 * except the handshake probe (which cleans up after itself, as in M5).
 */
export async function collectStatus(
  conn: SshConn,
  config: ServerConfig,
  state: State,
  opts: CollectStatusOptions = {},
): Promise<StatusData> {
  const runChecks = opts.runChecks === true;
  const subPath = `/${state.subHash}/sub.txt`;

  const [version, unit, unitEnter, hostUptime, top, free, df, stats, subMtime] =
    await Promise.all([
      conn.run(`${XRAY_BIN} version`, { timeoutMs: 15_000 }).catch(() => undefined),
      conn.run("systemctl is-active xray", { timeoutMs: 15_000 }).catch(() => undefined),
      conn.run("systemctl show xray -p ActiveEnterTimestamp --value", {
        timeoutMs: 15_000,
      }).catch(() => undefined),
      conn.run("uptime -p", { timeoutMs: 15_000 }).catch(() => undefined),
      conn.run("LC_ALL=C top -bn1", { timeoutMs: 20_000 }).catch(() => undefined),
      conn.run("free -m", { timeoutMs: 15_000 }).catch(() => undefined),
      conn.run("df -m /", { timeoutMs: 15_000 }).catch(() => undefined),
      (async () => {
        // statsApiFromRendered throws synchronously when the rendered
        // config has no api.listen — keep it inside the promise so it
        // degrades to undefined like every other command instead of
        // rejecting the whole snapshot.
        const api = statsApiFromRendered(config, state);
        return conn.run(`${XRAY_BIN} api statsquery --server=${api}`, { timeoutMs: 30_000 });
      })().catch(() => undefined),
      conn
        .run(`stat -c %y /var/www/viper/${config.name}/sub.txt 2>/dev/null`, {
          timeoutMs: 15_000,
        })
        .catch(() => undefined),
    ]);

  let statValues: Map<string, number> = new Map();
  if (stats !== undefined && stats.code === 0) {
    try {
      const parsed = JSON.parse(stats.stdout) as { stat?: RawStat[] };
      for (const s of parsed.stat ?? []) {
        const value = Number(s.value);
        if (Number.isFinite(value)) statValues.set(s.name, value);
      }
    } catch {
      statValues = new Map();
    }
  }

  const clients: ClientStatus[] = config.clients.map((c) => {
    // The rendered config sets each user's email to the client name.
    const uplink = statValues.get(userStatName(c.name, "uplink")) ?? null;
    const downlink = statValues.get(userStatName(c.name, "downlink")) ?? null;
    const st = state.clients.find((s) => s.name === c.name);
    return { name: c.name, uuid: st?.uuid ?? "", uplink, downlink };
  });

  let handshake: HandshakeCheck = { ok: null, detail: "not run yet" };
  let cert: CertInfo | null = null;
  if (runChecks) {
    const ctx: StepCtx = {
      name: config.name,
      ip: config.ip,
      config,
      state,
      artifacts: {},
    };
    const probe = xrayHandshakeProbeStep(opts.poll ?? {});
    const r = await probe.run(conn, ctx);
    handshake = {
      ok: r.status !== "failed" ? true : false,
      detail: r.detail ?? r.status,
    };
    const certRes = await conn.run(
      `echo | openssl s_client -connect ${config.ip}:443 -servername ${config.domain} ` +
        `2>/dev/null | openssl x509 -noout -subject -issuer -enddate`,
      { timeoutMs: 60_000 },
    ).catch(() => undefined);
    if (certRes !== undefined && certRes.code === 0) {
      const get = (label: string) =>
        certRes.stdout
          .split("\n")
          .find((l) => l.startsWith(label))
          ?.slice(label.length)
          .trim() ?? "";
      cert = {
        subject: get("subject="),
        issuer: get("issuer="),
        validTo: get("notAfter="),
      };
    }
  } else if (opts.prev !== undefined) {
    handshake = opts.prev.handshake;
    cert = opts.prev.cert;
  }

  return {
    name: config.name,
    ip: config.ip,
    domain: config.domain,
    xrayVersion:
      (version !== undefined && version.code === 0
        ? parseXrayVersion(version.stdout)
        : undefined) ?? "unavailable",
    unitActive:
      unit !== undefined && unit.code === 0 && unit.stdout.trim() === "active",
    unitUptime: unitEnter?.stdout.trim() ?? "",
    hostUptime: hostUptime?.stdout.trim() ?? "",
    cpu: (top !== undefined ? parseTopCpu(top.stdout) : undefined) ?? "n/a",
    ram: (free !== undefined ? parseFreeRam(free.stdout) : undefined) ?? "n/a",
    disk: (df !== undefined ? parseDfRoot(df.stdout) : undefined) ?? "n/a",
    clients,
    handshake,
    cert,
    subPath,
    subMtime: subMtime?.stdout.trim() ?? "n/a",
    fetchedAt: Date.now(),
  };
}

/** Human-readable byte counter for the panels. */
export function formatBytes(bytes: number | null): string {
  return bytes === null ? "n/a" : fmtBytes(bytes);
}

/**
 * Plain-text snapshot (non-TTY path + test path): one block per panel,
 * stable layout so it is easy to eyeball in a terminal or a CI log.
 */
export function renderStatusSnapshot(d: StatusData): string {
  const lines: string[] = [];
  const section = (title: string, body: string[]) => {
    lines.push(title);
    for (const b of body) lines.push(`  ${b}`);
    lines.push("");
  };

  section("Server", [
    `name:    ${d.name}`,
    `ip:      ${d.ip}`,
    `domain:  ${d.domain}`,
    `xray:    ${d.xrayVersion}`,
    `unit:    ${d.unitActive ? "active" : "INACTIVE"}${d.unitUptime !== "" ? ` (since ${d.unitUptime})` : ""}`,
  ]);

  section("Host", [
    `uptime:  ${d.hostUptime || "n/a"}`,
    `cpu:     ${d.cpu}`,
    `ram:     ${d.ram}`,
    `disk /:  ${d.disk}`,
  ]);

  section(
    "Clients",
    d.clients.map(
      (c) =>
        `${c.name} (${c.uuid}): up ${formatBytes(c.uplink)}, down ${formatBytes(c.downlink)}`,
    ),
  );

  const h = d.handshake;
  section("Checks", [
    `handshake: ${h.ok === null ? "not run yet (r to run)" : h.ok ? "OK" : "FAILED"} — ${h.detail}`,
    d.cert === null
      ? "cert:      not run yet (r to run)"
      : `cert:      ${d.cert.subject}\n            issuer ${d.cert.issuer}, valid to ${d.cert.validTo}`,
  ]);

  section("Sub", [
    `path:    ${d.subPath}`,
    `mtime:   ${d.subMtime}`,
  ]);

  lines.push(`updated: ${new Date(d.fetchedAt).toISOString()}`);
  lines.push("keys: q quit, r re-run checks");
  return lines.join("\n") + "\n";
}