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

/**
 * Warning signal state:
 *  - `ok` — the probe ran and the signal is healthy
 *  - `warn` — the probe ran and the signal needs attention
 *  - `unknown` — the probe degraded (command failed) or has not been run
 *    yet (checks-path signals before the first checks run)
 */
export type WarningState = "ok" | "warn" | "unknown";

/**
 * Error-log signal (xray / nginx). "Recent" = the last `ERROR_LOG_TAIL_LINES`
 * lines of the file, shown together with the total line count. No time-window
 * parsing of log timestamps: at the default `warning` log level every line in
 * xray's error.log (and every line in nginx's error.log) is a real problem,
 * so any non-empty tail is a warning.
 */
export interface LogWarning {
  state: WarningState;
  /** Total line count of the log, null when unknown. */
  total: number | null;
  /** Last ≤5 lines; empty when ok/unknown. */
  recent: string[];
}

/** `systemctl --failed --no-legend` — any service death. */
export interface FailedUnitsWarning {
  state: WarningState;
  /** Trimmed `--no-legend` lines; empty when ok/unknown. */
  units: string[];
}

/** fail2ban sshd jail (checks path; carried over from `prev` on refresh). */
export interface Fail2banWarning {
  state: WarningState;
  /** Banned IP count for the jail ("Ban total"), null when unknown. */
  banned: number | null;
  /** Total failed attempts ("Total failed"), null when unknown/absent. */
  totalFailed: number | null;
}

/**
 * Cert expiry countdown, derived from `cert.validTo` (checks path — the
 * cert probe already lives there, and the carry-over makes `cert` available
 * on refreshes too). Warns below `CERT_WARN_DAYS` (acme.sh auto-renews; this
 * is visibility, not a repair hook).
 */
export interface CertWarning {
  state: WarningState;
  /** Whole days until expiry (0 when already past), null when unknown. */
  daysLeft: number | null;
}

/** Root filesystem pressure, derived from the `df -m /` already collected. */
export interface DiskWarning {
  state: WarningState;
  /** Use% of /, null when unknown. Warns at ≥ `DISK_WARN_PERCENT`. */
  percent: number | null;
}

export interface Warnings {
  xrayLog: LogWarning;
  nginxLog: LogWarning;
  failedUnits: FailedUnitsWarning;
  fail2ban: Fail2banWarning;
  cert: CertWarning;
  disk: DiskWarning;
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
  /** M8: actual IPv6 posture ("disabled (v4-only)" / "enabled (global v6 on <if>)" / "unknown"). */
  ipv6: string;
  /** M5 probe logic, collectable (run on load + `r`, not every refresh). */
  handshake: HandshakeCheck;
  /** Borrowed LE cert (one-time on load is fine). */
  cert: CertInfo | null;
  /**
   * Warnings panel: six signals the user would otherwise have to go looking
   * for (error logs, dead units, fail2ban, cert expiry, disk pressure).
   * Refresh-path signals (xrayLog/nginxLog/failedUnits/disk) are re-probed
   * every 5 s; checks-path signals (fail2ban/cert) are carried over from
   * `prev` like `handshake`/`cert`. Each probe degrades to `unknown`
   * independently — one failure never rejects the snapshot.
   */
  warnings: Warnings;
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

/**
 * M8: render the `ipv6:` status line from the two read-only probes
 * (disable_ipv6 sysctls + global v6 address presence). Makes a
 * flipped-but-not-yet-redeployed `allowIPv6` knob visible instead of
 * silently inert (D5). Command failure degrades to "unknown".
 */
export function renderIpv6Status(sysctlOut: string | undefined, v6AddrOut: string | undefined): string {
  if (sysctlOut === undefined || v6AddrOut === undefined) return "unknown";
  const [all, def] = sysctlOut.trim().split(/\s+/);
  if (all === "1" && def === "1") return "disabled (v4-only)";
  const m = v6AddrOut.trim().match(/^\d+:\s*(\S+):/);
  return m !== null ? `enabled (global v6 on ${m[1]})` : "enabled (no global v6 address)";
}

/** "Recent" for the error-log signals: the last N lines (documented above). */
export const ERROR_LOG_TAIL_LINES = 5;
/** Warn when the LE cert expires within this many days (acme.sh renews at ~30). */
export const CERT_WARN_DAYS = 14;
/** Warn when the root filesystem is at or above this Use%. */
export const DISK_WARN_PERCENT = 80;

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

function parseDfRoot(output: string): { text: string; percent: number } | undefined {
  // df -m /: "Filesystem 1M-blocks Used Available Use% Mounted on\n/dev/vda1 40900 5120 ..."
  const lines = output.trim().split("\n");
  const last = lines[lines.length - 1] ?? "";
  const fields = last.split(/\s+/);
  const total = Number(fields[1]);
  const used = Number(fields[2]);
  if (!Number.isFinite(total) || !Number.isFinite(used) || total <= 0) return undefined;
  return { text: `${used} MB / ${total} MB`, percent: Math.round((used / total) * 100) };
}

/**
 * Whole days until an openssl `notAfter` ("Sep 4 12:00:00 2027 GMT").
 * Node's `Date.parse` handles this format (verified against Node ≥24,
 * including the two-space day variant `Mar  1 ...`); unparseable input
 * degrades to null. 0 when already past (still a warning: state `warn`).
 */
export function certDaysLeft(validTo: string): number | null {
  const ms = Date.parse(validTo);
  if (!Number.isFinite(ms)) return null;
  return Math.max(0, Math.ceil((ms - Date.now()) / 86_400_000));
}

/**
 * Error-log signal from the `wc -l <` and `tail -n 5` probes. Any line in
 * these logs is a real problem (see `LogWarning`); a missing/unreadable file
 * degrades to `unknown` (we cannot see the window, so we don't claim it is
 * clean).
 */
function logWarning(
  countOut: { code: number; stdout: string } | undefined,
  tailOut: { code: number; stdout: string } | undefined,
): LogWarning {
  if (tailOut === undefined || tailOut.code !== 0) {
    return { state: "unknown", total: null, recent: [] };
  }
  const recent = tailOut.stdout.split("\n").filter((l) => l !== "");
  const total = countOut !== undefined && countOut.code === 0 ? Number(countOut.stdout.trim()) : null;
  return {
    state: recent.length > 0 ? "warn" : "ok",
    total: Number.isFinite(total as number) ? (total as number) : null,
    recent: recent.slice(-ERROR_LOG_TAIL_LINES),
  };
}

/** `systemctl --failed --no-legend` → any service death. */
function failedUnitsWarning(res: { code: number; stdout: string } | undefined): FailedUnitsWarning {
  if (res === undefined || res.code !== 0) return { state: "unknown", units: [] };
  const units = res.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l !== "");
  return { state: units.length > 0 ? "warn" : "ok", units };
}

/**
 * `fail2ban-client status sshd` → the jail's ban count. The per-jail status
 * reports the live ban count as "Ban total: N" (the "Currently banned: N"
 * line only exists in the GLOBAL `fail2ban-client status`); "Total failed"
 * gives the cumulative attempt count when present. Degrades to `unknown`
 * when fail2ban is not installed/running (non-zero exit).
 */
function fail2banWarning(res: { code: number; stdout: string } | undefined): Fail2banWarning {
  if (res === undefined || res.code !== 0) return { state: "unknown", banned: null, totalFailed: null };
  const num = (label: string): number | null => {
    const m = res.stdout.match(new RegExp(`${label}: (\\d+)`));
    return m !== null && m[1] !== undefined ? Number(m[1]) : null;
  };
  const banned = num("Ban total");
  if (banned === null) return { state: "unknown", banned: null, totalFailed: num("Total failed") };
  return { state: banned > 0 ? "warn" : "ok", banned, totalFailed: num("Total failed") };
}

function certWarning(cert: CertInfo | null): CertWarning {
  if (cert === null || cert.validTo === "") return { state: "unknown", daysLeft: null };
  const daysLeft = certDaysLeft(cert.validTo);
  if (daysLeft === null) return { state: "unknown", daysLeft: null };
  return { state: daysLeft < CERT_WARN_DAYS ? "warn" : "ok", daysLeft };
}

function diskWarning(df: { text: string; percent: number } | undefined): DiskWarning {
  if (df === undefined) return { state: "unknown", percent: null };
  return { state: df.percent >= DISK_WARN_PERCENT ? "warn" : "ok", percent: df.percent };
}

export interface WarningLine {
  /** Panel label (xray, nginx, units, fail2ban, cert, disk). */
  label: string;
  state: WarningState;
  /** Compact one-line detail. */
  text: string;
  /** Extra detail lines (error-log tail / unit list) — only when non-ok. */
  extra: string[];
}

/**
 * Shared presentation for the Warnings section — one compact line per
 * signal so every window is visibly watched; detail only when non-ok.
 * Used by BOTH the ink TUI and the plain snapshot so the two always match.
 */
export function warningLines(w: Warnings): WarningLine[] {
  const log = (label: string, lw: LogWarning): WarningLine => {
    if (lw.state === "ok") return { label, state: "ok", text: "ok", extra: [] };
    if (lw.state === "warn")
      return {
        label,
        state: "warn",
        text:
          lw.total !== null
            ? `${lw.total} error${lw.total === 1 ? "" : "s"} (last ${lw.recent.length})`
            : `${lw.recent.length} recent errors`,
        extra: lw.recent,
      };
    return { label, state: "unknown", text: "unknown", extra: [] };
  };
  const units = w.failedUnits;
  const unitsLine: WarningLine =
    units.state === "ok"
      ? { label: "units", state: "ok", text: "ok", extra: [] }
      : units.state === "warn"
        ? { label: "units", state: "warn", text: `${units.units.length} failed`, extra: units.units }
        : { label: "units", state: "unknown", text: "unknown", extra: [] };
  const f2b = w.fail2ban;
  const f2bLine: WarningLine =
    f2b.state === "ok"
      ? { label: "fail2ban", state: "ok", text: "0 banned", extra: [] }
      : f2b.state === "warn"
        ? {
            label: "fail2ban",
            state: "warn",
            text: `${f2b.banned} banned${f2b.totalFailed !== null ? ` (total failed: ${f2b.totalFailed})` : ""}`,
            extra: [],
          }
        : { label: "fail2ban", state: "unknown", text: "unknown (not run yet)", extra: [] };
  const c = w.cert;
  const certLine: WarningLine =
    c.state === "unknown"
      ? { label: "cert", state: "unknown", text: "unknown (not run yet)", extra: [] }
      : {
          label: "cert",
          state: c.state,
          text: `${c.daysLeft} day${c.daysLeft === 1 ? "" : "s"} left`,
          extra: [],
        };
  const d = w.disk;
  const diskLine: WarningLine =
    d.state === "unknown"
      ? { label: "disk", state: "unknown", text: "unknown", extra: [] }
      : { label: "disk", state: d.state, text: `${d.percent}% used`, extra: [] };
  return [log("xray", w.xrayLog), log("nginx", w.nginxLog), unitsLine, f2bLine, certLine, diskLine];
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

  const [
    version,
    unit,
    unitEnter,
    hostUptime,
    top,
    free,
    df,
    stats,
    subMtime,
    ipv6Sysctl,
    ipv6Addr,
    xrayLogCount,
    xrayLogTail,
    nginxLogCount,
    nginxLogTail,
    failedUnits,
  ] = await Promise.all([
    conn.run(`${XRAY_BIN} version`, { timeoutMs: 15_000 }).catch(() => undefined),
    conn.run("systemctl is-active xray", { timeoutMs: 15_000 }).catch(() => undefined),
    conn
      .run("systemctl show xray -p ActiveEnterTimestamp --value", {
        timeoutMs: 15_000,
      })
      .catch(() => undefined),
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
    conn
      .run("sysctl -n net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6", {
        timeoutMs: 15_000,
      })
      .catch(() => undefined),
    conn.run("ip -6 addr show scope global", { timeoutMs: 15_000 }).catch(() => undefined),
    // Warnings (refresh path): two cheap probes per error log + failed
    // units. Disk pressure is derived from `df` above; fail2ban and the
    // cert run on the checks path (see below).
    conn.run(`wc -l < /var/log/xray/error.log 2>/dev/null`, { timeoutMs: 15_000 }).catch(() => undefined),
    conn
      .run(`tail -n ${ERROR_LOG_TAIL_LINES} /var/log/xray/error.log 2>/dev/null`, { timeoutMs: 15_000 })
      .catch(() => undefined),
    conn.run(`wc -l < /var/log/nginx/error.log 2>/dev/null`, { timeoutMs: 15_000 }).catch(() => undefined),
    conn
      .run(`tail -n ${ERROR_LOG_TAIL_LINES} /var/log/nginx/error.log 2>/dev/null`, { timeoutMs: 15_000 })
      .catch(() => undefined),
    conn.run("systemctl --failed --no-legend", { timeoutMs: 15_000 }).catch(() => undefined),
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
  // fail2ban is a client call into the fail2ban server (IPC, slower than a
  // file tail) and changes rarely — checks path, carried from `prev`, the
  // same way as `handshake`/`cert`.
  let fail2ban: Fail2banWarning = { state: "unknown", banned: null, totalFailed: null };
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
      ok: r.status !== "failed",
      detail: r.detail ?? r.status,
    };
    const certRes = await conn
      .run(
        `echo | openssl s_client -connect ${config.ip}:443 -servername ${config.domain} ` +
          `2>/dev/null | openssl x509 -noout -subject -issuer -enddate`,
        { timeoutMs: 60_000 },
      )
      .catch(() => undefined);
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
    const f2bRes = await conn
      .run("fail2ban-client status sshd", { timeoutMs: 15_000 })
      .catch(() => undefined);
    fail2ban = fail2banWarning(f2bRes);
  } else if (opts.prev !== undefined) {
    handshake = opts.prev.handshake;
    cert = opts.prev.cert;
    fail2ban = opts.prev.warnings.fail2ban;
  }

  const diskParsed = df !== undefined ? parseDfRoot(df.stdout) : undefined;
  return {
    name: config.name,
    ip: config.ip,
    domain: config.domain,
    xrayVersion:
      (version !== undefined && version.code === 0 ? parseXrayVersion(version.stdout) : undefined) ??
      "unavailable",
    unitActive: unit !== undefined && unit.code === 0 && unit.stdout.trim() === "active",
    unitUptime: unitEnter?.stdout.trim() ?? "",
    hostUptime: hostUptime?.stdout.trim() ?? "",
    cpu: (top !== undefined ? parseTopCpu(top.stdout) : undefined) ?? "n/a",
    ram: (free !== undefined ? parseFreeRam(free.stdout) : undefined) ?? "n/a",
    disk: diskParsed?.text ?? "n/a",
    clients,
    ipv6: renderIpv6Status(
      ipv6Sysctl !== undefined && ipv6Sysctl.code === 0 ? ipv6Sysctl.stdout : undefined,
      ipv6Addr !== undefined && ipv6Addr.code === 0 ? ipv6Addr.stdout : undefined,
    ),
    handshake,
    cert,
    warnings: {
      xrayLog: logWarning(xrayLogCount, xrayLogTail),
      nginxLog: logWarning(nginxLogCount, nginxLogTail),
      failedUnits: failedUnitsWarning(failedUnits),
      fail2ban,
      cert: certWarning(cert),
      disk: diskWarning(diskParsed),
    },
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
      (c) => `${c.name} (${c.uuid}): up ${formatBytes(c.uplink)}, down ${formatBytes(c.downlink)}`,
    ),
  );

  // Warnings: one compact line per signal (via the shared warningLines so
  // the TUI and the snapshot always match); detail lines only when non-ok.
  const warningRows: string[] = [];
  for (const w of warningLines(d.warnings)) {
    warningRows.push(`${(w.label + ":").padEnd(11)}${w.text}`);
    for (const e of w.extra) warningRows.push(`           ${e}`);
  }
  section("Warnings", warningRows);

  const h = d.handshake;
  section("Checks", [
    `handshake: ${h.ok === null ? "not run yet (r to run)" : h.ok ? "OK" : "FAILED"} — ${h.detail}`,
    `ipv6:      ${d.ipv6}`,
    d.cert === null
      ? "cert:      not run yet (r to run)"
      : `cert:      ${d.cert.subject}\n            issuer ${d.cert.issuer}, valid to ${d.cert.validTo}`,
  ]);

  section("Sub", [`path:    ${d.subPath}`, `mtime:   ${d.subMtime}`]);

  lines.push(`updated: ${new Date(d.fetchedAt).toISOString()}`);
  lines.push("keys: q quit, r re-run checks");
  return lines.join("\n") + "\n";
}
