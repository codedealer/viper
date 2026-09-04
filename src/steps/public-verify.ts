/**
 * Public-path verification step (M9) — a LOCAL probe that proves the
 * deployment works over the real public path, from the machine running
 * viper. Complements the M5 loopback handshake (which dials 127.0.0.1
 * on the server and proves the *server* works): this step proves the
 * *path* works — DNS → TCP → REALITY handshake → VLESS auth → egress.
 *
 * The first manual E2E exposed exactly this gap (.scratch/reports/viper/
 * e2e-diagnosis.md): the server was fully healthy, but the operator's
 * ISP had the server IP on a per-IP DPI blocklist — TCP connected, but
 * every TLS handshake was silently killed. Nothing server-side could
 * see that; this step catches it at deploy/update time, before any
 * client is pointed at the server.
 *
 * The step ignores `conn` and executes locally (decision 1: the probe
 * must run where the operator's network is). Linux x64/arm64 hosts
 * only; other platforms fail with a clear message.
 *
 * Flow (decision 4 — each stage has its own failure class):
 *  1. DNS: resolve4(config.domain) must include config.ip (the --ip
 *     override already flows into ctx.config).
 *  2. TCP: connect config.ip:config.port, 8 s timeout.
 *  3. Per client (same contract as the loopback probe): render a probe
 *     client dialing config.domain (not 127.0.0.1 — exactly what a real
 *     client does), validate with `xray -test`, run the pinned
 *     digest-verified xray binary in a local sandbox, poll the SOCKS
 *     port, curl gstatic through it and require HTTP 204. First failure
 *     stops the loop; each probe gets its own sandbox cycle (cleanup
 *     always, finally), and orphans are reaped before the first launch.
 *
 * Binary (decision 7): pinned, digest-verified, cached in
 * ~/.cache/viper/xray/<version>-<arch>/{xray,geoip.dat,geosite.dat,
 * SHA256SUMS}; the ZIP's SHA-2-256 is verified before anything runs and
 * a cache hit is re-verified against the release .dgst (mismatch or
 * missing → re-download). No unverified binary ever runs. Requires the
 * system `unzip` (viper host dependency — fail clearly, no auto-install).
 *
 * Opt-out (decision 8): `--skip-public-verify` — the operator may
 * legitimately deploy from a different network than the end user's; the
 * step is reported as `skipped`. Otherwise a failure fails the pipeline
 * (the server is left running — the detail says so).
 */
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, mkdtemp, mkdir, open, readFile, rm, writeFile } from "node:fs/promises";
import { connect } from "node:net";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { defaultDnsResolver, errDetail, poll, type DnsResolver, type PollOptions } from "./common.js";
import { PROBE_SOCKS_PORT, publicProbeAddress, renderXrayProbeClient } from "../render/xray-probe.js";
import type { Step, StepCtx, StepResult } from "./runner.js";

/**
 * The probe client's rendered config was rejected by `xray -test` —
 * a CONFIG error, which must not be mistaken for a path error (the
 * step reports it as a distinct failure class with the xray error).
 */
export class ProbeConfigError extends Error {}

/**
 * Injectable seam for the local probe (tests inject a fake). The real
 * implementation (ChildProcessProbeRunner) manages the local xray process via
 * node:child_process and the cached pinned binary.
 */
export interface LocalProbeRunner {
  /**
   * Ensure the pinned, digest-verified xray binary for this version is
   * available; returns the binary path. Hard-fails (throws) on any
   * verification problem — no unverified binary ever runs.
   */
  ensureBinary(version: string): Promise<string>;
  /**
   * Reap a local orphan probe left by a previously failed run (e.g. a
   * launch that timed out before the pid was captured) so the SOCKS
   * port is free for the first client.
   */
  reapOrphans(sandbox: string): Promise<void>;
  /**
   * Validate + run the probe client for one rendered config (xray
   * -test → launch → poll SOCKS → curl gstatic) and return the egress
   * HTTP code ("000" when there was no response). Throws
   * ProbeConfigError when `xray -test` rejects the config.
   */
  runClient(cfgPath: string, port: number): Promise<string>;
}

/**
 * Parse a release digest (`.dgst`) file into its SHA-2-256 hex.
 * Accepts the Xray release line format `SHA2-256=<hex>  <file>` and
 * plain sha256sum format `<hex>  <file>`. Returns undefined when no
 * line carries a 64-hex digest (malformed). Pure — unit-testable.
 */
export function parseSha256(dgstText: string): string | undefined {
  for (const line of dgstText.split("\n")) {
    const m = line.match(/([0-9a-fA-F]{64})/);
    if (m !== null) return (m[1] as string).toLowerCase();
  }
  return undefined;
}

/** Case-insensitive digest comparison (cache-hit re-verification). */
export function digestMatches(stored: string, expected: string): boolean {
  return stored.trim().toLowerCase() === expected.trim().toLowerCase();
}

/** Default TCP pre-check: a raw connect to ip:port, 8 s timeout. */
export function defaultTcpCheck(ip: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host: ip, port, timeout: 8_000 });
    const done = (ok: boolean): void => {
      sock.destroy();
      resolve(ok);
    };
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

/** True when a TCP connect to host:port succeeds within 1 s. */
function portOpen(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host, port, timeout: 1_000 });
    const done = (ok: boolean): void => {
      sock.destroy();
      resolve(ok);
    };
    sock.once("connect", () => done(true));
    sock.once("timeout", () => done(false));
    sock.once("error", () => done(false));
  });
}

interface LocalCmdResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Local child_process wrapper: resolves {code, stdout, stderr} even on
 *  non-zero exit (like the SshConn CommandResult the other steps use). */
function runLocal(
  cmd: string,
  args: string[],
  opts: { cwd?: string; timeoutMs: number },
): Promise<LocalCmdResult> {
  return new Promise((resolve) => {
    execFile(cmd, args, { cwd: opts.cwd, timeout: opts.timeoutMs }, (err, stdout, stderr) => {
      const code = err !== null && typeof err.code === "number" ? err.code : err !== null ? 1 : 0;
      resolve({ code, stdout, stderr });
    });
  });
}

/** SHA-2-256 of a file, hex. */
async function sha256File(path: string): Promise<string> {
  const hash = createHash("sha256");
  const fd = await open(path, "r");
  try {
    hash.update(await fd.readFile());
  } finally {
    await fd.close();
  }
  return hash.digest("hex");
}

/** Last 30 lines of a log, shortened for step details. */
async function tailLog(path: string): Promise<string> {
  try {
    const lines = (await readFile(path, "utf8")).split("\n");
    return errDetail(lines.slice(-30).join("\n"));
  } catch {
    return "(no log)";
  }
}

/**
 * Real probe runner: pinned Xray (same GitHub release URL scheme as the
 * server-side install step), digest-verified, cached in
 * ~/.cache/viper/xray/<version>-<arch>/; local process management via
 * node:child_process. Linux x64/arm64 hosts only; requires the system
 * `unzip`.
 */
export class ChildProcessProbeRunner implements LocalProbeRunner {
  private binPath: string | undefined;

  constructor(private pollOpts: PollOptions = {}) {}

  private static archName(): string {
    switch (process.arch) {
      case "x64":
        return "64";
      case "arm64":
        return "arm64";
      default:
        throw new Error(`public verify: unsupported architecture "${process.arch}" (need x64 or arm64)`);
    }
  }

  private static zipUrl(version: string, arch: string): string {
    return `https://github.com/XTLS/Xray-core/releases/download/${version}/Xray-linux-${arch}.zip`;
  }

  async ensureBinary(version: string): Promise<string> {
    const arch = ChildProcessProbeRunner.archName();
    const dir = join(homedir(), ".cache", "viper", "xray", `${version}-${arch}`);
    const expected = await this.fetchExpectedDigest(version, arch);
    const bin = join(dir, "xray");

    // A cached binary is reused ONLY if its stored digest still matches
    // the release .dgst (re-verified on cache hit; mismatch or missing →
    // re-download). The version is pinned, so cache staleness is
    // impossible by construction.
    try {
      const stored = parseSha256(await readFile(join(dir, "SHA256SUMS"), "utf8"));
      if (stored !== undefined && digestMatches(stored, expected)) {
        try {
          await access(bin);
          this.binPath = bin;
          return bin;
        } catch {
          // binary missing — fall through to download
        }
      }
    } catch {
      // no cache yet — fall through to download
    }

    await this.install(version, arch, dir, expected);
    this.binPath = bin;
    return bin;
  }

  private async fetchExpectedDigest(version: string, arch: string): Promise<string> {
    const res = await runLocal(
      "curl",
      ["-fsSL", "--max-time", "60", `${ChildProcessProbeRunner.zipUrl(version, arch)}.dgst`],
      {
        timeoutMs: 80_000,
      },
    );
    if (res.code !== 0) {
      throw new Error(
        `digest asset missing or unreachable (${errDetail(res.stderr)}) — refusing to use an unverified binary`,
      );
    }
    const hex = parseSha256(res.stdout);
    if (hex === undefined) {
      throw new Error("could not parse SHA2-256 from the digest file — refusing to use an unverified binary");
    }
    return hex;
  }

  private async install(version: string, arch: string, dir: string, expected: string): Promise<void> {
    const which = await runLocal("which", ["unzip"], { timeoutMs: 10_000 });
    if (which.code !== 0 || which.stdout.trim() === "") {
      throw new Error("unzip not found on the viper host — install it (e.g. apt-get install unzip)");
    }

    const zipName = `Xray-linux-${arch}.zip`;
    const tmp = await mkdtemp(join(tmpdir(), "viper-xray-dl-"));
    try {
      const dl = await runLocal(
        "curl",
        [
          "-fsSL",
          "--max-time",
          "300",
          ChildProcessProbeRunner.zipUrl(version, arch),
          "-o",
          join(tmp, zipName),
        ],
        { timeoutMs: 320_000 },
      );
      if (dl.code !== 0) throw new Error(`xray download failed: ${errDetail(dl.stderr)}`);

      const actual = await sha256File(join(tmp, zipName));
      if (!digestMatches(actual, expected)) {
        throw new Error(
          `SHA2-256 mismatch: expected ${expected}, got ${actual} — refusing to run an unverified binary`,
        );
      }

      // Fresh cache dir: a mismatched or partial cache is replaced,
      // never patched in place.
      await rm(dir, { recursive: true, force: true });
      await mkdir(dir, { recursive: true });
      const unzip = await runLocal("unzip", ["-o", join(tmp, zipName), "-d", dir], { timeoutMs: 120_000 });
      if (unzip.code !== 0) throw new Error(`unzip failed: ${errDetail(unzip.stderr)}`);
      await chmod(join(dir, "xray"), 0o755);
      await writeFile(join(dir, "SHA256SUMS"), `${actual}  ${zipName}\n`, "utf8");
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }

  async reapOrphans(sandbox: string): Promise<void> {
    // The [c] bracket keeps pkill from matching its own wrapping
    // invocation; rc 1 (no match) is fine.
    await runLocal("pkill", ["-f", `xray run -c ${sandbox}/[c]onfig.json`], { timeoutMs: 10_000 });
  }

  async runClient(cfgPath: string, port: number): Promise<string> {
    const bin = this.binPath;
    if (bin === undefined) throw new Error("public probe: ensureBinary was not called");
    // Xray expects the geo dat files next to its working directory.
    const cwd = dirname(bin);

    // Validate the probe client config before running it: a config
    // error must not be mistaken for a path failure.
    const test = await runLocal(bin, ["-test", "-c", cfgPath], { cwd, timeoutMs: 60_000 });
    if (test.code !== 0) {
      // xray logs config errors to stdout (not stderr) — include both.
      throw new ProbeConfigError(
        errDetail([test.stdout.trim(), test.stderr.trim()].filter(Boolean).join(" | ")),
      );
    }

    const logPath = join(dirname(cfgPath), "xray.log");
    const logFd = await open(logPath, "w");
    const child = spawn(bin, ["run", "-c", cfgPath], { cwd, stdio: ["ignore", logFd.fd, logFd.fd] });
    try {
      const up = await poll(async () => portOpen("127.0.0.1", port), {
        attempts: 10,
        intervalMs: 500,
        ...this.pollOpts,
      });
      if (!up) {
        throw new Error(`public probe xray did not open SOCKS port ${port} — log: ${await tailLog(logPath)}`);
      }
      const curl = await runLocal(
        "curl",
        [
          "--socks5-hostname",
          `127.0.0.1:${port}`,
          "-s",
          "-o",
          "/dev/null",
          "-w",
          "%{http_code}",
          "--max-time",
          "20",
          "https://www.gstatic.com/generate_204",
        ],
        { timeoutMs: 30_000 },
      );
      return curl.stdout.trim() || "000";
    } finally {
      child.kill();
      await new Promise<void>((resolve) => {
        const t = setTimeout(() => resolve(), 5_000);
        child.once("exit", () => {
          clearTimeout(t);
          resolve();
        });
      });
      await logFd.close();
    }
  }
}

/**
 * Options for the public verify step: the M5 polling knobs, the M9
 * opt-out, and the injectable seams (tests pass fakes; the pipeline
 * passes its DNS seam and poll options).
 */
export interface PublicVerifyOptions {
  poll?: PollOptions;
  /** --skip-public-verify → reported as skipped, zero side effects. */
  skip?: boolean;
  /** DNS seam (default: node:dns via common.defaultDnsResolver). */
  dnsResolver?: DnsResolver;
  /** TCP pre-check seam (default: local connect, 8 s timeout). */
  tcpCheck?: (ip: string, port: number) => Promise<boolean>;
  /** Local probe seam (default: the real child_process implementation). */
  runner?: LocalProbeRunner;
}

export const PUBLIC_VERIFY_STEP_NAME = "Verify public reachability (local probe)";

export function publicVerifyStep(opts: PublicVerifyOptions = {}): Step {
  const dnsResolver = opts.dnsResolver ?? defaultDnsResolver;
  const tcpCheck = opts.tcpCheck ?? defaultTcpCheck;
  const runner = opts.runner ?? new ChildProcessProbeRunner(opts.poll ?? {});

  return {
    name: PUBLIC_VERIFY_STEP_NAME,
    run: async (_conn, ctx): Promise<StepResult> => {
      try {
        return await doRun(opts, dnsResolver, tcpCheck, runner, ctx);
      } catch (err) {
        // The step itself never crashes: a thrown failure (DNS resolver
        // error, binary download/verification) is reported as `failed`
        // like every other step outcome.
        return { status: "failed", detail: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}

async function doRun(
  opts: PublicVerifyOptions,
  dnsResolver: DnsResolver,
  tcpCheck: (ip: string, port: number) => Promise<boolean>,
  runner: LocalProbeRunner,
  ctx: StepCtx,
): Promise<StepResult> {
  if (opts.skip) {
    return { status: "skipped", detail: "--skip-public-verify" };
  }
  // Decision 1: the probe must run where the operator's network is —
  // viper's supported host OS is Linux (x64/arm64).
  if (process.platform !== "linux" || (process.arch !== "x64" && process.arch !== "arm64")) {
    return {
      status: "failed",
      detail:
        `public verify requires a Linux x64/arm64 host (got ${process.platform}/${process.arch}) ` +
        `— the probe must run where the operator's network is`,
    };
  }

  // 1. DNS: the domain must resolve to the deployed ip (the --ip
  //    override already flows into ctx.config).
  const resolved = await dnsResolver(ctx.config.domain);
  if (!resolved.includes(ctx.config.ip)) {
    return {
      status: "failed",
      detail:
        `DNS: ${ctx.config.domain} resolves to ${resolved.join(", ") || "(none)"}, ` +
        `expected ${ctx.config.ip} — fix DNS; tunnel not tested`,
    };
  }

  // 2. TCP: a raw connect must succeed (8 s) — catches a SYN drop.
  if (!(await tcpCheck(ctx.config.ip, ctx.config.port))) {
    return {
      status: "failed",
      detail: `TCP connect to ${ctx.config.ip}:${ctx.config.port} failed — path blocked or port closed`,
    };
  }

  await runner.ensureBinary(ctx.config.xray);

  // Local sandbox: fresh per run, rm -rf in finally (always).
  const sandbox = join(tmpdir(), `viper-public-probe-${process.pid}`);
  try {
    // Reap a local orphan probe (e.g. a launch that timed out before
    // the pid was captured) so the SOCKS port is free for the first
    // client.
    await runner.reapOrphans(sandbox);

    // 3. Probe EVERY client, not just clients[0] (same contract as
    //    the loopback probe): each client's uuid is the credential a
    //    real client will present, so each gets its own sandbox
    //    cycle (render → -test → run → poll SOCKS → curl → cleanup).
    for (const client of ctx.config.clients) {
      const rendered = renderXrayProbeClient(ctx.config, ctx.state, client.name, {
        address: publicProbeAddress(ctx.config),
      });
      const result = await runLocalClientProbe(ctx, sandbox, rendered, runner, client.name);
      if (result !== null) return result;
    }
    const n = ctx.config.clients.length;
    return { status: "ok", detail: `HTTP 204 via gstatic, ${n} client${n === 1 ? "" : "s"}` };
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
}

/** Run the probe for ONE client. Returns null on success, else the
 *  failure result (the sandbox is cleaned up in both cases). */
async function runLocalClientProbe(
  ctx: StepCtx,
  sandbox: string,
  rendered: string,
  runner: LocalProbeRunner,
  clientName: string,
): Promise<StepResult | null> {
  try {
    await mkdir(sandbox, { recursive: true });
    const cfgPath = join(sandbox, "config.json");
    await writeFile(cfgPath, rendered, "utf8");

    let code: string;
    try {
      code = await runner.runClient(cfgPath, PROBE_SOCKS_PORT);
    } catch (err) {
      // A config error is a distinct failure class — the xray error is
      // included, and it is NOT reported as a path/DPI failure.
      if (err instanceof ProbeConfigError) {
        return {
          status: "failed",
          detail: `probe client "${clientName}": config rejected by xray -test: ${err.message}`,
        };
      }
      throw err;
    }

    if (code !== "204") {
      // The loopback probe passed (it runs earlier in the pipeline) and
      // the DNS + TCP pre-checks passed, so the server is healthy — the
      // egress failure means the path is killing TLS (per-IP DPI).
      return {
        status: "failed",
        detail:
          `probe client "${clientName}": HTTP ${code || "000"} via gstatic — ` +
          `TLS to ${ctx.config.ip} is being killed (per-IP DPI block; server is healthy). ` +
          `Provision a different server IP.`,
      };
    }
    return null;
  } finally {
    // Each probe gets its own sandbox cycle; cleanup always.
    await rm(sandbox, { recursive: true, force: true });
  }
}
