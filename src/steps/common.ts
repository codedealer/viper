/**
 * Shared helpers for the M4 hardening steps.
 *
 * The steps mutate the remote host through the minimal `SshConn` surface
 * (M3 engine). Artifacts travel by SFTP (`uploadRendered`), never by
 * heredoc. `StepCtx` is fixed (M3 shape), so the two seams a step needs
 * that cannot live in StepCtx — a DNS resolver and a state persister —
 * are injected via `HardeningStepOptions` by the caller (M7 CLI).
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolve4 } from "node:dns/promises";
import type { SshConn } from "../ssh.js";
import type { State } from "../state.js";

/** Minimum free space on `/` before a deploy (Meridian's MIN_DISK_SPACE_MB). */
export const MIN_DISK_SPACE_MB = 2048;

/** Packages viper requires (installed by the packages step, M4). */
export const REQUIRED_PACKAGES = ["nginx", "fail2ban", "unattended-upgrades", "ufw"];

/** OS ids accepted in v1 (checked against /etc/os-release ID). */
export const SUPPORTED_OS_IDS = ["ubuntu", "debian"] as const;

export type DnsResolver = (domain: string) => Promise<string[]>;

/**
 * Call-injected seams for the step list. The M7 CLI passes a real
 * persister (`saveState` on `state/<name>.yml`); tests pass recorders.
 * Both optional: without `persistState` state mutations stay in-memory
 * for the current run only.
 */
export interface HardeningStepOptions {
  dnsResolver?: DnsResolver;
  persistState?: (state: State) => Promise<void> | void;
}

/**
 * Error-code mapping for DNS lookups (used by `defaultDnsResolver`):
 * `ENOTFOUND`/`ENODATA` mean "the name exists but has no A record" -> `[]`.
 * Every other code is re-thrown — `EAI_AGAIN` in particular is a
 * *transient local resolver failure*, not a missing record, and must not
 * be reported as "create an A record" (it means "check your local
 * network/DNS").
 */
export function noRecordOrRethrow(err: unknown): string[] | never {
  const code = (err as { code?: string }).code;
  if (code === "ENOTFOUND" || code === "ENODATA") return [];
  throw err;
}

/**
 * Default DNS seam: Node's built-in resolver. "No A record" errors are
 * mapped to an empty list (a legitimate deploy state with its own
 * message); other failures (network down, resolver error, `EAI_AGAIN`)
 * throw and are reported distinctly by the preflight step.
 */
export const defaultDnsResolver: DnsResolver = (domain) => resolve4(domain).catch(noRecordOrRethrow);

/**
 * Parse sshd port(s) from command output (Meridian's _parse_ssh_ports
 * semantics: first numeric token per line, 1–65535, deduped).
 */
export function parsePorts(output: string): number[] {
  const ports: number[] = [];
  const seen = new Set<number>();
  for (const line of output.split("\n")) {
    for (const token of line.replace(",", " ").split(/\s+/)) {
      if (!/^\d+$/.test(token)) continue;
      const port = Number(token);
      if (port < 1 || port > 65535 || seen.has(port)) continue;
      seen.add(port);
      ports.push(port);
      break;
    }
  }
  return ports;
}

/**
 * Effective sshd listen ports, detected live — never assume 22
 * (Meridian's detect_ssh_ports command order: `sshd -T` first, config
 * grep as fallback). Returns `[]` when nothing could be detected: the
 * callers (preflight, ufw) fail rather than guess.
 */
export async function detectSshdPorts(conn: SshConn): Promise<number[]> {
  const commands = [
    "sshd -T 2>/dev/null | awk '$1 == \"port\" {print $2}'",
    "grep -hEi '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}'",
  ];
  for (const cmd of commands) {
    const res = await conn.run(cmd, { timeoutMs: 15_000 });
    if (res.code !== 0) continue;
    const ports = parsePorts(res.stdout);
    if (ports.length > 0) return ports;
  }
  return [];
}

/**
 * Rendered content → local temp file → SFTP upload → temp cleanup.
 * This is how every hardening artifact reaches the server (the plan's
 * "artifacts by SFTP, never heredoc").
 */
export async function uploadRendered(
  conn: SshConn,
  content: string,
  remotePath: string,
  baseName: string,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "viper-up-"));
  const local = join(dir, baseName);
  try {
    await writeFile(local, content, { mode: 0o600 });
    await conn.upload(local, remotePath);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** Shorten stderr for step details (200 chars, like Meridian's snippets). */
export function errDetail(err: string): string {
  const t = err.trim();
  return t.length > 200 ? `${t.slice(0, 200)}…` : t;
}

export interface PollOptions {
  attempts?: number;
  intervalMs?: number;
}

/**
 * Poll `fn` until it resolves true (or attempts are exhausted).
 * Default: 10 attempts, 1000 ms apart (the M5 post-restart contract
 * values); tests inject smaller intervals.
 */
export async function poll(fn: () => Promise<boolean>, opts: PollOptions = {}): Promise<boolean> {
  const attempts = opts.attempts ?? 10;
  const intervalMs = opts.intervalMs ?? 1000;
  for (let i = 0; i < attempts; i++) {
    if (await fn()) return true;
    if (i < attempts - 1) await new Promise((r) => setTimeout(r, intervalMs));
  }
  return false;
}
