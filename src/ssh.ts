/**
 * SSH engine (M3) — persistent connection for the whole deploy.
 *
 * Design rules (plan: "Remote execution strategy (ssh2)"):
 *  - One ssh2 `Client` for the whole deploy session; many execs, SFTP from
 *    the same connection. Re-connecting per command is what makes long
 *    deploys flaky and slow.
 *  - Artifacts travel by SFTP (`upload`), never by heredoc.
 *  - A non-zero exit code is a RESULT (`CommandResult.code`), never a
 *    thrown error. Thrown errors are transport-level failures (connect
 *    fail, socket drop, timeout, SFTP fail).
 *  - Retry-on-transient: transport-level failures trigger a reconnect
 *    (fresh Client against the same RemoteHost) + ONE retry of the failed
 *    operation, bounded with a small backoff. Command-level failures
 *    (non-zero code) are never retried. A second transient failure throws.
 */
import { Client } from "ssh2";
import { createHash } from "node:crypto";
import { dirname as posixDirname } from "node:path/posix";
import { readFile } from "node:fs/promises";

export interface RemoteHost {
  host: string;
  port?: number;
  username: string;
  /** Path to a private key file, or inline private key material. */
  privateKeyPath?: string;
  password?: string;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  code: number;
}

export interface RunOptions {
  /** Per-command timeout (defaults to the connection's commandTimeoutMs). */
  timeoutMs?: number;
}

/**
 * The minimal connection surface that deploy steps depend on. Steps take a
 * value of this type, so unit tests run against a fake conn (M4+ steps).
 */
export interface SshConn {
  run(cmd: string, opts?: RunOptions): Promise<CommandResult>;
  upload(localPath: string, remotePath: string): Promise<void>;
  close(): Promise<void>;
  /**
   * SHA-256 fingerprint of the server's host key, as `SHA256:<base64-no-
   * padding>` (byte-for-byte the OpenSSH `ssh-keygen -lf` / `ssh -Q`
   * format, so it cross-checks directly against local ssh tooling).
   * Captured from the handshake via ssh2's `hostVerifier`. `undefined`
   * when no client is connected (not connected, or closed).
   */
  hostKeyFingerprint(): string | undefined;
}

export interface ConnectOptions {
  /** Connect timeout (default 20 s). */
  connectTimeoutMs?: number;
  /** Default per-command timeout (default 30 s), overridable per call. */
  commandTimeoutMs?: number;
  /**
   * Injectable client factory (test seam): creates a fresh ssh2 Client per
   * (re)connect. Defaults to `() => new Client()`.
   */
  clientFactory?: () => unknown;
  /** Backoff before the single transient-failure retry (default 500 ms). */
  retryBackoffMs?: number;
}

const DEFAULT_CONNECT_TIMEOUT_MS = 20_000;
const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY_BACKOFF_MS = 500;
/** Fallback so close() never hangs on a dead socket. */
const CLOSE_FALLBACK_MS = 2_000;
/** TCP/SSH keepalive so long idle deploys survive NAT drops (M4). */
const KEEPALIVE_INTERVAL_MS = 30_000;

/**
 * Host-key fingerprint: `SHA256:` + base64 (no padding) of the raw server
 * host-key blob — byte-for-byte the OpenSSH `ssh-keygen -lf` / `ssh -Q`
 * format, so it cross-checks directly against local ssh tooling.
 *
 * The blob comes from ssh2's `hostVerifier` hook: ssh2 hands the server
 * key to user code ONLY there during KEX (`Client` has no `hostKeys`
 * property — the client.js `hostKeys` is the unrelated hostkeys-prove
 * feature). The engine TOFU-accepts (always returns true); verifying the
 * fingerprint against captured state is the preflight step's job.
 */
function fingerprintOf(blob: Buffer): string {
  const digest = createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
  return `SHA256:${digest}`;
}

/**
 * Loose structural surface of what the engine calls on the ssh2 Client /
 * channel / SFTP session. Kept intentionally minimal so a fake transport
 * can stand in in tests; the real Client is cast to it.
 */
interface AnySftp {
  mkdir(path: string, callback: (err: Error | null) => void): void;
  stat(path: string, callback: (err: Error | null, stats?: { mode?: number }) => void): void;
  /**
   * ssh2 1.17 surface: the old `put` was removed in favor of `fastPut`
   * (chunked, parallel). The 3-arg form (opts omitted) is supported.
   */
  fastPut(localPath: string, remotePath: string, callback: (err: Error | null) => void): void;
  end(): void;
}

interface AnyStream {
  on(event: "data", handler: (data: Buffer) => void): unknown;
  on(event: "close", handler: (code: number | null) => void): unknown;
  stderr: { on(event: "data", handler: (data: Buffer) => void): unknown };
}

interface AnyClient {
  on(event: "ready" | "error" | "close", handler: (...args: unknown[]) => void): unknown;
  connect(config: Record<string, unknown>): void;
  end(): void;
  exec(command: string, callback: (err: Error | null, stream?: AnyStream) => void): void;
  sftp(callback: (err: Error | null, sftp?: AnySftp) => void): void;
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Wrap a cause into an Error while preserving its `code` (retry classification). */
function wrapError(message: string, cause?: unknown): Error {
  const err = new Error(message) as Error & { code?: string; cause?: unknown };
  if (cause instanceof Error) {
    const c = cause as Error & { code?: string };
    if (typeof c.code === "string") err.code = c.code;
    err.cause = cause;
  }
  return err;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Socket-level codes that a fresh connection can plausibly fix. */
const TRANSIENT_CODES = new Set([
  "ECONNRESET",
  "ETIMEDOUT",
  "EPIPE",
  "ECONNREFUSED",
  "ENETUNREACH",
  "EHOSTUNREACH",
  "EAI_AGAIN",
]);

const TRANSIENT_RE =
  /socket closed|channel closed|connection (lost|reset|terminated|closed)|closed before ready|end of file|ssh session not ready|session not ready|timed out|EOF/i;

/** Auth/config failures: retrying a fresh connection cannot fix these. */
const NON_TRANSIENT_RE = /authenticat|password|private ?key|host key|no matching key|agent/i;

function isTransient(err: unknown): boolean {
  if ((err as { sshTimeout?: boolean })?.sshTimeout) return false;
  const e = err as Error & { code?: string };
  if (typeof e.code === "string" && TRANSIENT_CODES.has(e.code)) return true;
  const msg = errMsg(err);
  if (NON_TRANSIENT_RE.test(msg)) return false;
  return TRANSIENT_RE.test(msg);
}

/**
 * Connect to a remote host and return a persistent connection.
 * One ssh2 Client backs the whole deploy; run/upload share it.
 */
export async function connect(host: RemoteHost, opts: ConnectOptions = {}): Promise<SshConn> {
  const conn = new SshConnection(host, opts);
  // The initial connect is itself a retryable transport-level operation:
  // a transient ECONNRESET/timeout at connect time gets one bounded retry.
  await conn.withRetry(() => conn.ensureConnected());
  return conn;
}

class SshConnection implements SshConn {
  private client: AnyClient | null = null;
  private sftp: AnySftp | null = null;
  /** Raw server host-key blob captured via hostVerifier on the last handshake. */
  private hostKeyBlob: Buffer | null = null;
  private broken = false; // client died (error/close event) — reconnect next op
  private closed = false; // we closed — no more operations

  constructor(
    private readonly host: RemoteHost,
    private readonly opts: ConnectOptions,
  ) {}

  private get connectTimeoutMs(): number {
    return this.opts.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
  }
  private get commandTimeoutMs(): number {
    return this.opts.commandTimeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
  }
  private get retryBackoffMs(): number {
    return this.opts.retryBackoffMs ?? DEFAULT_RETRY_BACKOFF_MS;
  }
  private get addr(): string {
    return `${this.host.host}:${this.host.port ?? 22}`;
  }

  async run(cmd: string, opts?: RunOptions): Promise<CommandResult> {
    return this.withRetry(async () => {
      const client = await this.ensureConnected();
      return this.execOnce(client, cmd, opts?.timeoutMs ?? this.commandTimeoutMs);
    });
  }

  async upload(localPath: string, remotePath: string): Promise<void> {
    await this.withRetry(async () => {
      const client = await this.ensureConnected();
      const sftp = await this.ensureSftp(client);
      const parent = posixDirname(remotePath);
      if (parent !== "." && parent !== "" && parent !== "/") {
        await sftpMkdirs(sftp, parent);
      }
      await sftpPut(sftp, localPath, remotePath);
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const sftp = this.sftp;
    const client = this.client;
    this.sftp = null;
    this.client = null;
    if (sftp) {
      try {
        sftp.end();
      } catch {
        // already gone
      }
    }
    if (client) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, CLOSE_FALLBACK_MS);
        try {
          client.on("close", () => {
            clearTimeout(timer);
            resolve();
          });
        } catch {
            // ignore
        }
        try {
          client.end();
        } catch {
          clearTimeout(timer);
          resolve();
        }
      });
    }
    this.hostKeyBlob = null;
  }

  hostKeyFingerprint(): string | undefined {
    if (this.closed || this.client === null) return undefined;
    if (this.hostKeyBlob === null) return undefined;
    return fingerprintOf(this.hostKeyBlob);
  }

  /** Reconnect if the current client is dead; otherwise reuse it. */
  async ensureConnected(): Promise<AnyClient> {
    if (this.closed) throw new Error("ssh: connection is closed");
    if (this.client !== null && !this.broken) return this.client;
    this.discardClient();
    this.client = await this.connectOnce();
    return this.client;
  }

  private discardClient(): void {
    const client = this.client;
    this.client = null;
    this.sftp = null;
    this.broken = false;
    this.hostKeyBlob = null;
    if (client) {
      try {
        client.end();
      } catch {
        // already gone
      }
    }
  }

  private markBroken(): void {
    this.broken = true;
  }

  private async connectOnce(): Promise<AnyClient> {
    const client = (this.opts.clientFactory ?? (() => new Client()))() as AnyClient;
    const timeoutMs = this.connectTimeoutMs;

    let privateKey: Buffer | string | undefined;
    if (this.host.privateKeyPath) {
      try {
        privateKey = await readFile(this.host.privateKeyPath, "utf8");
      } catch (err) {
        throw new Error(
          `ssh: cannot read private key "${this.host.privateKeyPath}": ${errMsg(err)}`,
        );
      }
    }

    const config: Record<string, unknown> = {
      host: this.host.host,
      port: this.host.port ?? 22,
      username: this.host.username,
      readyTimeout: timeoutMs,
      keepaliveInterval: KEEPALIVE_INTERVAL_MS,
      // TOFU: capture the server host-key blob from the handshake and
      // always accept. (ssh2 hands the key to user code only here; the
      // fingerprint is what preflight verifies against state.)
      hostVerifier: (key: unknown) => {
        this.hostKeyBlob = key as Buffer;
        return true;
      },
    };
    if (privateKey !== undefined) config.privateKey = privateKey;
    else if (this.host.password !== undefined) config.password = this.host.password;

    return new Promise<AnyClient>((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        try {
          client.end();
        } catch {
          // ignore
        }
        reject(new Error(`ssh: connect timed out after ${timeoutMs}ms (${this.addr})`));
      }, timeoutMs);

      client.on("ready", () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(client);
      });
      client.on("error", (err: unknown) => {
        if (settled) {
          this.markBroken();
          return;
        }
        settled = true;
        clearTimeout(timer);
        reject(wrapError(`ssh: connect to ${this.addr} failed: ${errMsg(err)}`, err));
      });
      client.on("close", () => {
        if (settled) {
          this.markBroken();
          return;
        }
        settled = true;
        clearTimeout(timer);
        reject(new Error(`ssh: connect to ${this.addr}: connection closed before ready`));
      });

      client.connect(config);
    });
  }

  /** One exec on a known-good client; resolves on any exit code. */
  private execOnce(client: AnyClient, cmd: string, timeoutMs: number): Promise<CommandResult> {
    return new Promise<CommandResult>((resolve, reject) => {
      let settled = false;
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        // Kill the session (binding decision 2) and surface an actionable
        // error naming the command. Timeouts are NOT retried: the command
        // may have partially executed.
        try {
          client.end();
        } catch {
          // ignore
        }
        this.markBroken();
        const err = new Error(`ssh: command timed out after ${timeoutMs}ms: ${cmd}`);
        (err as { sshTimeout?: boolean }).sshTimeout = true;
        reject(err);
      }, timeoutMs);

      client.exec(cmd, (err, stream) => {
        if (err || stream === undefined) {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          reject(wrapError(`ssh: exec failed: ${errMsg(err ?? new Error("no stream"))}`, err));
          return;
        }
        stream.on("data", (data) => {
          stdout += data.toString();
        });
        stream.stderr.on("data", (data) => {
          stderr += data.toString();
        });
        stream.on("close", (code) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          if (code === null) {
            // Socket/channel died mid-command — transport-level failure.
            this.markBroken();
            reject(new Error(`ssh: command interrupted (socket closed): ${cmd}`));
            return;
          }
          resolve({ stdout, stderr, code });
        });
      });
    });
  }

  private async ensureSftp(client: AnyClient): Promise<AnySftp> {
    if (this.sftp !== null) return this.sftp;
    const sftp = await new Promise<AnySftp>((resolve, reject) => {
      client.sftp((err, s) => {
        if (err || s === undefined) {
          reject(
            wrapError(
              `ssh: sftp session failed: ${errMsg(err ?? new Error("no session"))}`,
              err,
            ),
          );
          return;
        }
        resolve(s);
      });
    });
    this.sftp = sftp;
    return sftp;
  }

  /**
   * Bounded retry: ONE retry of the failed operation after a transient
   * transport failure (reconnect + small backoff). Non-transient errors
   * and command-level non-zero codes (which never throw here) pass through.
   */
  async withRetry<T>(op: () => Promise<T>): Promise<T> {
    try {
      return await op();
    } catch (err) {
      if (this.closed || !isTransient(err)) throw err;
      this.discardClient();
      await sleep(this.retryBackoffMs);
      return op();
    }
  }
}

/** Create each missing ancestor directory (top-down), tolerating existing ones. */
async function sftpMkdirs(sftp: AnySftp, dir: string): Promise<void> {
  const parts = dir.split("/").filter((p) => p !== "");
  let current = "";
  for (const part of parts) {
    current += `/${part}`;
    const err = await new Promise<Error | null>((resolve) => {
      sftp.mkdir(current, (e) => resolve(e ?? null));
    });
    if (err === null) continue;
    // mkdir can fail because the directory already exists — verify with stat.
    const stats = await new Promise<{ mode?: number } | null>((resolve, reject) => {
      sftp.stat(current, (e, st) => {
        if (e) reject(wrapError(`ssh: cannot ensure remote dir ${current}: ${errMsg(e)}`, e));
        else resolve(st ?? null);
      });
    });
    if ((stats?.mode ?? 0) & 0o40000) continue;
    throw wrapError(`ssh: cannot create remote dir ${current}: ${errMsg(err)}`, err);
  }
}

async function sftpPut(sftp: AnySftp, localPath: string, remotePath: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    sftp.fastPut(localPath, remotePath, (err) => {
      if (err) reject(wrapError(`ssh: upload to ${remotePath} failed: ${errMsg(err)}`, err));
      else resolve();
    });
  });
}