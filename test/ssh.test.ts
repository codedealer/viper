import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { connect, type RemoteHost } from "../src/ssh.js";

/**
 * Engine tests run against a fake ssh2 transport (injected client factory)
 * — no sshd in this environment. Live-socket behavior is verified on wire
 * in M4+ against the VPS; those paths are NOT asserted here.
 */

class FakeStream {
  private stdoutHandler: ((d: Buffer) => void) | null = null;
  private stderrHandler: ((d: Buffer) => void) | null = null;
  private closeHandler: ((code: number | null) => void) | null = null;
  stderr = {
    on: (event: string, h: (d: Buffer) => void) => {
      if (event === "data") this.stderrHandler = h;
    },
  };
  on(event: string, h: unknown) {
    if (event === "data") this.stdoutHandler = h as (d: Buffer) => void;
    if (event === "close") this.closeHandler = h as (code: number | null) => void;
  }
  // --- test drivers ---
  emitStdout(s: string) {
    this.stdoutHandler?.(Buffer.from(s));
  }
  emitStderr(s: string) {
    this.stderrHandler?.(Buffer.from(s));
  }
  emitClose(code: number | null) {
    this.closeHandler?.(code);
  }
}

class FakeSftp {
  mkdirCalls: string[] = [];
  putCalls: Array<[string, string]> = [];
  ended = 0;
  mkdirBehavior: (path: string) => Error | null = () => null;
  putBehavior: () => Error | null = () => null;
  statDirs = new Set<string>();
  mkdir(path: string, cb: (err: Error | null) => void) {
    this.mkdirCalls.push(path);
    cb(this.mkdirBehavior(path));
  }
  stat(path: string, cb: (err: Error | null, stats?: { mode?: number }) => void) {
    if (this.statDirs.has(path)) cb(null, { mode: 0o40755 });
    else cb(new Error("no such file"));
  }
  /** ssh2 1.17 surface: the old `put` was removed in favor of `fastPut` (chunked). */
  fastPut(local: string, remote: string, cb: (err: Error | null) => void) {
    this.putCalls.push([local, remote]);
    cb(this.putBehavior());
  }
  end() {
    this.ended++;
  }
}

type ExecBehavior = (
  client: FakeClient,
  command: string,
  cb: (err: Error | null, stream?: FakeStream) => void,
) => void;

class FakeClient {
  ended = 0;
  sftpCalls = 0;
  execCalls: string[] = [];
  handlers: Record<string, Array<(...a: unknown[]) => void>> = {};
  stream: FakeStream | null = null;
  sftpSession: FakeSftp | null = null;
  execBehavior: ExecBehavior = (_c, _cmd, cb) => {
    const stream = new FakeStream();
    this.stream = stream;
    cb(null, stream);
    stream.emitStdout("hello\n");
    stream.emitClose(0);
  };
  /**
   * Deferred connect event: the real ssh2 Client only emits ready/error
   * AFTER the engine has registered its handlers, so the fake does the
   * same — the driver sets this in the factory, it fires in connect().
   */
  onConnect: (() => void) | null = null;
  /** Recorded connect config (ssh2 options). */
  connectConfig: Record<string, unknown> | null = null;
  /**
   * Raw server host-key blob as ssh2 hands it to `hostVerifier` during
   * KEX. The fake mirrors the REAL ssh2 surface: the Client has no
   * `hostKeys` property; the blob is delivered via the config's
   * hostVerifier, and connect() invokes it (like KEX does) before ready.
   */
  hostKeyBlob: Buffer | null = null;

  on(event: string, h: (...a: unknown[]) => void) {
    this.handlers[event] = this.handlers[event] ?? [];
    this.handlers[event].push(h);
    return this;
  }
  connect(config: Record<string, unknown>) {
    this.connectConfig = config;
    if (this.hostKeyBlob !== null) {
      const verifier = config.hostVerifier as ((key: unknown) => unknown) | undefined;
      if (typeof verifier === "function") verifier(this.hostKeyBlob);
    }
    this.onConnect?.();
  }
  end() {
    this.ended++;
    this.emitClose();
  }
  exec(command: string, cb: (err: Error | null, stream?: FakeStream) => void) {
    this.execCalls.push(command);
    this.execBehavior(this, command, cb);
  }
  sftp(cb: (err: Error | null, sftp?: FakeSftp) => void) {
    this.sftpCalls++;
    this.sftpSession = this.sftpSession ?? new FakeSftp();
    cb(null, this.sftpSession);
  }
  // --- test drivers ---
  emitReady() {
    for (const h of this.handlers.ready ?? []) h();
  }
  emitError(e: unknown) {
    for (const h of this.handlers.error ?? []) h(e);
  }
  emitClose() {
    for (const h of this.handlers.close ?? []) h();
  }
}

const host: RemoteHost = { host: "127.0.0.1", port: 2222, username: "root", password: "x" };

/** Fresh fake-transport harness: factory + connect with fast timeouts. */
async function harness() {
  const clients: FakeClient[] = [];
  const factory = () => {
    const c = new FakeClient();
    clients.push(c);
    c.onConnect = () => c.emitReady();
    return c;
  };
  const conn = await connect(host, {
    clientFactory: factory,
    connectTimeoutMs: 200,
    commandTimeoutMs: 150,
    retryBackoffMs: 1,
  });
  return { conn, clients };
}

function transientErr(code = "ECONNRESET"): Error {
  const e = new Error(`socket ${code.toLowerCase()}`) as Error & { code?: string };
  e.code = code;
  return e;
}

test("connect + run: single client, exit codes are results not errors", async () => {
  const { conn, clients } = await harness();
  const c = clients[0] as FakeClient;
  c.execBehavior = (_cl, cmd, cb) => {
    const stream = new FakeStream();
    cb(null, stream);
    if (cmd === "echo hello") stream.emitStdout("hello\n");
    if (cmd === "echo err 1>&2") stream.emitStderr("err line\n");
    stream.emitClose(cmd === "false" ? 1 : 0);
  };
  assert.equal(clients.length, 1);

  let r = await conn.run("echo hello");
  assert.deepEqual(r, { stdout: "hello\n", stderr: "", code: 0 });

  // non-zero exit code is a RESULT
  r = await conn.run("false");
  assert.equal(r.code, 1);
  assert.equal(clients.length, 1, "no reconnect for a command-level failure");

  // stderr captured; connection still works
  r = await conn.run("echo err 1>&2");
  assert.equal(r.code, 0);
  assert.equal(r.stderr, "err line\n");
  assert.equal(clients.length, 1, "one persistent client for many execs");
  await conn.close();
});

test("run: stdout/stderr separation and non-zero code without throw", async () => {
  const { conn, clients } = await harness();
  const c = clients[0] as FakeClient;
  c.execBehavior = (_cl, _cmd, cb) => {
    const stream = new FakeStream();
    cb(null, stream);
    stream.emitStdout("out\n");
    stream.emitStderr("err\n");
    stream.emitClose(2);
  };
  const r = await conn.run("mixed");
  assert.deepEqual(r, { stdout: "out\n", stderr: "err\n", code: 2 });
  assert.equal(clients.length, 1);
  await conn.close();
});

test("command timeout: session killed, actionable error names the command, NOT retried", async () => {
  const { conn, clients } = await harness();
  const c = clients[0] as FakeClient;
  c.execBehavior = (_cl, _cmd, cb) => cb(null, new FakeStream()); // never closes
  await assert.rejects(conn.run("long-job", { timeoutMs: 100 }), /command timed out after 100ms: long-job/);
  assert.ok(c.ended >= 1, "timeout kills the session");
  assert.equal(clients.length, 1, "a timed-out command is not retried");
  await conn.close();
});

test("transient exec failure: reconnect + one retry succeeds", async () => {
  const { conn, clients } = await harness();
  const first = clients[0] as FakeClient;
  first.execBehavior = (_cl, _cmd, cb) => cb(transientErr("ECONNRESET"));
  const r = await conn.run("ls");
  assert.equal(r.code, 0);
  assert.equal(clients.length, 2, "fresh client on retry");
  assert.deepEqual((clients[1] as FakeClient).execCalls, ["ls"], "retry re-runs the command");
  await conn.close();
});

test("socket closed mid-command: treated as transient, retried once", async () => {
  const { conn, clients } = await harness();
  const first = clients[0] as FakeClient;
  first.execBehavior = (_cl, _cmd, cb) => {
    const stream = new FakeStream();
    cb(null, stream);
    stream.emitClose(null); // channel died, no exit code
  };
  const r = await conn.run("ls");
  assert.equal(r.code, 0);
  assert.equal(clients.length, 2);
  await conn.close();
});

test("two transient failures: throws, no third client", async () => {
  const clients: FakeClient[] = [];
  const conn = await connect(host, {
    clientFactory: () => {
      const c = new FakeClient();
      clients.push(c);
      c.onConnect = () => c.emitReady();
      c.execBehavior = (_cl, _cmd, cb) => cb(transientErr("EPIPE"));
      return c;
    },
    connectTimeoutMs: 200,
    retryBackoffMs: 1,
  });
  await assert.rejects(conn.run("ls"), /socket epipe/i);
  assert.equal(clients.length, 2, "bounded: exactly one reconnect");
  await conn.close();
});

test("non-zero exit is never retried", async () => {
  const { conn, clients } = await harness();
  const c = clients[0] as FakeClient;
  c.execBehavior = (_cl, _cmd, cb) => {
    const stream = new FakeStream();
    cb(null, stream);
    stream.emitClose(1);
  };
  const r = await conn.run("will-fail");
  assert.equal(r.code, 1);
  assert.deepEqual(c.execCalls, ["will-fail"], "executed exactly once");
  assert.equal(clients.length, 1);
  await conn.close();
});

test("connect: transient failure at connect time gets one bounded retry", async () => {
  const clients: FakeClient[] = [];
  let i = 0;
  const conn = await connect(host, {
    clientFactory: () => {
      const c = new FakeClient();
      clients.push(c);
      c.onConnect = () => (i++ === 0 ? c.emitError(transientErr("ECONNRESET")) : c.emitReady());
      return c;
    },
    connectTimeoutMs: 200,
    retryBackoffMs: 1,
  });
  assert.equal(clients.length, 2);
  const r = await conn.run("true");
  assert.equal(r.code, 0);
  await conn.close();
});

test("connect: auth failure is NOT retried", async () => {
  const clients: FakeClient[] = [];
  await assert.rejects(
    connect(host, {
      clientFactory: () => {
        const c = new FakeClient();
        clients.push(c);
        c.onConnect = () => c.emitError(new Error("All configured authentication methods failed"));
        return c;
      },
      connectTimeoutMs: 200,
      retryBackoffMs: 1,
    }),
    /connect to 127.0.0.1:2222 failed: All configured authentication methods failed/,
  );
  assert.equal(clients.length, 1, "no retry for auth failures");
});

test("connect timeout: surfaces actionable error (one bounded retry)", async () => {
  const clients: FakeClient[] = [];
  await assert.rejects(
    connect(host, {
      clientFactory: () => {
        const c = new FakeClient();
        clients.push(c);
        return c; // never becomes ready
      },
      connectTimeoutMs: 80,
      retryBackoffMs: 1,
    }),
    /connect timed out after 80ms \(127\.0\.0\.1:2222\)/,
  );
  assert.equal(clients.length, 2, "one bounded retry, then throws");
});

test("upload: SFTP lazy + reused, parent dirs created top-down, existing dirs tolerated", async () => {
  const { conn, clients } = await harness();
  const c = clients[0] as FakeClient;
  assert.equal(c.sftpCalls, 0, "sftp session is lazy (no upload yet)");

  await conn.upload("/tmp/config.json", "/var/www/viper/main/config.json");
  assert.equal(c.sftpCalls, 1, "sftp opened on first upload");
  assert.deepEqual(c.sftpSession?.mkdirCalls, ["/var", "/var/www", "/var/www/viper", "/var/www/viper/main"]);
  assert.deepEqual(c.sftpSession?.putCalls, [["/tmp/config.json", "/var/www/viper/main/config.json"]]);

  // second upload reuses the same sftp session
  await conn.upload("/tmp/sub.txt", "/var/www/viper/main/sub.txt");
  assert.equal(c.sftpCalls, 1, "sftp session reused on the same connection");
  assert.deepEqual(c.sftpSession?.putCalls[1], ["/tmp/sub.txt", "/var/www/viper/main/sub.txt"]);
  await conn.close();
});

test("upload: mkdir failure is tolerated when the directory already exists", async () => {
  const { conn, clients } = await harness();
  const c = clients[0] as FakeClient;
  c.sftpSession = new FakeSftp();
  c.sftpSession.mkdirBehavior = (p) => (p === "/var" ? new Error("Failure") : null);
  c.sftpSession.statDirs.add("/var");
  await conn.upload("/tmp/a", "/var/www/b");
  assert.deepEqual(c.sftpSession?.putCalls, [["/tmp/a", "/var/www/b"]]);
  await conn.close();
});

test("upload: transient SFTP failure reconnects and retries once", async () => {
  const { conn, clients } = await harness();
  const first = clients[0] as FakeClient;
  first.sftpSession = new FakeSftp();
  first.sftpSession.putBehavior = () => transientErr("ECONNRESET");
  await conn.upload("/tmp/a", "/var/www/b");
  assert.equal(clients.length, 2, "fresh connection for the retry");
  assert.equal((clients[1] as FakeClient).sftpCalls, 1, "new sftp session on the new connection");
  assert.deepEqual((clients[1] as FakeClient).sftpSession?.putCalls, [["/tmp/a", "/var/www/b"]]);
  await conn.close();
});

test("close is idempotent; later operations reject with a closed error", async () => {
  const { conn } = await harness();
  await conn.close();
  await conn.close();
  await assert.rejects(conn.run("true"), /connection is closed/);
  await assert.rejects(conn.upload("/tmp/a", "/var/www/b"), /connection is closed/);
});
// ---------------------------------------------------------------- M4

test("connect config sets keepaliveInterval 30s (M4)", async () => {
  const { conn, clients } = await harness();
  const config = (clients[0] as FakeClient).connectConfig as Record<string, unknown>;
  assert.equal(config.keepaliveInterval, 30_000);
  await conn.close();
});

test("hostKeyFingerprint: SHA256:<base64-no-padding> of the raw host-key blob (OpenSSH format)", async () => {
  const blob = Buffer.from("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20raw-key-bytes-0123456789abcdefgh");
  const clients: FakeClient[] = [];
  const conn = await connect(host, {
    clientFactory: () => {
      const c = new FakeClient();
      c.onConnect = () => c.emitReady();
      c.hostKeyBlob = blob;
      clients.push(c);
      return c;
    },
    connectTimeoutMs: 200,
    retryBackoffMs: 1,
  });
  // the engine pins the real ssh2 surface: a hostVerifier in the connect config
  const config = (clients[0] as FakeClient).connectConfig as Record<string, unknown>;
  assert.equal(typeof config.hostVerifier, "function");
  const expected = "SHA256:" + createHash("sha256").update(blob).digest("base64").replace(/=+$/, "");
  assert.equal(conn.hostKeyFingerprint(), expected);
  await conn.close();
  assert.equal(conn.hostKeyFingerprint(), undefined, "no client after close");
});
