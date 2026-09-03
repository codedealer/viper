/**
 * Xray verify steps (M5) — prove the deployed VPN actually works.
 *
 *  1. "Verify Xray unit active" — `systemctl is-active xray`.
 *  2. "Verify Xray listening on :<port>" — `ss -tln` shows the inbound.
 *  3. "Verify REALITY handshake (probe)" — the end-to-end proof,
 *     run ONCE PER CLIENT: render a minimal client config (SOCKS
 *     127.0.0.1:10809 → vless/reality to 127.0.0.1:<port> with that
 *     client's uuid/flow/shortId and the server PUBLIC key), validate it
 *     with `xray -test`, run it in the background from the
 *     /tmp/viper-probe sandbox, poll for the SOCKS port, then
 *     `curl --socks5-hostname` a real HTTPS endpoint
 *     (https://www.gstatic.com/generate_204) through it and require
 *     HTTP 204. A 204 proves the full REALITY handshake + VLESS auth
 *     against the deployed server config with the pinned binary.
 *     The sandbox is ALWAYS cleaned up (kill pid, rm -rf), even on
 *     failure.
 */
import type { SshConn } from "../ssh.js";
import type { Step, StepResult } from "./runner.js";
import { errDetail, poll, uploadRendered, type PollOptions } from "./common.js";
import { PROBE_DIR, PROBE_SOCKS_PORT, renderXrayProbeClient } from "../render/xray-probe.js";

export function xrayUnitActiveStep(): Step {
  return {
    name: "Verify Xray unit active",
    run: async (conn): Promise<StepResult> => {
      const res = await conn.run("systemctl is-active xray", { timeoutMs: 10_000 });
      if (res.stdout.trim() === "active") {
        return { status: "ok", detail: "xray active" };
      }
      return {
        status: "failed",
        detail: `xray unit is not active (state: "${res.stdout.trim() || res.stderr.trim()}")`,
      };
    },
  };
}

/** True when any `ss -tln` local-address token ends in `:<port>`. */
function isListening(stdout: string, port: number): boolean {
  return stdout.split("\n").some((line) => line.split(/\s+/).some((tok) => tok.endsWith(`:${port}`)));
}

export function xrayListeningStep(): Step {
  return {
    name: "Verify Xray listening on :443",
    run: async (conn, ctx): Promise<StepResult> => {
      const res = await conn.run("ss -tln", { timeoutMs: 10_000 });
      if (res.code !== 0) {
        return { status: "failed", detail: `ss -tln failed: ${errDetail(res.stderr)}` };
      }
      if (isListening(res.stdout, ctx.config.port)) {
        return { status: "ok", detail: `listening on :${ctx.config.port}` };
      }
      return { status: "failed", detail: `nothing listening on :${ctx.config.port}` };
    },
  };
}

export function xrayHandshakeProbeStep(pollOpts: PollOptions = {}): Step {
  return {
    name: "Verify REALITY handshake (probe)",
    run: async (conn, ctx): Promise<StepResult> => {
      // Reap an orphan probe left by a previously failed run (e.g. a
      // launch that timed out before the pid was captured) so its
      // SOCKS port is free for the first client. The [c] bracket keeps
      // pkill from matching its own wrapping shell.
      await conn.run(`pkill -f 'xray run -c ${PROBE_DIR}/[c]onfig.json' 2>/dev/null || true`, {
        timeoutMs: 10_000,
      });

      // Probe EVERY client, not just clients[0]: each client's uuid is
      // the credential a real client will present, so every one gets its
      // own end-to-end handshake proof. Each probe runs in its own
      // sandbox cycle (upload → -test → launch → poll → curl → cleanup).
      for (const client of ctx.config.clients) {
        const rendered = renderXrayProbeClient(ctx.config, ctx.state, client.name);
        const result = await runClientProbe(conn, rendered, pollOpts, client.name);
        if (result !== null) return result;
      }
      const n = ctx.config.clients.length;
      return {
        status: "ok",
        detail: `REALITY handshake OK (${n} client${n === 1 ? "" : "s"}, HTTP 204 via gstatic)`,
      };
    },
  };
}

/** Run the probe for ONE client. Returns null on success, else the
 *  failure result (the sandbox is cleaned up in both cases). */
async function runClientProbe(
  conn: SshConn,
  rendered: string,
  pollOpts: PollOptions,
  clientName: string,
): Promise<StepResult | null> {
  const cleanup = async (pid?: string): Promise<void> => {
    if (pid !== undefined) {
      await conn.run(`kill ${pid} 2>/dev/null`, { timeoutMs: 10_000 });
    }
    await conn.run(`rm -rf ${PROBE_DIR}`, { timeoutMs: 10_000 });
  };

  let pid: string | undefined;
  try {
    await conn.run(`mkdir -p ${PROBE_DIR}`, { timeoutMs: 10_000 });
    await uploadRendered(conn, rendered, `${PROBE_DIR}/config.json`, "config.json");

    // Validate the probe client config before running it: a config
    // error must not be mistaken for a handshake failure.
    const test = await conn.run(`cd /usr/local/share/xray && xray -test -c ${PROBE_DIR}/config.json`, {
      timeoutMs: 60_000,
    });
    if (test.code !== 0) {
      // xray logs config errors to stdout (not stderr) — include both.
      return {
        status: "failed",
        detail:
          `probe client "${clientName}": config rejected by xray -test: ` +
          errDetail([test.stdout.trim(), test.stderr.trim()].filter(Boolean).join(" | ")),
      };
    }

    // NB: the whole `(cd … && exec nohup xray …)` job is backgrounded
    // with its stdout/stderr/stdin redirected at the JOB level. A bare
    // `cd … && nohup xray … &` would background the subshell holding the
    // SSH pipe open for the probe's lifetime (command timeout).
    const start = await conn.run(
      `(cd /usr/local/share/xray && exec nohup xray run -c ${PROBE_DIR}/config.json > ${PROBE_DIR}/xray.log 2>&1 < /dev/null) & echo $!`,
      { timeoutMs: 15_000 },
    );
    pid = start.stdout.trim();
    if (pid === "") {
      return {
        status: "failed",
        detail: `could not start probe xray for client "${clientName}" (${errDetail(start.stderr)})`,
      };
    }

    const up = await poll(
      async () => isListening((await conn.run("ss -tln", { timeoutMs: 10_000 })).stdout, PROBE_SOCKS_PORT),
      { attempts: 10, intervalMs: 500, ...pollOpts },
    );
    if (!up) {
      const log = await conn.run(`tail -n 30 ${PROBE_DIR}/xray.log 2>/dev/null`, {
        timeoutMs: 10_000,
      });
      return {
        status: "failed",
        detail:
          `probe xray for client "${clientName}" did not open SOCKS port ${PROBE_SOCKS_PORT} ` +
          `— log: ${errDetail(log.stdout)}`,
      };
    }

    const curl = await conn.run(
      `curl --socks5-hostname 127.0.0.1:${PROBE_SOCKS_PORT} -s -o /dev/null -w '%{http_code}' --max-time 20 https://www.gstatic.com/generate_204`,
      { timeoutMs: 30_000 },
    );
    const code = curl.stdout.trim();
    if (code !== "204") {
      const log = await conn.run(`tail -n 30 ${PROBE_DIR}/xray.log 2>/dev/null`, {
        timeoutMs: 10_000,
      });
      return {
        status: "failed",
        detail:
          `REALITY handshake probe failed for client "${clientName}" (HTTP ${code || "000"} via gstatic) ` +
          `— log: ${errDetail(log.stdout)}`,
      };
    }
    return null;
  } finally {
    await cleanup(pid);
  }
}
