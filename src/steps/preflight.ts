/**
 * Preflight step (M4) — read-only, fail fast, clear messages.
 *
 * Check order (first failure wins):
 *   1. OS is ubuntu/debian (/etc/os-release)
 *   2. >= 2048 MB free on /
 *   3. live sshd port(s) include the port we connected on (lockout guard
 *      for the ufw step)
 *   4. DNS: <domain> resolves (client-side) and at least one A record
 *      equals the target IP
 *   5. host key: capture on first deploy, verify on later deploys
 *
 * Only write: persisting the captured host key into state (via the
 * injected persister). Everything else is read-only.
 */
import type { Step, StepResult } from "./runner.js";
import {
  MIN_DISK_SPACE_MB,
  SUPPORTED_OS_IDS,
  detectSshdPorts,
  defaultDnsResolver,
  errDetail,
  type HardeningStepOptions,
} from "./common.js";

const OS_RELEASE_CMD = `bash -c '. /etc/os-release && echo "$ID:$VERSION_CODENAME"'`;
const DISK_CMD = "df -BM --output=avail / | tail -1";

export function preflightStep(opts: HardeningStepOptions = {}): Step {
  return {
    name: "Preflight",
    run: async (conn, ctx): Promise<StepResult> => {
      const domain = ctx.config.domain;
      // The EFFECTIVE ip (the `--ip` override when given), per the
      // StepCtx contract — not ctx.config.ip.
      const ip = ctx.ip;

      // 1 — OS
      const os = await conn.run(OS_RELEASE_CMD, { timeoutMs: 15_000 });
      if (os.code !== 0) {
        return {
          status: "failed",
          detail: `could not read /etc/os-release: ${errDetail(os.stderr)}`,
        };
      }
      const id = os.stdout.trim().split(":")[0] ?? "";
      if (!SUPPORTED_OS_IDS.includes(id as (typeof SUPPORTED_OS_IDS)[number])) {
        return {
          status: "failed",
          detail: `unsupported OS (found ${id || "unknown"}) — v1 supports Ubuntu/Debian`,
        };
      }

      // 2 — disk space
      const df = await conn.run(DISK_CMD, { timeoutMs: 15_000 });
      const m = df.stdout.trim().match(/^(\d+)M$/);
      if (df.code !== 0 || m === null) {
        return {
          status: "failed",
          detail: `could not check free disk space (df -BM --output=avail /)`,
        };
      }
      const availMb = Number(m[1]);
      if (availMb < MIN_DISK_SPACE_MB) {
        return {
          status: "failed",
          detail: `only ${availMb}MB free on /, need ${MIN_DISK_SPACE_MB}MB — free up space (df -h) and re-run`,
        };
      }

      // 3 — live SSH port must include the port we connected on
      const ports = await detectSshdPorts(conn);
      if (!ports.includes(ctx.config.sshPort)) {
        return {
          status: "failed",
          detail:
            ports.length === 0
              ? "could not detect sshd listen ports (sshd -T) — refusing to continue"
              : `connected on ${ctx.config.sshPort} but sshd listens on ${ports.join(", ")} — set sshPort in viper.${ctx.name}.yml`,
        };
      }

      // 4 — DNS A record (client-side resolver, injectable seam)
      let records: string[];
      try {
        records = await (opts.dnsResolver ?? defaultDnsResolver)(domain);
      } catch (err) {
        return {
          status: "failed",
          detail: `DNS lookup for ${domain} failed: ${err instanceof Error ? err.message : String(err)} — check your local network/DNS and retry`,
        };
      }
      if (records.length === 0) {
        return {
          status: "failed",
          detail: `${domain} does not resolve — create an A record for ${domain} → ${ip}`,
        };
      }
      if (!records.includes(ip)) {
        return {
          status: "failed",
          detail:
            `${domain} does not resolve to this server's IP (${ip}) — DNS returned: ${records.join(", ")}. ` +
            `The domain must point DIRECTLY to this server for TLS certificates. ` +
            `Fix: in your DNS provider (e.g. Cloudflare), set the A record ${domain} → ${ip} to ` +
            `"DNS only" (grey cloud, unproxied), then re-run. Switch back to "Proxied" afterwards if you want.`,
        };
      }

      // 5 — host key: capture on first deploy, verify afterwards
      const fingerprint = conn.hostKeyFingerprint();
      if (fingerprint === undefined) {
        return {
          status: "failed",
          detail: "could not read the server's host key — cannot verify the connection",
        };
      }
      if (ctx.state.hostKey === null) {
        ctx.state.hostKey = { fingerprint };
        await opts.persistState?.(ctx.state);
        return { status: "ok", detail: `host key captured (${fingerprint})` };
      }
      if (ctx.state.hostKey.fingerprint !== fingerprint) {
        return {
          status: "failed",
          detail:
            `server host key CHANGED (expected ${ctx.state.hostKey.fingerprint}, got ${fingerprint}). ` +
            `The server was re-provisioned or something is intercepting the connection — stop and investigate. ` +
            `If you deliberately re-imaged the box, delete state/${ctx.name}.yml to re-key.`,
        };
      }
      return { status: "ok", detail: "OS, disk, ssh port, DNS, host key all OK" };
    },
  };
}
