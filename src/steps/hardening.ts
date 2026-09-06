/**
 * Hardening steps (M4 + M8 IPv6) — Meridian's semantics, ported:
 *   tz → auto-upgrades → ssh → fail2ban → bbr → Configure IPv6 → ufw
 *
 * Rules honored throughout:
 *  - check-then-act; a second run in the same final state makes no
 *    mutating calls (the engine may re-execute a command once after a
 *    mid-command socket drop, so idempotency is a correctness
 *    requirement).
 *  - Artifacts travel by SFTP (`uploadRendered`), never heredoc.
 *  - SSH: sshd -t + sshd -T effective-config verification BEFORE any
 *    restart.
 *  - ufw: allow-rules (detected sshd ports + config.port + 80) BEFORE enable;
 *    no `ufw limit 22`; viper owns only its own rules.
 *  - BBR: warn-not-fail (skipped + WARNING) on kernels without the
 *    tunables.
 */
import type { SshConn } from "../ssh.js";
import type { ServerConfig } from "../config.js";
import type { Step, StepCtx, StepResult } from "./runner.js";
import {
  detectSshdPorts,
  errDetail,
  poll,
  uploadRendered,
  type HardeningStepOptions,
  type PollOptions,
} from "./common.js";
import { preflightStep } from "./preflight.js";
import { packagesStep } from "./packages.js";

// ---------------------------------------------------------------- renders

/** Meridian's auto-upgrades content, verbatim semantics. */
export function renderAutoUpgradesConf(): string {
  return (
    'APT::Periodic::Update-Package-Lists "1";\n' +
    'APT::Periodic::Unattended-Upgrade "1";\n' +
    'APT::Periodic::AutocleanInterval "7";\n'
  );
}

/**
 * Authoritative sshd hardening drop-in (Meridian's directive set,
 * verbatim). Written to 00-viper.conf so it sorts first in the
 * sshd_config.d/ load order.
 */
export function renderSshdDropin(): string {
  return (
    "PasswordAuthentication no\n" +
    "KbdInteractiveAuthentication no\n" +
    "ChallengeResponseAuthentication no\n" +
    "DebianBanner no\n"
  );
}

/** BBR persistence (the plan names this file; /etc/sysctl.conf untouched). */
export function renderBbrSysctlConf(): string {
  return "net.core.default_qdisc = fq\nnet.ipv4.tcp_congestion_control = bbr\n";
}

export const AUTO_UPGRADES_PATH = "/etc/apt/apt.conf.d/20auto-upgrades";
export const SSHD_DROPIN_PATH = "/etc/ssh/sshd_config.d/00-viper.conf";
export const BBR_SYCTL_PATH = "/etc/sysctl.d/99-viper.conf";
export const IPV6_SYCTL_PATH = "/etc/sysctl.d/99-viper-ipv6.conf";

/**
 * M8: read both disable_ipv6 sysctls in one round-trip (`sysctl -n` with
 * two keys → one line per key). The plan's single check command.
 */
export const IPV6_SYSCTL_CHECK =
  "sysctl -n net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6";

/** M8: v4-only persistence (D1: kernel-level disable, viper's own drop-in). */
export function renderIpv6DisableConf(): string {
  return "net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\n";
}

/**
 * Neutralize conflicting directives in OTHER drop-ins (cloud-init & co.)
 * so viper's values are authoritative regardless of load order
 * (Meridian's sed-comment loop, ported).
 */
const NEUTRALIZE_DROPINS_CMD =
  "for f in /etc/ssh/sshd_config.d/*.conf; do " +
  `[ "$f" = "${SSHD_DROPIN_PATH}" ] && continue; ` +
  "sed -i -E 's/^[[:space:]]*(PasswordAuthentication|KbdInteractiveAuthentication|ChallengeResponseAuthentication)[[:space:]]/#\\1 /' " +
  '"$f" 2>/dev/null; done';

// ------------------------------------------------------------------- steps

export function tzStep(): Step {
  return {
    name: "Set timezone to UTC",
    run: async (conn): Promise<StepResult> => {
      const check = await conn.run(
        "timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null",
        { timeoutMs: 15_000 },
      );
      if (check.code === 0 && check.stdout.trim() === "UTC") {
        return { status: "ok", detail: "already UTC" };
      }
      const set = await conn.run("timedatectl set-timezone UTC", { timeoutMs: 15_000 });
      if (set.code !== 0) {
        // Fallback: point /etc/localtime directly (Meridian's fallback).
        const fb = await conn.run("ln -sf /usr/share/zoneinfo/UTC /etc/localtime", {
          timeoutMs: 15_000,
        });
        if (fb.code !== 0) {
          return {
            status: "failed",
            detail: `timezone set failed: ${errDetail(fb.stderr || set.stderr)}`,
          };
        }
      }
      return { status: "changed", detail: "timezone set to UTC" };
    },
  };
}

export function autoUpgradesStep(): Step {
  return {
    name: "Enable automatic security updates",
    run: async (conn): Promise<StepResult> => {
      const content = renderAutoUpgradesConf();
      const check = await conn.run(`cat ${AUTO_UPGRADES_PATH} 2>/dev/null`, {
        timeoutMs: 15_000,
      });
      if (check.code === 0 && check.stdout.trim() === content.trim()) {
        return { status: "ok", detail: "already configured" };
      }
      await uploadRendered(conn, content, AUTO_UPGRADES_PATH, "20auto-upgrades");
      const chmod = await conn.run(`chmod 644 ${AUTO_UPGRADES_PATH}`, { timeoutMs: 15_000 });
      if (chmod.code !== 0) {
        return {
          status: "failed",
          detail: `chmod 644 ${AUTO_UPGRADES_PATH} failed: ${errDetail(chmod.stderr)}`,
        };
      }
      return { status: "changed", detail: `${AUTO_UPGRADES_PATH} written` };
    },
  };
}

/**
 * Check `sshd -T` output against viper's required effective settings.
 * Returns null when compliant, else a human-readable mismatch detail.
 * A missing auth directive is a mismatch: the distro default is `yes` for
 * both, so "absent" is not "no".
 */
function effectiveMismatch(stdout: string): string | null {
  const effective = new Map<string, string>();
  for (const line of stdout.split("\n")) {
    const i = line.indexOf(" ");
    if (i > 0) effective.set(line.slice(0, i).toLowerCase(), line.slice(i + 1).trim());
  }
  const required: ReadonlyArray<readonly [string, string]> = [
    ["passwordauthentication", "no"],
    ["kbdinteractiveauthentication", "no"],
  ];
  for (const [key, want] of required) {
    const got = effective.get(key);
    if (got !== want) return `expected ${key} ${want} (found ${got ?? "absent"})`;
  }
  // DebianBanner is a Debian/Ubuntu-specific directive; builds that don't
  // recognize it omit it from sshd -T — skip verification then.
  const banner = effective.get("debianbanner");
  if (banner !== undefined && banner !== "no") {
    return `expected debianbanner no (found ${banner})`;
  }
  return null;
}

export function sshStep(): Step {
  return {
    name: "Harden SSH configuration",
    run: async (conn): Promise<StepResult> => {
      const content = renderSshdDropin();
      const check = await conn.run(`cat ${SSHD_DROPIN_PATH} 2>/dev/null`, { timeoutMs: 15_000 });
      let changed = false;
      let wrote = false;
      if (check.code !== 0 || check.stdout.trim() !== content.trim()) {
        await uploadRendered(conn, content, SSHD_DROPIN_PATH, "00-viper.conf");
        const chmod = await conn.run(`chmod 644 ${SSHD_DROPIN_PATH}`, { timeoutMs: 15_000 });
        if (chmod.code !== 0) {
          return {
            status: "failed",
            detail: `chmod 644 ${SSHD_DROPIN_PATH} failed: ${errDetail(chmod.stderr)}`,
          };
        }
        // rc intentionally ignored: no other drop-ins → the glob stays
        // literal and sed fails silently (2>/dev/null).
        await conn.run(NEUTRALIZE_DROPINS_CMD, { timeoutMs: 15_000 });
        changed = true;
        wrote = true;
      }

      // Validate the config file BEFORE restarting (lockout safety).
      const validate = await conn.run("sshd -t", { timeoutMs: 15_000 });
      if (validate.code !== 0) {
        return { status: "failed", detail: `sshd config validation failed: ${errDetail(validate.stderr)}` };
      }

      // Verify the EFFECTIVE config (drop-ins can override the main
      // file). One `sshd -T` round-trip, checked locally — equivalent to
      // Meridian's per-setting greps.
      const effectiveRes = await conn.run("sshd -T 2>/dev/null", { timeoutMs: 15_000 });
      if (effectiveRes.code !== 0) {
        return { status: "failed", detail: `sshd -T failed: ${errDetail(effectiveRes.stderr)}` };
      }
      let mismatch = effectiveMismatch(effectiveRes.stdout);

      if (mismatch !== null) {
        // A conflicting directive may have appeared in ANOTHER drop-in
        // after viper's last write (cloud-init or a user editing
        // sshd_config.d/). The neutralize loop is idempotent and bounded
        // — it only sed-comments viper's auth directives in
        // sshd_config.d/*.conf (never 00-viper.conf, never the main
        // sshd_config) — so re-run it and re-check before failing.
        await conn.run(NEUTRALIZE_DROPINS_CMD, { timeoutMs: 15_000 });
        const revalidate = await conn.run("sshd -t", { timeoutMs: 15_000 });
        if (revalidate.code !== 0) {
          return {
            status: "failed",
            detail: `sshd config validation failed after neutralize: ${errDetail(revalidate.stderr)}`,
          };
        }
        const recheckRes = await conn.run("sshd -T 2>/dev/null", { timeoutMs: 15_000 });
        if (recheckRes.code === 0) {
          const recheck = effectiveMismatch(recheckRes.stdout);
          if (recheck === null) {
            mismatch = null;
            changed = true; // neutralized a conflicting drop-in → restart
          }
        }
        if (mismatch !== null) {
          return {
            status: "failed",
            detail:
              `effective sshd setting mismatch: ${mismatch} — ` +
              `check /etc/ssh/sshd_config and /etc/ssh/sshd_config.d/ for a ` +
              `conflicting directive outside 00-viper.conf`,
          };
        }
      }

      if (!changed) {
        return { status: "ok", detail: "already hardened" };
      }

      // Service is "sshd" on some distros, "ssh" on others.
      const restart = await conn.run("systemctl restart sshd 2>/dev/null || systemctl restart ssh", {
        timeoutMs: 30_000,
      });
      if (restart.code !== 0) {
        return { status: "failed", detail: `sshd restart failed: ${errDetail(restart.stderr)}` };
      }
      return {
        status: "changed",
        detail: wrote ? "drop-in written, sshd restarted" : "conflicting drop-in neutralized, sshd restarted",
      };
    },
  };
}

export function fail2banStep(): Step {
  return {
    name: "Enable fail2ban",
    run: async (conn): Promise<StepResult> => {
      const active = await conn.run("systemctl is-active fail2ban", { timeoutMs: 15_000 });
      if (active.code === 0 && active.stdout.trim() === "active") {
        return { status: "ok", detail: "already running" };
      }
      const enable = await conn.run("systemctl enable fail2ban", { timeoutMs: 15_000 });
      if (enable.code !== 0) {
        return { status: "failed", detail: `failed to enable fail2ban: ${errDetail(enable.stderr)}` };
      }
      const start = await conn.run("systemctl restart fail2ban", { timeoutMs: 30_000 });
      if (start.code !== 0) {
        return { status: "failed", detail: `failed to start fail2ban: ${errDetail(start.stderr)}` };
      }
      return { status: "changed", detail: "enabled and started" };
    },
  };
}

const BBR_SETTINGS: ReadonlyArray<readonly [string, string]> = [
  ["net.core.default_qdisc", "fq"],
  ["net.ipv4.tcp_congestion_control", "bbr"],
];

/**
 * Availability probes (orchestrator correction, M4): modern kernels use
 * `tcp_available_congestion_control` (singular); older kernels used
 * `tcp_available_congestions`. The module may be unloaded, but the
 * availability list still names bbr when the kernel supports it. The
 * sysctl writes remain the final arbiter (warn-not-fail only when they
 * are genuinely unavailable).
 */
const BBR_AVAILABILITY_KEYS = [
  "net.ipv4.tcp_available_congestion_control",
  "net.ipv4.tcp_available_congestions",
] as const;

export function bbrStep(): Step {
  return {
    name: "Enable BBR congestion control",
    run: async (conn): Promise<StepResult> => {
      const content = renderBbrSysctlConf();
      const cc = await conn.run("sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null", {
        timeoutMs: 15_000,
      });
      if (cc.code === 0 && cc.stdout.trim() === "bbr") {
        const qd = await conn.run("sysctl -n net.core.default_qdisc 2>/dev/null", {
          timeoutMs: 15_000,
        });
        if (qd.code === 0 && qd.stdout.trim() === "fq") {
          // The live sysctls may have been set by a run that died between
          // the `sysctl -w` calls and the SFTP persist — re-check the
          // persist file so BBR survives reboots (a live-only box loses
          // it on the next reboot).
          const persist = await conn.run(`cat ${BBR_SYCTL_PATH} 2>/dev/null`, {
            timeoutMs: 15_000,
          });
          if (persist.code === 0 && persist.stdout.trim() === content.trim()) {
            return { status: "ok", detail: "already enabled" };
          }
          await uploadRendered(conn, content, BBR_SYCTL_PATH, "99-viper.conf");
          return {
            status: "changed",
            detail: `bbr already enabled live, persisted to ${BBR_SYCTL_PATH}`,
          };
        }
      }

      // Probe availability via both key names (either naming bbr is enough).
      let available = false;
      for (const key of BBR_AVAILABILITY_KEYS) {
        const res = await conn.run(`sysctl -n ${key} 2>/dev/null`, { timeoutMs: 15_000 });
        if (res.code === 0 && res.stdout.split(/\s+/).includes("bbr")) {
          available = true;
          break;
        }
      }

      // tcp_bbr is a loadable module on modern kernels; modprobe before the
      // writes. Non-zero exit is fine (module already loaded) — the sysctl
      // writes decide.
      await conn.run("modprobe tcp_bbr 2>/dev/null", { timeoutMs: 15_000 });

      // Live sysctls; the writes are the arbiter of availability.
      for (const [key, value] of BBR_SETTINGS) {
        const res = await conn.run(`sysctl -w ${key}=${value}`, { timeoutMs: 15_000 });
        if (res.code !== 0) {
          const stderr = res.stderr.trim();
          if (stderr.includes("No such file") || stderr.includes("does not exist")) {
            return {
              status: "skipped",
              detail:
                `WARNING: BBR genuinely unavailable here (probe ${
                  available ? "reported bbr" : "found no bbr"
                }; sysctl ${key} missing) ` + "— continuing without BBR",
            };
          }
          return { status: "failed", detail: `sysctl ${key} failed: ${errDetail(res.stderr)}` };
        }
      }

      // Persist to viper's own drop-in (the plan names this file).
      await uploadRendered(conn, renderBbrSysctlConf(), BBR_SYCTL_PATH, "99-viper.conf");
      return { status: "changed", detail: `bbr enabled live, persisted to ${BBR_SYCTL_PATH}` };
    },
  };
}

/**
 * M8 D4 re-enable path (allowIPv6 flipped false→true on a live box):
 * delete viper's disable drop-in, clear both sysctls live, then bounce the
 * primary interface to trigger SLAAC reassignment. SSH rides on that
 * interface → the bounce runs DETACHED (nohup ... &) and the step polls
 * for a global v6 address. No address within the poll window is non-fatal
 * (reboot completes the assignment).
 */
async function reenableIpv6(conn: SshConn, pollOpts: PollOptions | undefined): Promise<StepResult> {
  await conn.run(`rm -f ${IPV6_SYCTL_PATH}`, { timeoutMs: 10_000 });
  for (const scope of ["all", "default"]) {
    const key = `net.ipv6.conf.${scope}.disable_ipv6`;
    const res = await conn.run(`sysctl -w ${key}=0`, { timeoutMs: 15_000 });
    if (res.code !== 0) {
      return { status: "failed", detail: `sysctl -w ${key}=0 failed: ${errDetail(res.stderr)}` };
    }
  }

  // Primary interface from the v4 default route (D4's exact command).
  const ifRes = await conn.run("ip -4 route show default | awk '/default/{print $5;exit}'", {
    timeoutMs: 15_000,
  });
  const ifname = ifRes.code === 0 ? ifRes.stdout.trim() : "";
  if (ifname !== "") {
    // Detached: the down/up drops the SSH session itself.
    await conn.run(
      `nohup sh -c 'sleep 1; ip link set dev ${ifname} down; sleep 2; ip link set dev ${ifname} up' >/tmp/viper-ipv6-rev.log 2>&1 &`,
      { timeoutMs: 15_000 },
    );
  }

  const hasAddr = (out: string): string | undefined => {
    const m = out.trim().match(/^\d+:\s*(\S+):/);
    return m !== null ? (m[1] as string) : undefined;
  };
  const found = await poll(async () => {
    try {
      const res = await conn.run("ip -6 addr show scope global", { timeoutMs: 15_000 });
      return res.code === 0 && res.stdout.trim() !== "";
    } catch {
      return false; // the connection rides on the bouncing interface
    }
  }, pollOpts ?? { attempts: 30, intervalMs: 1000 });
  if (!found) {
    return {
      status: "changed",
      detail: "re-enabled; v6 address not yet assigned (reboot to complete)",
    };
  }
  const addr = await conn.run("ip -6 addr show scope global", { timeoutMs: 15_000 });
  const iface = hasAddr(addr.stdout) ?? "";
  return {
    status: "changed",
    detail: `re-enabled IPv6 (global v6 on ${iface})`,
  };
}

/**
 * M8: `Configure IPv6` — v4-only by default (D1/D2), `allowIPv6: true`
 * opts out (never disables; re-enables if a previous deploy disabled it,
 * D4). Independent of the `harden` gate (own knob, like `bbr`).
 *
 * Disable path: check-then-act — persist file written only on content
 * diff, `sysctl -p` only on change, then a three-part verification
 * (sysctls 1/1, no global v6 address — the kernel purges them —, no v6
 * default route). A second run in the final state issues zero mutations.
 */
export function ipv6Step(opts: { poll?: PollOptions } = {}): Step {
  return {
    name: "Configure IPv6",
    run: async (conn, ctx): Promise<StepResult> => {
      const check = await conn.run(IPV6_SYSCTL_CHECK, { timeoutMs: 15_000 });
      if (check.code !== 0) {
        return { status: "failed", detail: `sysctl check failed: ${errDetail(check.stderr)}` };
      }
      const [all, def] = check.stdout.trim().split(/\s+/);
      const disabled = all === "1" && def === "1";

      if (ctx.config.allowIPv6 === true) {
        if (disabled) return reenableIpv6(conn, opts.poll);
        return { status: "skipped", detail: "allowIPv6: true, v6 left as-is" };
      }
      if (disabled) {
        return { status: "ok", detail: "already v4-only" };
      }

      // Persist to viper's own drop-in (written only when content differs —
      // a run that died between the SFTP persist and the `sysctl -p` is
      // recovered here without a rewrite).
      const persist = await conn.run(`cat ${IPV6_SYCTL_PATH} 2>/dev/null`, { timeoutMs: 15_000 });
      if (!(persist.code === 0 && persist.stdout.trim() === renderIpv6DisableConf().trim())) {
        await uploadRendered(conn, renderIpv6DisableConf(), IPV6_SYCTL_PATH, "99-viper-ipv6.conf");
      }
      const apply = await conn.run(`sysctl -p ${IPV6_SYCTL_PATH}`, { timeoutMs: 30_000 });
      if (apply.code !== 0) {
        return {
          status: "failed",
          detail: `sysctl -p ${IPV6_SYCTL_PATH} failed: ${errDetail(apply.stderr || apply.stdout)}`,
        };
      }

      // Verify the disable actually took hold (apply rc is not the proof).
      const vcheck = await conn.run(IPV6_SYSCTL_CHECK, { timeoutMs: 15_000 });
      const [vall, vdef] = vcheck.code === 0 ? vcheck.stdout.trim().split(/\s+/) : ["?", "?"];
      const gaddr = await conn.run("ip -6 addr show scope global", { timeoutMs: 15_000 });
      const route = await conn.run("ip -6 route show default", { timeoutMs: 15_000 });
      const problems: string[] = [];
      if (vall !== "1" || vdef !== "1") {
        problems.push(`sysctl disable_ipv6 ${vall}/${vdef} (expected 1/1)`);
      }
      if (gaddr.code !== 0) {
        problems.push(`global v6 address check failed: ${errDetail(gaddr.stderr)}`);
      } else if (gaddr.stdout.trim() !== "") {
        problems.push(`global v6 address remains (${errDetail(gaddr.stdout.trim().split("\n")[0] ?? "")})`);
      }
      if (route.code !== 0) {
        problems.push(`v6 default-route check failed: ${errDetail(route.stderr)}`);
      } else if (route.stdout.trim() !== "") {
        problems.push(`v6 default route remains (${errDetail(route.stdout.trim().split("\n")[0] ?? "")})`);
      }
      if (problems.length > 0) {
        return {
          status: "failed",
          detail: `IPv6 disable applied but verification failed: ${problems.join("; ")}`,
        };
      }
      return { status: "changed", detail: "IPv6 disabled (v4-only)" };
    },
  };
}

export function ufwStep(): Step {
  return {
    name: "Configure firewall",
    run: async (conn, ctx): Promise<StepResult> => {
      const which = await conn.run("which ufw 2>/dev/null", { timeoutMs: 15_000 });
      if (which.code !== 0) {
        return {
          status: "failed",
          detail: "ufw not available — the packages step installs it; re-run deploy",
        };
      }

      // Re-detect live sshd ports (StepCtx is fixed — no ctx extension).
      const ports = await detectSshdPorts(conn);
      if (ports.length === 0) {
        return {
          status: "failed",
          detail: "could not detect sshd listen ports (sshd -T) — refusing to configure ufw (lockout risk)",
        };
      }
      // viper-owned ports: detected ssh ports + config.port (VPN) + 80 (ACME).
      const allowPorts: number[] = [];
      for (const p of [...ports, ctx.config.port, 80]) {
        if (!allowPorts.includes(p)) allowPorts.push(p);
      }

      // `ufw status verbose` (NOT plain `ufw status`): plain status on
      // Ubuntu 24.04 omits the "Default:" line (verified live), whose
      // absence made the defaults check fall back and re-issue
      // `ufw default deny incoming` on every idempotent run. The verbose
      // output format was confirmed on the live box and always carries:
      // Status / Logging / Default / New profiles / rule table (incl. v6).
      const status = await conn.run("ufw status verbose", { timeoutMs: 15_000 });
      const active = status.code === 0 && status.stdout.includes("Status: active");
      let changed = false;

      // Rules already present, parsed from the `ufw status` table
      // (lines like "22/tcp                     ALLOW Anywhere") — a
      // second run then issues zero `ufw allow` calls at all.
      const existing = new Set<string>();
      for (const line of status.stdout.split("\n")) {
        const m = line.match(/(\d+\/tcp)/);
        if (m !== null && m[1] !== undefined) existing.add(m[1]);
      }

      // Allow rules BEFORE enable (lockout ordering). Never `ufw limit`.
      for (const p of allowPorts) {
        const rule = `${p}/tcp`;
        if (existing.has(rule)) continue;
        const res = await conn.run(`ufw allow ${p}/tcp`, { timeoutMs: 15_000 });
        if (res.code !== 0) {
          return { status: "failed", detail: `failed to allow port ${p}: ${errDetail(res.stderr)}` };
        }
        if (!res.stdout.includes("Skipping")) changed = true;
      }

      // Current defaults, parsed from the single "Default:" line
      // ("Default: deny (incoming), allow (outgoing), disabled (routed)")
      // so a second run re-issues nothing. Fallback direction is safe:
      // dIn->"allow" re-issues exactly the policy we want (deny incoming
      // is a no-op server-side when already deny); dOut->"allow" never
      // re-issues.
      const defaultLine = status.stdout.split("\n").find((l) => l.startsWith("Default:")) ?? "";
      const dIn = defaultLine.match(/(\w+)\s*\(incoming\)/)?.[1] ?? "allow";
      const dOut = defaultLine.match(/(\w+)\s*\(outgoing\)/)?.[1] ?? "allow";
      if (dIn !== "deny") {
        const denyIn = await conn.run("ufw default deny incoming", { timeoutMs: 15_000 });
        if (denyIn.code !== 0) {
          return {
            status: "failed",
            detail: `ufw default deny incoming failed: ${errDetail(denyIn.stderr)}`,
          };
        }
        changed = true;
      }
      if (dOut !== "allow") {
        const allowOut = await conn.run("ufw default allow outgoing", { timeoutMs: 15_000 });
        if (allowOut.code !== 0) {
          return {
            status: "failed",
            detail: `ufw default allow outgoing failed: ${errDetail(allowOut.stderr)}`,
          };
        }
        changed = true;
      }

      if (!active) {
        const enable = await conn.run("ufw --force enable", { timeoutMs: 30_000 });
        if (enable.code !== 0) {
          return { status: "failed", detail: `ufw enable failed: ${errDetail(enable.stderr)}` };
        }
        changed = true;
      } else if (changed) {
        // Apply rule/policy changes to the running firewall (only when
        // something actually changed — a fully idempotent run re-issues
        // nothing).
        await conn.run("ufw reload", { timeoutMs: 30_000 });
      }

      return changed
        ? { status: "changed", detail: `allowed ${allowPorts.join(", ")} tcp, default deny incoming` }
        : { status: "ok", detail: "already configured" };
    },
  };
}

// ------------------------------------------------------------ step list

/**
 * The ordered M4/M8 step list:
 *   preflight → packages → tz → auto-upgrades → ssh → fail2ban → bbr →
 *   Configure IPv6 → ufw
 *
 * Knob-gated: `harden: false` excludes tz/auto-upgrades/ssh/fail2ban/ufw
 * (not run, not traced); `bbr: false` excludes bbr. The IPv6 step is
 * independent of `harden` (its own knob: `allowIPv6`; M8 D2) and sits
 * after BBR, before the firewall (the network cluster). Preflight and
 * packages always run.
 */
export function hardeningSteps(
  _ctx: StepCtx,
  config: ServerConfig,
  opts: HardeningStepOptions & { poll?: PollOptions } = {},
): Step[] {
  const steps: Step[] = [preflightStep(opts), packagesStep(opts)];
  if (config.harden) {
    steps.push(tzStep(), autoUpgradesStep(), sshStep(), fail2banStep());
  }
  if (config.bbr) {
    steps.push(bbrStep());
  }
  steps.push(ipv6Step(opts));
  if (config.harden) {
    steps.push(ufwStep());
  }
  return steps;
}
