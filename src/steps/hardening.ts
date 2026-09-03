/**
 * Hardening steps (M4) — Meridian's semantics, ported:
 *   tz → auto-upgrades → ssh → fail2ban → bbr → ufw
 *
 * Rules honored throughout:
 *  - check-then-act; a second run in the same final state makes no
 *    mutating calls (the engine may re-execute a command once after a
 *    mid-command socket drop, so idempotency is a correctness
 *    requirement).
 *  - Artifacts travel by SFTP (`uploadRendered`), never heredoc.
 *  - SSH: sshd -t + sshd -T effective-config verification BEFORE any
 *    restart.
 *  - ufw: allow-rules (detected sshd ports + 443 + 80) BEFORE enable;
 *    no `ufw limit 22`; viper owns only its own rules.
 *  - BBR: warn-not-fail (skipped + WARNING) on kernels without the
 *    tunables.
 */
import type { ServerConfig } from "../config.js";
import type { Step, StepCtx, StepResult } from "./runner.js";
import { detectSshdPorts, errDetail, uploadRendered, type HardeningStepOptions } from "./common.js";
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

export function ufwStep(): Step {
  return {
    name: "Configure firewall",
    run: async (conn): Promise<StepResult> => {
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
      // viper-owned ports: detected ssh ports + 443 (VPN) + 80 (ACME).
      const allowPorts: number[] = [];
      for (const p of [...ports, 443, 80]) {
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
 * The ordered M4 step list per the plan:
 *   preflight → packages → tz → auto-upgrades → ssh → fail2ban → bbr → ufw
 *
 * Knob-gated: `harden: false` excludes tz/auto-upgrades/ssh/fail2ban/ufw
 * (not run, not traced); `bbr: false` excludes bbr. Preflight and
 * packages always run.
 */
export function hardeningSteps(_ctx: StepCtx, config: ServerConfig, opts: HardeningStepOptions = {}): Step[] {
  const steps: Step[] = [preflightStep(opts), packagesStep(opts)];
  if (config.harden) {
    steps.push(tzStep(), autoUpgradesStep(), sshStep(), fail2banStep());
  }
  if (config.bbr) {
    steps.push(bbrStep());
  }
  if (config.harden) {
    steps.push(ufwStep());
  }
  return steps;
}
