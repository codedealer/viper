/**
 * Xray log rotation step — viper-managed logrotate drop-in for
 * `/var/log/xray/*.log`.
 *
 * Xray opens its access/error log files once at startup and holds the fds
 * open for the life of the process; it does not reopen logs on SIGHUP.
 * With logrotate's default rename+create strategy the running process
 * would keep writing into the renamed (now rotated) file while the new
 * file stayed empty until the next restart. `copytruncate` (copy, then
 * truncate in place) leaves xray's fd valid, so rotation works without a
 * restart. (The fd-holding behavior is well established for v2fly/Xray;
 * see the implementation report for verification status.)
 *
 * Follows the M4 hardening drop-in discipline (bbr/ssh/ipv6 precedent):
 *  - check-then-act: the drop-in already matches → ok, zero mutations.
 *  - artifact travels by SFTP (`uploadRendered`), never heredoc.
 *  - after a (re)write, `logrotate -d` (dry-run/debug) validates the
 *    drop-in's syntax NON-MUTATIVELY; a config error fails the step with
 *    stderr detail.
 *  - clear status strings.
 */
import type { Step, StepResult } from "./runner.js";
import { errDetail, uploadRendered } from "./common.js";

/** viper's logrotate drop-in. Named `xray` (xray owns the logs it rotates);
 *  there is no stock `/etc/logrotate.d/xray` on Ubuntu to collide with. */
export const XRAY_LOGROTATE_PATH = "/etc/logrotate.d/xray";

/** Render the logrotate drop-in (pure function, golden-tested). */
export function renderXrayLogrotateDropin(): string {
  return (
    "/var/log/xray/*.log {\n" +
    "    daily\n" +
    "    rotate 14\n" +
    "    compress\n" +
    "    delaycompress\n" +
    "    missingok\n" +
    "    notifempty\n" +
    "    copytruncate\n" +
    "}\n"
  );
}

export function xrayLogrotateStep(): Step {
  return {
    name: "Configure xray log rotation",
    run: async (conn): Promise<StepResult> => {
      const content = renderXrayLogrotateDropin();
      const check = await conn.run(`cat ${XRAY_LOGROTATE_PATH} 2>/dev/null`, {
        timeoutMs: 15_000,
      });
      if (check.code === 0 && check.stdout.trim() === content.trim()) {
        return { status: "ok", detail: "already configured" };
      }

      await uploadRendered(conn, content, XRAY_LOGROTATE_PATH, "xray");
      const chmod = await conn.run(`chmod 644 ${XRAY_LOGROTATE_PATH}`, { timeoutMs: 15_000 });
      if (chmod.code !== 0) {
        return {
          status: "failed",
          detail: `chmod 644 ${XRAY_LOGROTATE_PATH} failed: ${errDetail(chmod.stderr)}`,
        };
      }

      // Non-mutating syntax check: `logrotate -d` (dry-run/debug) parses the
      // drop-in without rotating anything. A config error → non-zero rc.
      const validate = await conn.run(`logrotate -d ${XRAY_LOGROTATE_PATH}`, { timeoutMs: 30_000 });
      if (validate.code !== 0) {
        const detail = [validate.stderr.trim(), validate.stdout.trim()].filter(Boolean).join(" | ");
        return { status: "failed", detail: `logrotate -d rejected the drop-in: ${errDetail(detail)}` };
      }
      return { status: "changed", detail: `${XRAY_LOGROTATE_PATH} written (copytruncate, 14 days)` };
    },
  };
}
