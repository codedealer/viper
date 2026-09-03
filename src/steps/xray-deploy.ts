/**
 * Xray deploy step (M5) — deploy the rendered `config.json`.
 *
 * Safe-swap: render → SFTP upload to `/etc/xray/config.new.json` →
 * `xray -test` validates the NEW config → `mv` over the live one →
 * `systemctl restart xray` → poll until active. A bad render therefore
 * never kills a live config (the old file is untouched until the new
 * one has passed `-test`).
 *
 * The staged file MUST end in `.json`: Xray infers the config format
 * from the file extension, and an unrecognized suffix makes `xray -test`
 * fail with "Failed to get format of …" even for a valid config
 * (verified live on the pinned v26.3.27 binary).
 *
 * Idempotent: current `/etc/xray/config.json` already identical to the
 * render → ok, zero mutating calls (no upload, no restart).
 */
import type { Step, StepResult } from "./runner.js";
import { poll, uploadRendered, errDetail } from "./common.js";
import type { PollOptions } from "./common.js";
import { renderXray } from "../render/xray.js";

export const XRAY_CONFIG_PATH = "/etc/xray/config.json";
export const XRAY_CONFIG_TMP = "/etc/xray/config.new.json";
/** Staged-file name used by viper builds before the .json-suffix fix —
 *  removed opportunistically in case a failed run left one behind. */
const XRAY_CONFIG_LEGACY_TMP = "/etc/xray/config.json.tmp";
const XRAY_LOG_DIR = "/var/log/xray";

export function xrayDeployStep(pollOpts: PollOptions = {}): Step {
  return {
    name: "Deploy Xray configuration",
    run: async (conn, ctx): Promise<StepResult> => {
      const rendered = renderXray(ctx.config, ctx.state);

      const current = await conn.run(`cat ${XRAY_CONFIG_PATH} 2>/dev/null`, {
        timeoutMs: 15_000,
      });
      if (current.stdout === rendered) {
        return { status: "ok", detail: "config unchanged" };
      }

      await conn.run(`mkdir -p ${XRAY_LOG_DIR}`, { timeoutMs: 10_000 });
      // Remove a stale staged file left by a failed run of the old
      // (non-.json) staged name — cleanup belongs to the deploy step.
      await conn.run(`rm -f ${XRAY_CONFIG_LEGACY_TMP}`, { timeoutMs: 10_000 });
      await uploadRendered(conn, rendered, XRAY_CONFIG_TMP, "config.new.json");

      // Validate the NEW config before touching the live one.
      const test = await conn.run(`cd /usr/local/share/xray && xray -test -c ${XRAY_CONFIG_TMP}`, {
        timeoutMs: 60_000,
      });
      if (test.code !== 0) {
        await conn.run(`rm -f ${XRAY_CONFIG_TMP}`, { timeoutMs: 10_000 });
        // xray logs config errors to stdout (not stderr) — include both.
        const detail = [test.stdout.trim(), test.stderr.trim()].filter(Boolean).join(" | ");
        return {
          status: "failed",
          detail: `xray -test rejected the new config (live config untouched): ${errDetail(detail)}`,
        };
      }

      const mv = await conn.run(`mv ${XRAY_CONFIG_TMP} ${XRAY_CONFIG_PATH}`, { timeoutMs: 10_000 });
      if (mv.code !== 0) {
        await conn.run(`rm -f ${XRAY_CONFIG_TMP}`, { timeoutMs: 10_000 });
        return { status: "failed", detail: `moving config into place failed: ${errDetail(mv.stderr)}` };
      }

      const restart = await conn.run("systemctl restart xray", { timeoutMs: 30_000 });
      if (restart.code !== 0) {
        return { status: "failed", detail: `systemctl restart xray failed: ${errDetail(restart.stderr)}` };
      }

      const active = await poll(
        async () =>
          (await conn.run("systemctl is-active xray", { timeoutMs: 10_000 })).stdout.trim() === "active",
        pollOpts,
      );
      if (!active) {
        return { status: "failed", detail: "xray did not become active after restart" };
      }
      return { status: "changed", detail: "config deployed, xray restarted" };
    },
  };
}
