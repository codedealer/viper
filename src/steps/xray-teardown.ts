/**
 * Xray teardown step (M5 scope; wired into `viper teardown` in M7).
 *
 * Removes everything the install/deploy steps installed: unit (disable +
 * now), binary, geo assets, /etc/xray config, and the logrotate drop-in.
 * Idempotent: nothing present → ok, zero mutating calls.
 *
 * Deliberately does NOT touch:
 *  - /var/log/xray (left in place for forensics; M7 teardown decides)
 *  - nginx in any form (M6's scope — incl. the M5 bootstrap vhost/cert,
 *    which M6's deploy overwrites)
 *  - the `unzip` tool dependency (apt-level, recorded in state for M7)
 *
 * The logrotate drop-in (viper's own /etc/logrotate.d/xray) IS removed:
 * it is a viper artifact and references a log path viper no longer owns
 * once xray is gone. The log files themselves stay (forensics).
 */
import type { Step, StepResult } from "./runner.js";
import { errDetail } from "./common.js";
import { XRAY_BIN, XRAY_GEO_DIR, XRAY_UNIT } from "./xray-install.js";
import { XRAY_CONFIG_PATH } from "./xray-deploy.js";
import { XRAY_LOGROTATE_PATH } from "./xray-logrotate.js";

export function xrayTeardownStep(): Step {
  return {
    name: "Remove Xray (teardown)",
    run: async (conn): Promise<StepResult> => {
      const present = await conn.run(
        `test -f ${XRAY_BIN} || test -f ${XRAY_UNIT} || test -f ${XRAY_CONFIG_PATH} || test -f ${XRAY_LOGROTATE_PATH}`,
        { timeoutMs: 10_000 },
      );
      if (present.code !== 0) {
        return { status: "ok", detail: "xray not present" };
      }

      // Stop first (ignore rc — the unit may already be gone/inactive).
      await conn.run("systemctl disable --now xray 2>/dev/null", { timeoutMs: 30_000 });
      const rmUnit = await conn.run(`rm -f ${XRAY_UNIT}`, { timeoutMs: 10_000 });
      if (rmUnit.code !== 0) {
        return { status: "failed", detail: `removing unit failed: ${errDetail(rmUnit.stderr)}` };
      }
      await conn.run("systemctl daemon-reload", { timeoutMs: 30_000 });

      const rmBin = await conn.run(`rm -f ${XRAY_BIN}`, { timeoutMs: 10_000 });
      if (rmBin.code !== 0) {
        return { status: "failed", detail: `removing binary failed: ${errDetail(rmBin.stderr)}` };
      }
      const rmGeo = await conn.run(`rm -rf ${XRAY_GEO_DIR}`, { timeoutMs: 10_000 });
      if (rmGeo.code !== 0) {
        return { status: "failed", detail: `removing geo assets failed: ${errDetail(rmGeo.stderr)}` };
      }
      const rmConf = await conn.run(`rm -rf /etc/xray`, { timeoutMs: 10_000 });
      if (rmConf.code !== 0) {
        return { status: "failed", detail: `removing config failed: ${errDetail(rmConf.stderr)}` };
      }
      const rmLogrotate = await conn.run(`rm -f ${XRAY_LOGROTATE_PATH}`, { timeoutMs: 10_000 });
      if (rmLogrotate.code !== 0) {
        return {
          status: "failed",
          detail: `removing logrotate drop-in failed: ${errDetail(rmLogrotate.stderr)}`,
        };
      }

      return {
        status: "changed",
        detail: "removed xray unit, binary, geo assets, /etc/xray, logrotate drop-in",
      };
    },
  };
}
