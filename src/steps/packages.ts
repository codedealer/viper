/**
 * Packages step (M4) — ensure viper's required packages are installed.
 *
 * check-then-act: one `dpkg-query` pre-check, then a single `apt-get
 * update` + a single `apt-get install` of ONLY the missing packages.
 * Newly-installed packages are recorded in `state.installedPackages`
 * (for teardown, M7+) and persisted through the injected persister.
 * Idempotent: all present → ok, zero mutating calls.
 */
import type { SshConn } from "../ssh.js";
import type { Step, StepResult } from "./runner.js";
import { REQUIRED_PACKAGES, errDetail, type HardeningStepOptions } from "./common.js";

const APT_UPDATE_CMD = "DEBIAN_FRONTEND=noninteractive apt-get update -qq";

export function packagesStep(opts: HardeningStepOptions = {}): Step {
  return {
    name: "Install system packages",
    run: async (conn, ctx): Promise<StepResult> => {
      /**
       * dpkg-query check command. The showformat MUST include `${Package}`:
       * with only `${Status}` each line is just "install ok installed" and
       * the package name is lost (verified on a live Ubuntu 24.04 box) ->
       * the parser below would never recognize anything as installed and
       * would re-install every run.
       */
      const checkCmd =
        "dpkg-query -W --showformat='${Package} ${Status}\\n' " + REQUIRED_PACKAGES.join(" ");
      const check = await conn.run(checkCmd, { timeoutMs: 15_000 });

      // dpkg-query exits non-zero when ANY package is missing (and prints
      // nothing for it), so the rc is ignored: parse the `${Package}
      // ${Status}` lines ("name install ok installed").
      const installed = new Set<string>();
      for (const line of check.stdout.split("\n")) {
        const f = line.trim().split(/\s+/);
        if (f.length >= 4 && f[0] !== undefined && f[1] === "install" && f[3] === "installed") {
          installed.add(f[0]);
        }
      }

      const missing = REQUIRED_PACKAGES.filter((p) => !installed.has(p));
      if (missing.length > 0) {
        const update = await conn.run(APT_UPDATE_CMD, { timeoutMs: 180_000 });
        if (update.code !== 0) {
          const stderr = update.stderr.trim();
          if (stderr.includes("no longer has a Release file")) {
            return {
              status: "failed",
              detail:
                "OS version is end-of-life — package repos have been removed. Reinstall with an Ubuntu LTS version",
            };
          }
          return { status: "failed", detail: `apt-get update failed: ${errDetail(update.stderr)}` };
        }

        const install = await conn.run(
          `DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${missing.join(" ")}`,
          { timeoutMs: 300_000 },
        );
        if (install.code !== 0) {
          return { status: "failed", detail: `apt-get install failed: ${errDetail(install.stderr)}` };
        }
      }

      // Record the full set of required packages present on the host
      // (pre-existing + just installed) for teardown (M7+). A second run
      // finds the set already complete → no persist.
      let recorded = false;
      for (const p of REQUIRED_PACKAGES) {
        if (!ctx.state.installedPackages.includes(p)) {
          ctx.state.installedPackages.push(p);
          recorded = true;
        }
      }
      if (recorded) await opts.persistState?.(ctx.state);

      return missing.length > 0
        ? { status: "changed", detail: `installed ${missing.join(", ")}` }
        : { status: "ok", detail: `all ${REQUIRED_PACKAGES.length} packages present` };
    },
  };
}