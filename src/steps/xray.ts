/**
 * M5 step lists.
 *
 * `xraySteps` — the deploy pipeline (called by the M7 `deploy` /
 * `update` commands; live-verified in the M5 scratch harness):
 * install (hard-pinned) → deploy (tmp → -test → mv → restart) →
 * verify (unit active → :443 listening → REALITY handshake probe).
 *
 * `xrayTeardownSteps` — exported for M7's `viper teardown`; NOT
 * executed live in the M5 loop.
 */
import type { Step } from "./runner.js";
import type { HardeningStepOptions, PollOptions } from "./common.js";
import { xrayInstallStep } from "./xray-install.js";
import { xrayDeployStep } from "./xray-deploy.js";
import { xrayUnitActiveStep, xrayListeningStep, xrayHandshakeProbeStep } from "./xray-verify.js";
import { xrayTeardownStep } from "./xray-teardown.js";

export interface XrayStepOptions extends HardeningStepOptions {
  /** Polling knobs for the post-restart / probe waits (tests only). */
  poll?: PollOptions;
}

/** The M5 deploy steps in pipeline order. The steps read everything they
 *  need from the StepCtx at run time, so no ctx/config is passed here. */
export function xraySteps(opts: XrayStepOptions = {}): Step[] {
  return [
    xrayInstallStep(opts),
    xrayDeployStep(opts.poll),
    xrayUnitActiveStep(),
    xrayListeningStep(),
    xrayHandshakeProbeStep(opts.poll),
  ];
}

/** M5 teardown: remove the xray footprint. Nothing is kept (unlike M6's
 *  nginx/acme, where the nginx package and .acme.sh survive). */
export function xrayTeardownSteps(): Step[] {
  return [xrayTeardownStep()];
}