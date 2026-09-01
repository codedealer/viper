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
import type { Step, StepCtx } from "./runner.js";
import type { ServerConfig } from "../config.js";
import type { HardeningStepOptions } from "./common.js";
import type { PollOptions } from "./common.js";
import { xrayInstallStep } from "./xray-install.js";
import { xrayDeployStep } from "./xray-deploy.js";
import { xrayUnitActiveStep, xrayListeningStep, xrayHandshakeProbeStep } from "./xray-verify.js";
import { xrayTeardownStep } from "./xray-teardown.js";

export interface XrayStepOptions extends HardeningStepOptions {
  /** Polling knobs for the post-restart / probe waits (tests only). */
  poll?: PollOptions;
}

export function xraySteps(_ctx: StepCtx, _config: ServerConfig, opts: XrayStepOptions = {}): Step[] {
  return [
    xrayInstallStep(opts),
    xrayDeployStep(opts.poll),
    xrayUnitActiveStep(),
    xrayListeningStep(),
    xrayHandshakeProbeStep(opts.poll),
  ];
}

export function xrayTeardownSteps(ctx: StepCtx): Step[] {
  return [xrayTeardownStep()];
}