/**
 * M7 pipeline composition — wires the already-reviewed M4/M5/M6 step
 * modules into the CLI commands (contract D1/D3/D6). No step semantics
 * are changed here; the lists below are the single wiring source and
 * are unit-tested so wiring regressions are caught without a server.
 *
 *  - `deploySteps` — fresh VPS, full pipeline:
 *      preflight → packages → hardening (knob-gated) →
 *      xray install → xray deploy → xray verify → nginx (12 M6 steps)
 *    Idempotent by construction (every step is check-then-act except the
 *    two documented always-runners), so re-running `deploy` on a live
 *    server is safe.
 *  - `updateSteps` — no-disruption redeploy: xray deploy + verify (NO
 *    preflight/packages/hardening/xray-install) + nginx steps.
 *    cert-issue returns rc-2 skip on a healthy server → zero LE budget.
 *  - `teardownSteps` — M5 xray teardown + M6 nginx teardown.
 */
import type { Step, StepCtx } from "./steps/runner.js";
import type { ServerConfig } from "./config.js";
import { hardeningSteps } from "./steps/hardening.js";
import { xraySteps, xrayTeardownSteps } from "./steps/xray.js";
import { xrayDeployStep } from "./steps/xray-deploy.js";
import { xrayUnitActiveStep, xrayListeningStep, xrayHandshakeProbeStep } from "./steps/xray-verify.js";
import { nginxSteps, nginxTeardownSteps, type NginxStepOptions } from "./steps/nginx.js";
import type { PollOptions } from "./steps/common.js";
/**
 * Options shared by all composed pipelines: the M6 hero seam, the M4 DNS
 * + state-persister seams, and the M5 polling knobs.
 */
export interface PipelineStepOptions extends NginxStepOptions {
  poll?: PollOptions;
}

/** Full fresh-VPS pipeline (contract D1, order as listed there). */
export function deploySteps(ctx: StepCtx, config: ServerConfig, opts: PipelineStepOptions = {}): Step[] {
  return [...hardeningSteps(ctx, config, opts), ...xraySteps(opts), ...nginxSteps(ctx, config, opts)];
}

/**
 * No-disruption redeploy (contract D3): re-rendered artifacts are already
 * in ctx.artifacts; the xray config swap stays validate-before-swap and
 * the nginx changes stay `nginx -t`-gated (step-internal behavior).
 */
export function updateSteps(ctx: StepCtx, config: ServerConfig, opts: PipelineStepOptions = {}): Step[] {
  return [
    xrayDeployStep(opts.poll),
    xrayUnitActiveStep(),
    xrayListeningStep(),
    xrayHandshakeProbeStep(opts.poll),
    ...nginxSteps(ctx, config, opts),
  ];
}

/**
 * Teardown (contract D6): xray (unit/binary/config) then nginx
 * (vhosts, acme cron, web files). Idempotent; the local state file is
 * deliberately NOT deleted (re-deploy stays possible).
 */
export function teardownSteps(): Step[] {
  return [...xrayTeardownSteps(), ...nginxTeardownSteps()];
}
