import assert from "node:assert/strict";
import { test } from "node:test";
import { xraySteps, xrayTeardownSteps } from "../src/steps/xray.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
  };
}

test("xraySteps — ordered install → deploy → verify triple", () => {
  const steps = xraySteps(ctx(), fixtureConfig);
  assert.deepEqual(
    steps.map((s) => s.name),
    [
      "Install pinned Xray",
      "Deploy Xray configuration",
      "Verify Xray unit active",
      "Verify Xray listening on :443",
      "Verify REALITY handshake (probe)",
    ],
  );
});

test("xraySteps — honors opts (no throw with poll overrides)", () => {
  const steps = xraySteps(ctx(), fixtureConfig, { poll: { attempts: 2, intervalMs: 1 } });
  assert.equal(steps.length, 5);
});

test("xrayTeardownSteps — single teardown step", () => {
  const steps = xrayTeardownSteps(ctx());
  assert.deepEqual(
    steps.map((s) => s.name),
    ["Remove Xray (teardown)"],
  );
});