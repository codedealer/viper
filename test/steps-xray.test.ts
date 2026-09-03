import assert from "node:assert/strict";
import { test } from "node:test";
import { xraySteps, xrayTeardownSteps } from "../src/steps/xray.js";

test("xraySteps — ordered install → deploy → verify triple (no ctx/config params)", () => {
  const steps = xraySteps();
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
  const steps = xraySteps({ poll: { attempts: 2, intervalMs: 1 } });
  assert.equal(steps.length, 5);
});

test("xrayTeardownSteps — single teardown step (no ctx param)", () => {
  const steps = xrayTeardownSteps();
  assert.deepEqual(
    steps.map((s) => s.name),
    ["Remove Xray (teardown)"],
  );
});
