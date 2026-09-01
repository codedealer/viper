import { test } from "node:test";
import assert from "node:assert/strict";
import { deploySteps, updateSteps, teardownSteps } from "../src/pipeline.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";

/** Minimal ctx — composition is pure, steps are not executed here. */
const ctx: StepCtx = {
  name: "main",
  ip: fixtureConfig.ip,
  config: fixtureConfig,
  state: fixtureState,
  artifacts: {},
};

const names = (steps: { name: string }[]) => steps.map((s) => s.name);

const NGINX_STEPS = [
  "Ensure cron service",
  "Install acme.sh",
  "Install acme renewal cron",
  "Deploy ACME vhost (:80)",
  "Issue Let's Encrypt cert",
  "Deploy cert",
  "Deploy page + subscription",
  "Deploy web vhost (:8443)",
  "Verify decoy page (public path)",
  "Verify subscription (public path)",
  "Verify 404 (public path)",
  "Verify Let's Encrypt cert (public path)",
];

const XRAY_DEPLOY_VERIFY = [
  "Deploy Xray configuration",
  "Verify Xray unit active",
  "Verify Xray listening on :443",
  "Verify REALITY handshake (probe)",
];

test("deploySteps: full pipeline order (contract D1)", () => {
  const got = names(deploySteps(ctx, fixtureConfig, {}));
  const expected = [
    "Preflight",
    "Install system packages",
    "Set timezone to UTC",
    "Enable automatic security updates",
    "Harden SSH configuration",
    "Enable fail2ban",
    "Enable BBR congestion control",
    "Configure firewall",
    "Install pinned Xray",
    ...XRAY_DEPLOY_VERIFY,
    ...NGINX_STEPS,
  ];
  assert.deepEqual(got, expected);
});

test("deploySteps: harden:false drops the hardening steps, bbr:false drops bbr", () => {
  const noHarden = names(
    deploySteps(ctx, { ...fixtureConfig, harden: false }, {}),
  );
  for (const dropped of [
    "Set timezone to UTC",
    "Enable automatic security updates",
    "Harden SSH configuration",
    "Enable fail2ban",
    "Configure firewall",
  ]) {
    assert.ok(!noHarden.includes(dropped), `expected ${dropped} dropped`);
  }
  assert.ok(noHarden.includes("Preflight"));
  assert.ok(noHarden.includes("Install system packages"));
  assert.ok(noHarden.includes("Enable BBR congestion control"));

  const noBbr = names(deploySteps(ctx, { ...fixtureConfig, bbr: false }, {}));
  assert.ok(!noBbr.includes("Enable BBR congestion control"));
  assert.ok(noBbr.includes("Configure firewall"));
});

test("updateSteps: xray deploy + verify + nginx only (contract D3)", () => {
  const got = names(updateSteps(ctx, fixtureConfig, {}));
  const expected = [...XRAY_DEPLOY_VERIFY, ...NGINX_STEPS];
  assert.deepEqual(got, expected);
  for (const absent of [
    "Preflight",
    "Install system packages",
    "Install pinned Xray",
    "Harden SSH configuration",
  ]) {
    assert.ok(!got.includes(absent), `update must not run ${absent}`);
  }
});

test("teardownSteps: xray teardown then nginx teardown (contract D6)", () => {
  const got = names(teardownSteps(ctx));
  assert.deepEqual(got, [
    "Remove Xray (teardown)",
    "Remove viper nginx vhosts (teardown)",
    "Remove acme renewal cron (teardown)",
    "Remove viper web files (teardown)",
  ]);
});