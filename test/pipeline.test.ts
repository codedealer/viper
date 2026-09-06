import { test } from "node:test";
import assert from "node:assert/strict";
import { deploySteps, updateSteps, teardownSteps } from "../src/pipeline.js";
import { runSteps } from "../src/steps/runner.js";
import { ACME_CRON_CMD } from "../src/steps/nginx.js";
import { FakeRemote } from "./fake-remote.js";
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
  // M8 D3: first step of the nginx group (unconditional, both pipelines).
  "Remove stock nginx default site",
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
  // The logrotate drop-in is a config artifact that must exist on live
  // boxes after `update` too, so it rides in both pipelines here.
  "Configure xray log rotation",
  "Verify Xray unit active",
  "Verify Xray listening on VPN port",
];

/**
 * The REALITY handshake probe runs AFTER the nginx steps: the deployed
 * server borrows its Reality cert from the :8443 web vhost live per
 * handshake, and on a fresh box the vhost + cert only exist once the
 * nginx steps have run (the M5 xray-triple order fails on fresh boxes).
 */
const HANDSHAKE_PROBE = "Verify REALITY handshake (probe)";

/** M9: the public-path probe is the LAST step of both deploy and update. */
const PUBLIC_VERIFY = "Verify public reachability (local probe)";

test("deploySteps: full pipeline order (contract D1) — 29 steps (26 pre-M8)", () => {
  const got = names(deploySteps(ctx, fixtureConfig, {}));
  const expected = [
    "Preflight",
    "Install system packages",
    "Set timezone to UTC",
    "Enable automatic security updates",
    "Harden SSH configuration",
    "Enable fail2ban",
    "Enable BBR congestion control",
    // M8: the network cluster — ipv6 after BBR, before the firewall.
    "Configure IPv6",
    "Configure firewall",
    "Install pinned Xray",
    ...XRAY_DEPLOY_VERIFY,
    ...NGINX_STEPS,
    HANDSHAKE_PROBE,
    PUBLIC_VERIFY,
  ];
  assert.deepEqual(got, expected);
  assert.equal(got.length, 29, "deploy grew 26 -> 29 steps (M8 + log rotation)");
});

test("deploySteps: harden:false drops the hardening steps, bbr:false drops bbr", () => {
  const noHarden = names(deploySteps(ctx, { ...fixtureConfig, harden: false }, {}));
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
  // M8: the IPv6 step is independent of the `harden` gate.
  assert.ok(noHarden.includes("Configure IPv6"));

  const noBbr = names(deploySteps(ctx, { ...fixtureConfig, bbr: false }, {}));
  assert.ok(!noBbr.includes("Enable BBR congestion control"));
  assert.ok(noBbr.includes("Configure IPv6"));
  assert.ok(
    noBbr.indexOf("Configure IPv6") < noBbr.indexOf("Configure firewall"),
    "ipv6 stays before the firewall without bbr",
  );
});

test("updateSteps: xray deploy + verify + nginx + handshake probe + public verify (contract D3)", () => {
  const got = names(updateSteps(ctx, fixtureConfig, {}));
  // M8 D5: update order unchanged — the IPv6 step is deploy-only; the
  // new nginx-group step (default-site removal, D3) rides with the nginx
  // group in both pipelines.
  const expected = [...XRAY_DEPLOY_VERIFY, ...NGINX_STEPS, HANDSHAKE_PROBE, PUBLIC_VERIFY];
  assert.deepEqual(got, expected);
  for (const absent of [
    "Preflight",
    "Install system packages",
    "Install pinned Xray",
    "Harden SSH configuration",
    "Configure IPv6",
  ]) {
    assert.ok(!got.includes(absent), `update must not run ${absent}`);
  }
});

test("deploySteps/updateSteps: skipPublicVerify keeps the wiring (step reports skipped, M9)", () => {
  const deploy = names(deploySteps(ctx, fixtureConfig, { skipPublicVerify: true }));
  const update = names(updateSteps(ctx, fixtureConfig, { skipPublicVerify: true }));
  // The step stays in both pipelines (last) — the skip is a STATUS, not
  // an un-wire, so the runner renders `– name (skipped: …)` (decision 8).
  assert.equal(deploy[deploy.length - 1], PUBLIC_VERIFY);
  assert.equal(update[update.length - 1], PUBLIC_VERIFY);
  assert.deepEqual(deploy, names(deploySteps(ctx, fixtureConfig, {})));
  assert.deepEqual(update, names(updateSteps(ctx, fixtureConfig, {})));
});

test("teardownSteps: xray teardown then nginx teardown (contract D6)", () => {
  const got = names(teardownSteps());
  assert.deepEqual(got, [
    "Remove Xray (teardown)",
    "Remove viper nginx vhosts (teardown)",
    "Remove acme renewal cron (teardown)",
    "Remove viper web files (teardown)",
  ]);
});

// ------------------------------------------------- R11.3: full run-twice

const ACME_SH = "/root/.acme.sh/acme.sh";
const DOMAIN = fixtureConfig.domain;

/**
 * Full pipeline execution (not just composition): run the WHOLE
 * `deploySteps` list twice against a stateful FakeRemote. Run 1 changes
 * the box; run 2 must be idempotent — the only mutations allowed are the
 * probe's own kill/rm and the two documented always-runners (acme-cron
 * D3, install-cert D4).
 */
test("deploySteps: full pipeline run twice — run 2 idempotent (R11.3)", async () => {
  const remote = new FakeRemote({ listeningPorts: [443] });
  const c: StepCtx = {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
  };

  const report1 = await runSteps(
    deploySteps(c, fixtureConfig, {
      heroBase64: "aGVsbG8=",
      dnsResolver: async () => [fixtureConfig.ip],
      // The public probe dials the network — skipped in the unit test
      // (its behavior is covered by test/steps-public-verify.test.ts).
      skipPublicVerify: true,
    }),
    remote,
    c,
    {
      quiet: true,
    },
  );
  assert.equal(report1.failed, false, `run 1 failed: ${JSON.stringify(report1.results)}`);

  const mutBefore = remote.mutatingCommands().length;
  const cmdBefore = remote.commands.length;
  const report2 = await runSteps(
    deploySteps(c, fixtureConfig, {
      heroBase64: "aGVsbG8=",
      dnsResolver: async () => [fixtureConfig.ip],
      skipPublicVerify: true,
    }),
    remote,
    c,
    { quiet: true },
  );
  assert.equal(report2.failed, false, `run 2 failed: ${JSON.stringify(report2.results)}`);

  // Run 2's mutating surface is exactly: the two always-runners
  // (acme-cron D3, install-cert D4) + the probe reap/teardown — now the
  // probe runs AFTER the nginx steps (fresh-deploy ordering fix).
  const expectedRun2Mutations = [
    ACME_CRON_CMD,
    `${ACME_SH} --issue -d ${DOMAIN} --server letsencrypt --webroot /var/www/acme --keylength 2048 2>&1`,
    `${ACME_SH} --install-cert -d ${DOMAIN} --key-file /etc/nginx/ssl/${DOMAIN}/privkey.pem --fullchain-file /etc/nginx/ssl/${DOMAIN}/fullchain.pem --reloadcmd "systemctl reload nginx" 2>&1`,
    "pkill -f 'xray run -c /tmp/viper-probe/[c]onfig.json' 2>/dev/null || true",
    "kill 12345 2>/dev/null",
    "rm -rf /tmp/viper-probe",
  ];
  assert.deepEqual(remote.mutatingCommands().slice(mutBefore), expectedRun2Mutations);

  // No hardening re-mutations on the idempotent run.
  const run2 = remote.commands.slice(cmdBefore);
  assert.ok(!run2.some((x) => x.startsWith("systemctl restart sshd")), "no sshd restart");
  assert.ok(!run2.some((x) => x.startsWith("sysctl -w")), "no sysctl re-apply");
  assert.ok(
    !run2.some(
      (x) => x.startsWith("ufw allow ") || x.startsWith("ufw default ") || x === "ufw --force enable",
    ),
    "no ufw re-mutations",
  );
  assert.ok(!run2.some((x) => x === "systemctl restart xray"), "no xray restart");
  assert.ok(!run2.some((x) => x.includes("apt-get ")), "no apt activity");
});

// ------------------------------------------- M3: full-pipeline M8 idempotency

/**
 * M3: the strongest idempotency net — run the FULL 29-step `deploySteps`
 * pipeline twice on a stateful FakeRemote (run 1: a fresh box, i.e. v6
 * enabled + stock default site present) and assert run 2 contributes
 * ZERO M8 mutations: no `sysctl -p`/`-w`, no drop-in removal, no
 * interface bounce, no default-site removal, and no deploy-artifact
 * SFTP re-uploads (the probe's own sandbox config is the one exempt
 * upload, matching R11.3's probe allowlist). (R11.3 above pins the full
 * run-2 mutation list; this test adds the M8-specific status pins and
 * the upload freeze R11.3 lacks.)
 */
test("deploySteps: full 29-step pipeline twice — run 2 contributes zero M8 mutations (M3)", async () => {
  const remote = new FakeRemote({ listeningPorts: [443] });
  const c: StepCtx = {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
  };
  const opts = {
    heroBase64: "aGVsbG8=",
    dnsResolver: async () => [fixtureConfig.ip],
    skipPublicVerify: true,
  };

  const report1 = await runSteps(deploySteps(c, fixtureConfig, opts), remote, c, { quiet: true });
  assert.equal(report1.failed, false, `run 1 failed: ${JSON.stringify(report1.results)}`);
  assert.equal(report1.results.length, 29, "all 29 deploy steps ran");
  const byName1 = new Map(report1.results.map((r) => [r.name, r.status]));
  // Fresh box: both M8 steps must actually do work in run 1.
  assert.equal(byName1.get("Configure IPv6"), "changed");
  assert.equal(byName1.get("Remove stock nginx default site"), "changed");

  const upBefore = remote.uploads.length;
  const cmdBefore = remote.commands.length;
  const report2 = await runSteps(deploySteps(c, fixtureConfig, opts), remote, c, { quiet: true });
  assert.equal(report2.failed, false, `run 2 failed: ${JSON.stringify(report2.results)}`);
  const byName2 = new Map(report2.results.map((r) => [r.name, r.status]));
  assert.equal(byName2.get("Configure IPv6"), "ok");
  assert.equal(byName2.get("Remove stock nginx default site"), "ok");

  // Run 2 contributes zero M8 mutations.
  const run2 = remote.commands.slice(cmdBefore);
  assert.ok(!run2.some((x) => x.startsWith("sysctl -p ")), "no sysctl -p re-apply");
  assert.ok(!run2.some((x) => x.startsWith("sysctl -w ")), "no sysctl -w (re-enable) on run 2");
  assert.ok(!run2.includes("rm -f /etc/sysctl.d/99-viper-ipv6.conf"), "no drop-in removal");
  assert.ok(!run2.some((x) => x.startsWith("nohup sh -c 'sleep 1; ip link set dev ")), "no interface bounce");
  assert.ok(!run2.includes("rm /etc/nginx/sites-enabled/default"), "no default-site removal");
  // (the `test -e … || test -L …` presence check is read-only — the rm
  // above is the only default-site mutation, and it is pinned absent.)
  // No deploy-artifact re-uploads in run 2 (ipv6 drop-in, xray
  // config/unit, nginx confs, page, subscription). The ONLY upload run 2
  // is entitled to is the probe's own sandbox config — the probe's
  // per-run reap/teardown is already pinned in R11.3's allowlist.
  const extraUploads = remote.uploads.slice(upBefore).map((u) => u.remote);
  assert.deepEqual(
    extraUploads,
    ["/tmp/viper-probe/config.json"],
    "only the probe's own sandbox config is re-written",
  );
});
