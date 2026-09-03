import assert from "node:assert/strict";
import { test } from "node:test";
import {
  nginxSteps,
  nginxTeardownSteps,
  ensureCronStep,
  acmeInstallStep,
  acmeCronStep,
  acmeVhostStep,
  certIssueStep,
  certDeployStep,
  pageDeployStep,
  webVhostStep,
  verifyPageStep,
  verifySubStep,
  verify404Step,
  verifyCertStep,
  ACME_CRON_CMD,
} from "../src/steps/nginx.js";
import { renderNginx } from "../src/render/nginx.js";
import { renderPage, PAGE_MARKER } from "../src/render/page.js";
import { renderSub } from "../src/render/sub.js";
import { runSteps, type StepCtx } from "../src/steps/runner.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";

/** Small, deterministic hero stand-in (tests never touch the real asset). */
const HERO = "aGVsbG8=";

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
  };
}

const stepOpts = () => ({ heroBase64: HERO });

/** Run the full deploy pipeline on the given remote; returns the report. */
async function deploy(remote: FakeRemote, c: StepCtx = ctx()) {
  const report = await runSteps(nginxSteps(c, c.config, stepOpts()), remote, c, { quiet: true });
  assert.equal(report.failed, false, `pipeline failed: ${JSON.stringify(report.results)}`);
  return report;
}

// ------------------------------------------------------------------ cron

test("ensure-cron: installed and active — ok, zero mutating calls", async () => {
  const remote = new FakeRemote();
  const res = await ensureCronStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.equal(remote.mutatingCommands().length, 0);
  assert.ok(!remote.commands.includes("systemctl enable --now cron"));
});

test("ensure-cron: service inactive — enable --now", async () => {
  const remote = new FakeRemote({ cronServiceActive: false });
  const res = await ensureCronStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("systemctl enable --now cron"));
});

test("ensure-cron: package missing — apt install cron", async () => {
  const remote = new FakeRemote({ cronInstalled: false, cronServiceActive: false });
  const res = await ensureCronStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cron"));
  assert.ok(remote.commands.includes("DEBIAN_FRONTEND=noninteractive apt-get update -qq"));
});

test("ensure-cron: apt install fails — failed", async () => {
  const remote = new FakeRemote({ cronInstalled: false, aptInstallFails: "E: Unable to fetch" });
  const res = await ensureCronStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /apt-get install cron failed/);
});

test("ensure-cron: enable fails — failed", async () => {
  const remote = new FakeRemote({ cronServiceActive: false, cronEnableFails: true });
  const res = await ensureCronStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /enabling cron failed/);
});

// ------------------------------------------------------------ acme.sh

test("acme-install: fresh — installer runs (no email arg)", async () => {
  const remote = new FakeRemote();
  const res = await acmeInstallStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("curl -fsSL https://get.acme.sh | sh -s --"));
  assert.ok(!remote.commands.some((c) => c.includes("email=")), "no email arg (the installer crashes on it)");
});

test("acme-install: already installed — ok, zero mutating calls", async () => {
  const remote = new FakeRemote({ acmeInstalled: true });
  const res = await acmeInstallStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.equal(remote.mutatingCommands().length, 0);
});

test("acme-install: installer fails — failed", async () => {
  const remote = new FakeRemote({ acmeInstallFails: "curl: (22) 404" });
  const res = await acmeInstallStep().run(remote, ctx());
  assert.equal(res.status, "failed");
});

test("acme-install: installer reports success but leaves no file — failed", async () => {
  const remote = new FakeRemote({ acmeInstallLeavesNoFile: true });
  const res = await acmeInstallStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /is missing/);
});

test("acme-cron: always re-installs (D3)", async () => {
  const remote = new FakeRemote({ acmeInstalled: true });
  const first = await acmeCronStep().run(remote, ctx());
  const second = await acmeCronStep().run(remote, ctx());
  assert.equal(first.status, "changed");
  assert.equal(second.status, "changed", "always changed, even on re-run");
  assert.equal(
    remote.commands.filter((c) => c === ACME_CRON_CMD).length,
    2,
    "--install-cronjob re-runs every deploy",
  );
});

test("acme-cron: fails — failed", async () => {
  const remote = new FakeRemote({ acmeInstalled: true, acmeCronFails: "no crontab" });
  const res = await acmeCronStep().run(remote, ctx());
  assert.equal(res.status, "failed");
});

test("acme-cron: acme.sh missing — failed (not a silent ok)", async () => {
  const remote = new FakeRemote();
  const res = await acmeCronStep().run(remote, ctx());
  assert.equal(res.status, "failed");
});

// -------------------------------------------------------------- vhosts

test("acme-vhost: fresh — upload → symlink → nginx -t → reload", async () => {
  const remote = new FakeRemote();
  const rendered = renderNginx(fixtureConfig, fixtureState)["nginx-80.conf"];
  const res = await acmeVhostStep(rendered).run(remote, ctx());
  assert.equal(res.status, "changed");

  const upload = remote.uploads.find((u) => u.remote === "/etc/nginx/sites-available/viper-acme.conf");
  assert.equal(upload?.content, rendered);
  const cmds = remote.commands;
  const idx = (frag: string) => cmds.findIndex((c) => c.includes(frag));
  assert.ok(
    idx("ln -sf /etc/nginx/sites-available/viper-acme.conf") >
      idx("cat /etc/nginx/sites-available/viper-acme.conf"),
  );
  assert.ok(idx("nginx -t") > idx("ln -sf"));
  assert.ok(idx("systemctl reload nginx") > idx("nginx -t"), "reload only after a passing nginx -t");
});

test("acme-vhost: unchanged — ok, zero mutating calls", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const rendered = renderNginx(fixtureConfig, fixtureState)["nginx-80.conf"];
  const before = remote.nginxReloadCount;
  const res = await acmeVhostStep(rendered).run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.equal(remote.nginxReloadCount, before, "no reload when unchanged");
});

test("acme-vhost: nginx -t rejects — failed, no reload", async () => {
  const remote = new FakeRemote({
    nginxTestFails: "nginx: [emerg] unexpected end of file, expecting }",
  });
  const rendered = renderNginx(fixtureConfig, fixtureState)["nginx-80.conf"];
  const res = await acmeVhostStep(rendered).run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /nginx -t rejected/);
  assert.equal(remote.nginxReloadCount, 0);
});

test("web-vhost: fresh — replaces the bootstrap file in place", async () => {
  const remote = new FakeRemote();
  remote.files.set("/etc/nginx/sites-available/viper-web.conf", "bootstrap self-signed vhost\n");
  remote.symlinksForTest().add("/etc/nginx/sites-enabled/viper-web.conf");
  const rendered = renderNginx(fixtureConfig, fixtureState)["nginx-8443.conf"];
  const res = await webVhostStep(rendered).run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.equal(remote.files.get("/etc/nginx/sites-available/viper-web.conf"), rendered);
});

// ------------------------------------------------------- cert issue/deploy

test("cert-issue: fresh — issued (changed), D1/A3 flags present", async () => {
  const remote = new FakeRemote({ acmeInstalled: true });
  const res = await certIssueStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  const issue = remote.commands.find((c) => c.includes("acme.sh --issue -d "));
  assert.ok(issue !== undefined);
  assert.match(issue ?? "", /--webroot \/var\/www\/acme/);
  assert.match(issue ?? "", /--keylength 2048/);
  // A3: LE is pinned explicitly — current acme.sh defaults to ZeroSSL.
  assert.match(issue ?? "", /--server letsencrypt/);
  assert.ok(!/ --server (?!letsencrypt)/.test(issue ?? ""), "exactly one --server flag");
});

test("cert-issue: existing cert still valid (rc 2) — ok, skip", async () => {
  const remote = new FakeRemote({ acmeInstalled: true, certIssued: true });
  const res = await certIssueStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /cert valid, skip/);
});

test("cert-issue: rc not 0/2 — failed (D2: stop the line)", async () => {
  const remote = new FakeRemote({ acmeInstalled: true, acmeIssueRc: 3 });
  const res = await certIssueStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /issuance failed \(rc 3\)/);
});

test("cert-deploy: fresh — install-cert + reload (md5 changed)", async () => {
  const remote = new FakeRemote({ acmeInstalled: true, certIssued: true });
  const res = await certDeployStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  const install = remote.commands.find((c) => c.includes("acme.sh --install-cert -d "));
  assert.ok(install !== undefined);
  assert.match(install ?? "", /--key-file \/etc\/nginx\/ssl\/vpn\.example\.com\/privkey\.pem/);
  assert.match(install ?? "", /--fullchain-file \/etc\/nginx\/ssl\/vpn\.example\.com\/fullchain\.pem/);
  assert.match(install ?? "", /--reloadcmd "systemctl reload nginx"/);
  assert.equal(remote.nginxReloadCount, 1);
});

test("cert-deploy: unchanged md5 — ok, NO reload (D4)", async () => {
  const remote = new FakeRemote({ acmeInstalled: true, certIssued: true });
  await certDeployStep().run(remote, ctx());
  const before = remote.nginxReloadCount;
  const res = await certDeployStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /unchanged/);
  assert.equal(remote.nginxReloadCount, before, "no reload when the cert md5 is unchanged");
  // install-cert still re-runs (D4: handles the hook-not-registered edge).
  assert.equal(remote.commands.filter((c) => c.includes("acme.sh --install-cert -d ")).length, 2);
});

test("cert-deploy: install-cert fails — failed", async () => {
  const remote = new FakeRemote({
    acmeInstalled: true,
    certIssued: true,
    installCertFails: "Can not find the cert for this domain",
  });
  const res = await certDeployStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /cert install failed/);
  assert.equal(remote.nginxReloadCount, 0);
});

// ----------------------------------------------------------- page deploy

test("page-deploy: fresh — uploads renderPage + renderSub base64", async () => {
  const remote = new FakeRemote();
  const res = await pageDeployStep(stepOpts()).run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.equal(remote.files.get("/var/www/viper/main/index.html"), renderPage(HERO));
  assert.equal(
    remote.files.get("/var/www/viper/main/sub.txt"),
    renderSub(fixtureConfig, fixtureState).base64,
  );
});

test("page-deploy: unchanged — ok, zero uploads", async () => {
  const remote = new FakeRemote();
  await pageDeployStep(stepOpts()).run(remote, ctx());
  const uploads = remote.uploads.length;
  const res = await pageDeployStep(stepOpts()).run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.equal(remote.uploads.length, uploads, "no re-upload when md5 matches");
});

test("page-deploy: no hero seam — failed", async () => {
  const remote = new FakeRemote();
  const res = await pageDeployStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /heroBase64/);
});

// --------------------------------------------------------------- verifies

test("verify-page: served at / and /login via the public path", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const res = await verifyPageStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.ok(
    remote.commands.some((c) => c.includes(`--resolve ${fixtureConfig.domain}:443:${fixtureConfig.ip}`)),
  );
  assert.ok(remote.commands.some((c) => c.endsWith("https://vpn.example.com/login")));
});

test("verify-page: web down (000) — failed", async () => {
  const remote = new FakeRemote({ publicWebDown: true });
  const res = await verifyPageStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /HTTP 000/);
});

test("verify-page: page not deployed (404) — failed", async () => {
  const remote = new FakeRemote(); // vhost never deployed
  const res = await verifyPageStep().run(remote, ctx());
  assert.equal(res.status, "failed");
});

test("verify-sub: served and decodes (vless + pbk + routing)", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const res = await verifySubStep().run(remote, ctx());
  assert.equal(res.status, "ok");
});

test("verify-sub: wrong pbk in the served blob — failed (byte-match)", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const bad = Buffer.from(
    `vless://x@example.com:443?security=reality&pbk=WRONGKEY\nhapp://routing/onadd/eyJhIjoxfQ==\n`,
    "utf8",
  ).toString("base64");
  remote.files.set("/var/www/viper/main/sub.txt", bad);
  const res = await verifySubStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /does not byte-match the locally rendered subscription/);
});

test("verify-sub: missing routing line — failed (byte-match)", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const noRouting = Buffer.from(
    `vless://x@example.com:443?security=reality&pbk=${fixtureState.reality.publicKey}\n`,
    "utf8",
  ).toString("base64");
  remote.files.set("/var/www/viper/main/sub.txt", noRouting);
  const res = await verifySubStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /does not byte-match the locally rendered subscription/);
});

test("verify-sub: truncation of the served blob — failed (byte-match)", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const full = remote.files.get("/var/www/viper/main/sub.txt") as string;
  remote.files.set("/var/www/viper/main/sub.txt", full.slice(0, Math.floor(full.length * 0.8)));
  const res = await verifySubStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /does not byte-match the locally rendered subscription/);
});

test("verify-404: unknown path 404s", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const res = await verify404Step().run(remote, ctx());
  assert.equal(res.status, "ok");
});

test("verify-cert: Let's Encrypt issuer via public :443", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const res = await verifyCertStep().run(remote, ctx());
  assert.equal(res.status, "ok");
});

test("verify-cert: non-LE cert — failed", async () => {
  const remote = new FakeRemote(); // no cert issued → self-signed
  const res = await verifyCertStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /not Let's Encrypt/);
});

// ------------------------------------------------------- full pipeline

test("pipeline run 1: full deploy, expected statuses and ordering", async () => {
  const remote = new FakeRemote();
  const report = await deploy(remote);
  const byName = new Map(report.results.map((r) => [r.name, r.status]));
  assert.equal(byName.get("Ensure cron service"), "ok");
  assert.equal(byName.get("Install acme.sh"), "changed");
  assert.equal(byName.get("Install acme renewal cron"), "changed");
  assert.equal(byName.get("Deploy ACME vhost (:80)"), "changed");
  assert.equal(byName.get("Issue Let's Encrypt cert"), "changed");
  assert.equal(byName.get("Deploy cert"), "changed");
  assert.equal(byName.get("Deploy page + subscription"), "changed");
  assert.equal(byName.get("Deploy web vhost (:8443)"), "changed");
  assert.equal(byName.get("Verify decoy page (public path)"), "ok");
  assert.equal(byName.get("Verify subscription (public path)"), "ok");
  assert.equal(byName.get("Verify 404 (public path)"), "ok");
  assert.equal(byName.get("Verify Let's Encrypt cert (public path)"), "ok");

  // Ordering: :80 vhost before issue; issue before install-cert;
  // pages before the web vhost (so verifies have something to serve).
  const names = report.results.map((r) => r.name);
  assert.ok(names.indexOf("Deploy ACME vhost (:80)") < names.indexOf("Issue Let's Encrypt cert"));
  assert.ok(names.indexOf("Deploy cert") < names.indexOf("Deploy page + subscription"));
  assert.ok(names.indexOf("Deploy page + subscription") < names.indexOf("Deploy web vhost (:8443)"));
  // Three reloads in a full deploy: acme-vhost, cert-deploy, web-vhost.
  assert.equal(remote.nginxReloadCount, 3);
});

test("pipeline run 2: idempotent — zero observable changes except D3/D4 re-runs", async () => {
  const remote = new FakeRemote();
  await deploy(remote);

  remote.commands.length = 0;
  remote.uploads.length = 0;
  const reloadsAfterRun1 = remote.nginxReloadCount;
  const report = await deploy(remote);
  const byName = new Map(report.results.map((r) => [r.name, r.status]));

  assert.equal(byName.get("Ensure cron service"), "ok");
  assert.equal(byName.get("Install acme.sh"), "ok");
  assert.equal(byName.get("Install acme renewal cron"), "changed", "D3: always changed");
  assert.equal(byName.get("Deploy ACME vhost (:80)"), "ok");
  assert.equal(byName.get("Issue Let's Encrypt cert"), "ok", "rc 2 → cert valid, skip");
  assert.equal(byName.get("Deploy cert"), "ok", "md5 unchanged → ok");
  assert.equal(byName.get("Deploy page + subscription"), "ok");
  assert.equal(byName.get("Deploy web vhost (:8443)"), "ok");
  for (const n of [
    "Verify decoy page (public path)",
    "Verify subscription (public path)",
    "Verify 404 (public path)",
    "Verify Let's Encrypt cert (public path)",
  ]) {
    assert.equal(byName.get(n), "ok");
  }

  assert.equal(remote.uploads.length, 0, "no re-uploads in run 2");
  assert.ok(!remote.commands.includes("ln -sf"), "no symlink churn in run 2");
  assert.equal(remote.nginxReloadCount, reloadsAfterRun1, "NO nginx reload in run 2");
  // The only run-2 mutations: the D3 cron reinstall, the issue probe that
  // returns rc 2 (no order, no observable change), and the D4 install-cert
  // re-run (md5-identical copy).
  const run2Issue = remote.commands.filter((c) => c.includes("acme.sh --issue -d "));
  const expectedInstallCert = remote.commands.filter((c) => c.includes("acme.sh --install-cert -d "));
  assert.deepEqual(remote.mutatingCommands(), [ACME_CRON_CMD, ...run2Issue, ...expectedInstallCert]);
});

test("pipeline: cert issue fails — stop the line (D2)", async () => {
  const remote = new FakeRemote({ acmeIssueRc: 3 });
  const report = await runSteps(nginxSteps(ctx(), fixtureConfig, stepOpts()), remote, ctx(), {
    quiet: true,
  });
  assert.equal(report.failed, true);
  const failed = report.results.find((r) => r.status === "failed");
  assert.equal(failed?.name, "Issue Let's Encrypt cert");
  assert.ok(report.unrun.includes("Deploy cert"));
  assert.ok(report.unrun.includes("Deploy web vhost (:8443)"));
  // Nothing was deployed after the failure: no web vhost, no pages.
  assert.equal(remote.files.has("/etc/nginx/sites-available/viper-web.conf"), false);
  assert.equal(remote.files.has("/var/www/viper/main/index.html"), false);
});

test("pipeline: page body without the marker fails verify (no step/renderer drift)", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  // Corrupt the served page: a renderer/step drift would look like this.
  remote.files.set(
    "/var/www/viper/main/index.html",
    renderPage(HERO).replace(PAGE_MARKER, "Some Other SaaS"),
  );
  const res = await verifyPageStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /page marker/);
});

// -------------------------------------------------------------- teardown

test("teardown: after a deploy — removes M6 artifacts only", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  const report = await runSteps(nginxTeardownSteps(), remote, ctx(), { quiet: true });
  assert.equal(report.failed, false, JSON.stringify(report.results));
  const byName = new Map(report.results.map((r) => [r.name, r.status]));
  assert.equal(byName.get("Remove viper nginx vhosts (teardown)"), "changed");
  assert.equal(byName.get("Remove acme renewal cron (teardown)"), "changed");
  assert.equal(byName.get("Remove viper web files (teardown)"), "changed");

  assert.equal(remote.files.has("/etc/nginx/sites-available/viper-acme.conf"), false);
  assert.equal(remote.files.has("/etc/nginx/sites-available/viper-web.conf"), false);
  assert.equal(remote.files.has("/var/www/viper/main/index.html"), false);
  // nginx -t + reload happened after the removal, while nginx is active.
  const names = report.results.map((r) => r.name);
  assert.equal(names.length, 3);
  assert.ok(remote.commands.includes("nginx -t"));
  assert.ok(remote.commands.includes("systemctl reload nginx"));

  // D10: the nginx package and /root/.acme.sh are NOT touched.
  assert.ok(!remote.commands.some((c) => c.includes("apt-get remove") || c.includes("apt-get purge")));
  assert.ok(!remote.commands.some((c) => c.includes("rm -rf /root/.acme.sh")));
});

test("teardown: nothing present — all ok, zero mutating calls", async () => {
  const remote = new FakeRemote();
  const report = await runSteps(nginxTeardownSteps(), remote, ctx(), { quiet: true });
  assert.equal(report.failed, false);
  assert.ok(report.results.every((r) => r.status === "ok"));
  assert.equal(remote.mutatingCommands().length, 0);
});

test("teardown: idempotent — second run all ok", async () => {
  const remote = new FakeRemote();
  await deploy(remote);
  await runSteps(nginxTeardownSteps(), remote, ctx(), { quiet: true });
  const report = await runSteps(nginxTeardownSteps(), remote, ctx(), { quiet: true });
  assert.equal(report.failed, false);
  assert.ok(report.results.every((r) => r.status === "ok"));
});
