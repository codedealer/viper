import assert from "node:assert/strict";
import { test } from "node:test";
import {
  pinnedVersion,
  parseXrayVersion,
  renderXrayUnit,
  xrayInstallStep,
  XRAY_BIN,
  XRAY_UNIT,
} from "../src/steps/xray-install.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";
import type { StepCtx } from "../src/steps/runner.js";
import type { State } from "../src/state.js";

function ctx(): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState, installedPackages: [] },
    artifacts: {},
  };
}

const FAST = { attempts: 3, intervalMs: 1 } as const;

test("pure: pinnedVersion strips leading v", () => {
  assert.equal(pinnedVersion("v26.3.27"), "26.3.27");
  assert.equal(pinnedVersion("26.3.27"), "26.3.27");
});

test("pure: parseXrayVersion", () => {
  assert.equal(
    parseXrayVersion("Xray 26.3.27 (Xray, Penetrates Everything) abc123\n"),
    "26.3.27",
  );
  assert.equal(parseXrayVersion("garbage"), undefined);
});

test("pure: renderXrayUnit — golden", () => {
  const unit = renderXrayUnit();
  assert.match(unit, /\[Unit\]/);
  assert.match(unit, /ExecStart=\/usr\/local\/bin\/xray run -config \/etc\/xray\/config\.json/);
  assert.match(unit, /WorkingDirectory=\/usr\/local\/share\/xray/);
  assert.match(unit, /Restart=on-failure/);
});

test("install: fresh box — download, verify, install, unit, enable", async () => {
  const remote = new FakeRemote(); // xray not installed, unzip present
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /installed Xray 26\.3\.27/);

  const cmds = remote.commands;
  const idx = (frag: string) => cmds.findIndex((c) => c.includes(frag));
  // Digest verified BEFORE anything is installed.
  assert.ok(idx("sha256sum") > idx("curl -fsSL --max-time 60"), "digest downloaded");
  assert.ok(idx("cp /tmp/viper-xray/xray") > idx("sha256sum"), "verify before install");
  // Binary + geo + unit installed.
  assert.ok(cmds.includes(`cp /tmp/viper-xray/xray ${XRAY_BIN}`));
  assert.ok(cmds.includes("cp /tmp/viper-xray/geoip.dat /usr/local/share/xray/geoip.dat"));
  assert.ok(cmds.includes("cp /tmp/viper-xray/geosite.dat /usr/local/share/xray/geosite.dat"));
  assert.ok(cmds.includes("systemctl enable xray"));
  // Unit uploaded by SFTP with the rendered content.
  const unitUpload = remote.uploads.find((u) => u.remote === XRAY_UNIT);
  assert.ok(unitUpload !== undefined, "unit uploaded");
  assert.equal(unitUpload?.content, renderXrayUnit());
  // Sandbox cleaned up.
  assert.ok(cmds.includes("rm -rf /tmp/viper-xray"));
  // unzip pre-existing → NOT recorded.
  assert.equal(ctx().state.installedPackages.includes("unzip"), false);
});

test("install: fresh box without unzip — installs + records unzip", async () => {
  const remote = new FakeRemote({ unzipInstalled: false });
  const c = ctx();
  const persisted: State[] = [];
  const res = await xrayInstallStep({ persistState: (s) => {
    persisted.push(s);
  } }).run(remote, c);
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.some((x) => x.includes("apt-get install -y -qq unzip")));
  assert.deepEqual(c.state.installedPackages, ["unzip"]);
  assert.ok(persisted.length > 0, "state persisted");
});

test("install: second run — ok, zero mutating calls", async () => {
  const remote = new FakeRemote();
  const c = ctx();
  const first = await xrayInstallStep().run(remote, c);
  assert.equal(first.status, "changed");
  const mutatingAfterFirst = remote.mutatingCommands().length;
  assert.ok(mutatingAfterFirst > 0);

  const second = await xrayInstallStep().run(remote, c);
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /already installed/);
  assert.equal(remote.mutatingCommands().length, mutatingAfterFirst, "no new mutations");
  assert.equal(remote.uploads.length, 1, "unit uploaded exactly once");
});

test("install: version mismatch — in-place upgrade", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayVersion: "1.8.24" });
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /upgraded Xray 1\.8\.24 → 26\.3\.27/);
  assert.ok(remote.commands.includes(`cp /tmp/viper-xray/xray ${XRAY_BIN}`));
});

test("install: unit present but stale — re-upload + reload + enable", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayUnitFile: "[Unit]\nDescription=stale\n",
  });
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /repaired/);
  assert.ok(remote.commands.includes("systemctl daemon-reload"));
  const unitUploads = remote.uploads.filter((u) => u.remote === XRAY_UNIT);
  assert.equal(unitUploads.length, 1);
  assert.equal(unitUploads[0]?.content, renderXrayUnit());
});

test("install: pinned version but geo assets missing — re-download + repair", async () => {
  const remote = new FakeRemote({ xrayInstalled: true, xrayGeoMissing: true, xrayUnitFile: renderXrayUnit() });
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("cp /tmp/viper-xray/geoip.dat /usr/local/share/xray/geoip.dat"));
});

test("install: geo repair without unzip — installs + records unzip (R10.1)", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayGeoMissing: true,
    xrayUnitFile: renderXrayUnit(),
    unzipInstalled: false,
  });
  const c = ctx();
  const res = await xrayInstallStep().run(remote, c);
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("cp /tmp/viper-xray/geoip.dat /usr/local/share/xray/geoip.dat"));
  assert.deepEqual(c.state.installedPackages, ["unzip"], "geo-repair path records unzip");
});

test("install: unit present but DISABLED — re-enabled, no re-upload (R10.2)", async () => {
  const remote = new FakeRemote({
    xrayInstalled: true,
    xrayUnitFile: renderXrayUnit(),
    xrayUnitEnabled: false,
  });
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("systemctl enable xray"), "disabled unit re-enabled");
  assert.ok(!remote.commands.includes("systemctl daemon-reload"), "content unchanged → no reload");
  assert.equal(remote.uploads.length, 0, "unit content unchanged → no upload");
});

test("install: SHA2-256 mismatch — hard fail, nothing installed", async () => {
  const remote = new FakeRemote({ sha256Mismatch: true });
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /SHA2-256 mismatch/);
  assert.ok(!remote.commands.includes(`cp /tmp/viper-xray/xray ${XRAY_BIN}`));
  assert.ok(remote.commands.includes("rm -rf /tmp/viper-xray"), "downloaded artifacts cleaned up");
});

test("install: digest asset missing — hard fail (no unverified binary)", async () => {
  const remote = new FakeRemote({ dgstMissing: true });
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /digest asset missing/);
  assert.ok(!remote.commands.includes(`cp /tmp/viper-xray/xray ${XRAY_BIN}`));
});

test("install: apt failure while installing unzip — fails loudly", async () => {
  const remote = new FakeRemote({ unzipInstalled: false, aptInstallFails: "E: Unable to fetch" });
  const res = await xrayInstallStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /unzip/);
});