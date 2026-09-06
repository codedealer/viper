import assert from "node:assert/strict";
import { test } from "node:test";
import {
  hardeningSteps,
  tzStep,
  autoUpgradesStep,
  sshStep,
  fail2banStep,
  bbrStep,
  ipv6Step,
  ufwStep,
  renderAutoUpgradesConf,
  renderSshdDropin,
  renderBbrSysctlConf,
  renderIpv6DisableConf,
  AUTO_UPGRADES_PATH,
  SSHD_DROPIN_PATH,
  BBR_SYCTL_PATH,
  IPV6_SYCTL_PATH,
} from "../src/steps/hardening.js";
import { FakeRemote } from "./fake-remote.js";
import { fixtureConfig, fixtureState } from "./fixtures.js";
import { runSteps } from "../src/steps/runner.js";
import type { StepCtx } from "../src/steps/runner.js";
import { assertGolden } from "./golden.js";

function ctx(overrides: Partial<StepCtx> = {}): StepCtx {
  return {
    name: "main",
    ip: fixtureConfig.ip,
    config: fixtureConfig,
    state: { ...fixtureState },
    artifacts: {},
    ...overrides,
  };
}

// ------------------------------------------------------------------- tz

test("tz: non-UTC box → changed via timedatectl; second run ok with no mutations", async () => {
  const remote = new FakeRemote({ timezone: "America/New_York" });
  const c = ctx();
  const step = tzStep();
  const first = await step.run(remote, c);
  assert.equal(first.status, "changed");
  assert.match(remote.commands.join("\n"), /timedatectl set-timezone UTC/);
  const second = await step.run(remote, c);
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /already UTC/);
  // only the second run's read-only check was issued after the first run
  const setCalls = remote.commands.filter((x) => x === "timedatectl set-timezone UTC");
  assert.equal(setCalls.length, 1);
});

test("tz: already UTC → ok, zero mutations", async () => {
  const remote = new FakeRemote();
  const res = await tzStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.deepEqual(remote.mutatingCommands(), []);
});

test("tz: timedatectl fails → ln fallback; second run ok", async () => {
  const remote = new FakeRemote({ timezone: "Asia/Tokyo", setTzFails: true });
  const step = tzStep();
  const first = await step.run(remote, ctx());
  assert.equal(first.status, "changed");
  assert.match(remote.commands.join("\n"), /ln -sf \/usr\/share\/zoneinfo\/UTC \/etc\/localtime/);
  const second = await step.run(remote, ctx());
  assert.equal(second.status, "ok");
});

test("tz: both set methods fail → failed", async () => {
  const remote = new FakeRemote({ timezone: "Asia/Tokyo", setTzFails: true, lnFails: true });
  const res = await tzStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /timezone set failed/);
});

// ------------------------------------------------------- auto-upgrades

test("auto-upgrades: fresh box → changed (SFTP upload of golden content + chmod); second run ok", async () => {
  const remote = new FakeRemote();
  const c = ctx();
  const step = autoUpgradesStep();
  const first = await step.run(remote, c);
  assert.equal(first.status, "changed");
  const up = remote.uploads.find((u) => u.remote === AUTO_UPGRADES_PATH);
  assert.ok(up !== undefined, "uploaded via SFTP, not heredoc");
  assert.equal(up?.content, renderAutoUpgradesConf());
  assertGolden(import.meta.url, "auto-upgrades.conf", renderAutoUpgradesConf());
  assert.match(remote.commands.join("\n"), /chmod 644 \/etc\/apt\/apt\.conf\.d\/20auto-upgrades/);
  const second = await step.run(remote, c);
  assert.equal(second.status, "ok");
  assert.equal(remote.uploads.length, 1, "no re-upload on second run");
});

test("auto-upgrades: pre-existing different content → replaced", async () => {
  const remote = new FakeRemote({ autoUpgradesFile: 'APT::Periodic::Update-Package-Lists "0";\n' });
  const res = await autoUpgradesStep().run(remote, ctx());
  assert.equal(res.status, "changed");
});

test("auto-upgrades: matching content already present → ok", async () => {
  const remote = new FakeRemote({ autoUpgradesFile: renderAutoUpgradesConf() });
  const res = await autoUpgradesStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.equal(remote.uploads.length, 0);
});

test("auto-upgrades: SFTP upload failure → step reports failed (runSteps)", async () => {
  const remote = new FakeRemote({ uploadFails: "sftp: session closed" });
  const report = await runSteps([autoUpgradesStep()], remote, ctx(), { quiet: true });
  assert.equal(report.failed, true);
  assert.equal(report.results[0]?.status, "failed");
  assert.match(report.results[0]?.detail ?? "", /sftp: session closed/);
});

// ------------------------------------------------------------------ ssh

test("ssh: fresh box → drop-in written, neutralized, validated, effective-checked, restarted; second run ok", async () => {
  const remote = new FakeRemote();
  const c = ctx();
  const step = sshStep();
  const first = await step.run(remote, c);
  assert.equal(first.status, "changed");
  const up = remote.uploads.find((u) => u.remote === SSHD_DROPIN_PATH);
  assert.ok(up !== undefined);
  assert.equal(up?.content, renderSshdDropin());
  assertGolden(import.meta.url, "sshd-00-viper.conf", renderSshdDropin());
  const cmds = remote.commands;
  const neutralizeIdx = cmds.findIndex((x) => x.startsWith("for f in /etc/ssh/sshd_config.d"));
  const validateIdx = cmds.indexOf("sshd -t");
  const effectiveIdx = cmds.indexOf("sshd -T 2>/dev/null");
  const restartIdx = cmds.findIndex((x) => x.startsWith("systemctl restart sshd"));
  assert.ok(neutralizeIdx >= 0 && validateIdx > neutralizeIdx, "neutralize then validate");
  assert.ok(effectiveIdx > validateIdx, "effective check after validation");
  assert.ok(restartIdx > effectiveIdx, "restart only after both checks");
  const second = await step.run(remote, c);
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /already hardened/);
  const restarts = cmds.filter((x) => x.startsWith("systemctl restart sshd"));
  assert.equal(restarts.length, 1, "no restart on the idempotent run");
  assert.equal(remote.uploads.length, 1);
});

test("ssh: sshd -t failure → failed BEFORE any restart", async () => {
  const remote = new FakeRemote({ sshdConfigOk: false });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /sshd config validation failed/);
  assert.ok(!remote.commands.some((x) => x.startsWith("systemctl restart")));
});

test("ssh: conflicting drop-in (effective passwordauth yes) → failed BEFORE any restart", async () => {
  const remote = new FakeRemote({
    effectiveSsh: {
      passwordauthentication: "yes",
      kbdinteractiveauthentication: "no",
      debianbanner: "no",
    },
  });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /effective sshd setting mismatch/);
  assert.match(res.detail ?? "", /expected passwordauthentication no \(found yes\)/);
  assert.ok(!remote.commands.some((x) => x.startsWith("systemctl restart")));
});

test("ssh: kbdinteractive absent from effective output → failed (never assumed)", async () => {
  const remote = new FakeRemote({
    effectiveSsh: { passwordauthentication: "no", debianbanner: "no" },
  });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /found absent/);
});

test("ssh: debianbanner unrecognized by distro → verification skipped, still changed", async () => {
  const remote = new FakeRemote({
    effectiveSsh: { passwordauthentication: "no", kbdinteractiveauthentication: "no" },
  });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "changed");
});

test("ssh: already hardened → ok, zero mutations", async () => {
  const remote = new FakeRemote({ sshdDropinFile: renderSshdDropin() });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.deepEqual(remote.mutatingCommands(), []);
  assert.ok(!remote.commands.some((x) => x.startsWith("systemctl restart")));
});

test("ssh: conflicting drop-in neutralized on re-check → changed + restart (recovery)", async () => {
  // A conflicting directive appeared in another drop-in AFTER viper's last
  // write; the idempotent neutralize loop fixes it, so the step recovers
  // instead of failing.
  const remote = new FakeRemote({
    sshdDropinFile: renderSshdDropin(),
    effectiveSsh: {
      passwordauthentication: "yes",
      kbdinteractiveauthentication: "no",
      debianbanner: "no",
    },
    effectiveSshAfterNeutralize: {
      passwordauthentication: "no",
      kbdinteractiveauthentication: "no",
      debianbanner: "no",
    },
  });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /conflicting drop-in neutralized, sshd restarted/);
  // Drop-in already matched → the neutralize ran exactly once (the
  // mismatch re-run), and the restart happened AFTER the re-check.
  const neutralizes = remote.commands.filter((x) => x.startsWith("for f in /etc/ssh/sshd_config.d"));
  assert.equal(neutralizes.length, 1);
  const restartIdx = remote.commands.findIndex((x) => x.startsWith("systemctl restart sshd"));
  assert.ok(restartIdx >= 0, "restart issued");
  assert.ok(
    restartIdx > remote.commands.lastIndexOf("sshd -T 2>/dev/null"),
    "restart after the final effective check",
  );
});

test("ssh: conflicting drop-in NOT fixed by neutralize → failed with drop-in hint, no restart", async () => {
  const remote = new FakeRemote({
    sshdDropinFile: renderSshdDropin(),
    effectiveSsh: {
      passwordauthentication: "yes",
      kbdinteractiveauthentication: "no",
      debianbanner: "no",
    },
  });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /effective sshd setting mismatch/);
  assert.match(res.detail ?? "", /sshd_config\.d/);
  // The neutralize loop re-ran once (it did not fix the mismatch) — bounded.
  const neutralizes = remote.commands.filter((x) => x.startsWith("for f in /etc/ssh/sshd_config.d"));
  assert.equal(neutralizes.length, 1, "re-run at most once");
  assert.ok(!remote.commands.some((x) => x.startsWith("systemctl restart")));
});

test("ssh: fresh box with conflicting drop-in → write + neutralize recovers", async () => {
  const remote = new FakeRemote({
    effectiveSsh: {
      passwordauthentication: "yes",
      kbdinteractiveauthentication: "no",
      debianbanner: "no",
    },
    effectiveSshAfterNeutralize: {
      passwordauthentication: "no",
      kbdinteractiveauthentication: "no",
      debianbanner: "no",
    },
  });
  const res = await sshStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(
    remote.uploads.some((u) => u.remote === SSHD_DROPIN_PATH),
    "drop-in written",
  );
});

// ------------------------------------------------------------- fail2ban

test("fail2ban: inactive → enabled + started; second run ok", async () => {
  const remote = new FakeRemote();
  const step = fail2banStep();
  const first = await step.run(remote, ctx());
  assert.equal(first.status, "changed");
  assert.match(remote.commands.join("\n"), /systemctl enable fail2ban/);
  assert.match(remote.commands.join("\n"), /systemctl restart fail2ban/);
  const second = await step.run(remote, ctx());
  assert.equal(second.status, "ok");
  assert.equal(remote.commands.filter((x) => x.startsWith("systemctl restart fail2ban")).length, 1);
});

test("fail2ban: already active → ok, zero mutations", async () => {
  const remote = new FakeRemote({ fail2banActive: true });
  const res = await fail2banStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.deepEqual(remote.mutatingCommands(), []);
});

// ------------------------------------------------------------------ bbr

test("bbr: fresh box (module kernel) → probe, modprobe, sysctls, persist; second run ok", async () => {
  const remote = new FakeRemote();
  const c = ctx();
  const step = bbrStep();
  const first = await step.run(remote, c);
  assert.equal(first.status, "changed");
  const cmds = remote.commands;
  const probeIdx = cmds.findIndex((x) => x.includes("tcp_available_congestion_control"));
  const modprobeIdx = cmds.indexOf("modprobe tcp_bbr 2>/dev/null");
  const qdiscIdx = cmds.indexOf("sysctl -w net.core.default_qdisc=fq");
  const cbrIdx = cmds.indexOf("sysctl -w net.ipv4.tcp_congestion_control=bbr");
  assert.ok(probeIdx >= 0, "availability probed");
  assert.ok(modprobeIdx > probeIdx, "modprobe after probe");
  assert.ok(qdiscIdx > modprobeIdx && cbrIdx > modprobeIdx, "sysctls after modprobe");
  const up = remote.uploads.find((u) => u.remote === BBR_SYCTL_PATH);
  assert.ok(up !== undefined);
  assert.equal(up?.content, renderBbrSysctlConf());
  assertGolden(import.meta.url, "sysctl-99-viper.conf", renderBbrSysctlConf());
  const second = await step.run(remote, c);
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /already enabled/);
  assert.equal(remote.uploads.length, 1, "no re-upload on the idempotent run");
});

test("bbr: availability only in the legacy key → still enabled", async () => {
  const remote = new FakeRemote({
    bbrAvailableSingular: "", // kernel without the singular key
    bbrAvailableLegacy: "reno cubic bbr",
  });
  const res = await bbrStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  // both keys probed
  assert.ok(remote.commands.some((x) => x.includes("tcp_available_congestion_control")));
  assert.ok(remote.commands.some((x) => x.includes("tcp_available_congestions")));
});

test("bbr: sysctls genuinely unavailable → skipped + WARNING, no persistence", async () => {
  const remote = new FakeRemote({ sysctlUnavailable: true });
  const res = await bbrStep().run(remote, ctx());
  assert.equal(res.status, "skipped");
  assert.match(res.detail ?? "", /^WARNING: BBR genuinely unavailable/);
  assert.match(res.detail ?? "", /continuing without BBR/);
  assert.equal(remote.uploads.length, 0, "nothing persisted");
});

test("bbr: other sysctl failure → failed (not warn-swallowed)", async () => {
  const remote = new FakeRemote({
    sysctlFails: 'sysctl: setting key "net.core.default_qdisc", ignoring: permission denied',
  });
  const res = await bbrStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /sysctl net\.core\.default_qdisc failed/);
});

test("bbr: cc=bbr but qdisc not fq → re-applies and persists", async () => {
  const remote = new FakeRemote({ sysctl: { "net.ipv4.tcp_congestion_control": "bbr" } });
  const res = await bbrStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.some((x) => x === "sysctl -w net.core.default_qdisc=fq"));
});

test("bbr: live bbr+fq but persist file missing → persisted (changed); second run ok", async () => {
  // A previous run set the live sysctls but died before the SFTP persist
  // — the ok-path must re-check the persist file (a live-only box loses
  // BBR on the next reboot).
  const remote = new FakeRemote({
    sysctl: { "net.ipv4.tcp_congestion_control": "bbr", "net.core.default_qdisc": "fq" },
  });
  const c = ctx();
  const first = await bbrStep().run(remote, c);
  assert.equal(first.status, "changed");
  assert.match(first.detail ?? "", /persisted to \/etc\/sysctl\.d\/99-viper\.conf/);
  const up = remote.uploads.find((u) => u.remote === BBR_SYCTL_PATH);
  assert.ok(up !== undefined, "persist file uploaded");
  assert.equal(up?.content, renderBbrSysctlConf());
  assert.ok(!remote.commands.some((x) => x.startsWith("sysctl -w")), "no re-apply of live sysctls");

  const second = await bbrStep().run(remote, c);
  assert.equal(second.status, "ok");
  assert.equal(remote.uploads.length, 1, "no re-upload on the idempotent run");
});

test("bbr: live bbr+fq with stale persist file → re-persisted", async () => {
  const remote = new FakeRemote({
    sysctl: { "net.ipv4.tcp_congestion_control": "bbr", "net.core.default_qdisc": "fq" },
    autoUpgradesFile: "stale",
  });
  // Seed a stale 99-viper.conf directly.
  remote.files.set(BBR_SYCTL_PATH, "# stale\nnet.ipv4.tcp_congestion_control = bbr\n");
  const res = await bbrStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.equal(remote.files.get(BBR_SYCTL_PATH), renderBbrSysctlConf());
});

// --------------------------------------------------------------- ipv6 (M8)

const POLL_FAST = { attempts: 5, intervalMs: 1 };

test("ipv6: fresh box (sysctl 0/0) → conf written, applied, verified → changed; second run ok", async () => {
  const remote = new FakeRemote(); // v6 enabled + global v6 addr by default
  const c = ctx();
  const step = ipv6Step();
  const first = await step.run(remote, c);
  assert.equal(first.status, "changed");
  assert.match(first.detail ?? "", /IPv6 disabled \(v4-only\)/);
  const up = remote.uploads.find((u) => u.remote === IPV6_SYCTL_PATH);
  assert.ok(up !== undefined, "persisted via SFTP, not heredoc");
  assert.equal(up?.content, renderIpv6DisableConf());
  assertGolden(import.meta.url, "sysctl-99-viper-ipv6.conf", renderIpv6DisableConf());
  const cmds = remote.commands;
  const checkIdx = cmds.indexOf(
    "sysctl -n net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6",
  );
  const catIdx = cmds.indexOf(`cat ${IPV6_SYCTL_PATH} 2>/dev/null`);
  const applyIdx = cmds.indexOf(`sysctl -p ${IPV6_SYCTL_PATH}`);
  assert.ok(checkIdx >= 0 && catIdx > checkIdx && applyIdx > catIdx, "check → content check → apply");
  // The three-part verification comes AFTER the apply.
  assert.ok(cmds.indexOf("ip -6 addr show scope global", applyIdx) > applyIdx);
  assert.ok(cmds.indexOf("ip -6 route show default") > applyIdx);

  const mutAfterRun1 = remote.mutatingCommands().length;
  const uploadsAfterRun1 = remote.uploads.length;
  const second = await step.run(remote, c);
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /already v4-only/);
  assert.equal(remote.mutatingCommands().length, mutAfterRun1, "run 2 issues zero mutations");
  assert.equal(remote.uploads.length, uploadsAfterRun1, "no re-upload on the idempotent run");
});

test("ipv6: already 1/1 → ok, zero mutations", async () => {
  const remote = new FakeRemote({ ipv6Disabled: true, ipv6GlobalAddr: false });
  const res = await ipv6Step().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.match(res.detail ?? "", /already v4-only/);
  assert.deepEqual(remote.mutatingCommands(), []);
  assert.ok(!remote.commands.some((x) => x.startsWith("sysctl -p")), "no apply on the ok path");
});

test("ipv6: allowIPv6 true, sysctl 0/0 → skipped, zero mutations", async () => {
  const remote = new FakeRemote();
  const res = await ipv6Step().run(remote, ctx({ config: { ...fixtureConfig, allowIPv6: true } }));
  assert.equal(res.status, "skipped");
  assert.match(res.detail ?? "", /allowIPv6: true, v6 left as-is/);
  assert.deepEqual(remote.mutatingCommands(), []);
});

test("ipv6: apply succeeds but verify fails (sysctls + v6 remain) → failed + diagnostics", async () => {
  const remote = new FakeRemote({ ipv6Stuck: true });
  const res = await ipv6Step().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /verification failed/);
  assert.match(res.detail ?? "", /sysctl disable_ipv6 0\/0 \(expected 1\/1\)/);
  assert.match(res.detail ?? "", /global v6 address remains/);
});

test("ipv6: re-enable (flag true, sysctl 1/1) → file removed, sysctl 0, detached bounce, poll → changed", async () => {
  const remote = new FakeRemote({ ipv6Disabled: true, ipv6GlobalAddr: false });
  remote.files.set(IPV6_SYCTL_PATH, renderIpv6DisableConf());
  const c = ctx({ config: { ...fixtureConfig, allowIPv6: true } });
  const res = await ipv6Step({ poll: POLL_FAST }).run(remote, c);
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /re-enabled IPv6 \(global v6 on eth0\)/);
  assert.ok(!remote.files.has(IPV6_SYCTL_PATH), "viper's disable drop-in removed");
  const cmds = remote.commands;
  const rmIdx = cmds.indexOf(`rm -f ${IPV6_SYCTL_PATH}`);
  const wAll = cmds.indexOf("sysctl -w net.ipv6.conf.all.disable_ipv6=0");
  const wDef = cmds.indexOf("sysctl -w net.ipv6.conf.default.disable_ipv6=0");
  const bounceIdx = cmds.findIndex((x) => x.startsWith("nohup sh -c 'sleep 1; ip link set dev "));
  const pollIdx = cmds.indexOf("ip -6 addr show scope global", bounceIdx);
  assert.ok(rmIdx >= 0 && wAll > rmIdx && wDef > wAll, "rm → sysctl -w all → default");
  assert.ok(bounceIdx > wDef, "bounce after the sysctls");
  assert.ok(pollIdx > bounceIdx, "poll after the bounce");
  assert.match(
    cmds[bounceIdx] ?? "",
    /^nohup sh -c 'sleep 1; ip link set dev eth0 down; sleep 2; ip link set dev eth0 up' >\/tmp\/viper-ipv6-rev\.log 2>&1 &$/,
  );
  // M2: the success detail reuses the poll's output — exactly one
  // `ip -6 addr show scope global` probe, no raced-empty extra call.
  assert.equal(
    cmds.filter((x) => x === "ip -6 addr show scope global").length,
    1,
    "no extra probe after a successful poll",
  );
});

test("ipv6: re-enable but no address after the bounce → changed + non-fatal warning", async () => {
  const remote = new FakeRemote({
    ipv6Disabled: true,
    ipv6GlobalAddr: false,
    ipv6ReassignsAfterBounce: false,
  });
  const c = ctx({ config: { ...fixtureConfig, allowIPv6: true } });
  const res = await ipv6Step({ poll: POLL_FAST }).run(remote, c);
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /re-enabled; v6 address not yet assigned \(reboot to complete\)/);
});

test("ipv6: re-enable with no detectable primary interface → no bounce, warning status", async () => {
  const remote = new FakeRemote({
    ipv6Disabled: true,
    ipv6GlobalAddr: false,
    ipv6ReassignsAfterBounce: false,
    ipv6PrimaryIf: "",
  });
  const c = ctx({ config: { ...fixtureConfig, allowIPv6: true } });
  const res = await ipv6Step({ poll: POLL_FAST }).run(remote, c);
  assert.equal(res.status, "changed");
  assert.match(res.detail ?? "", /reboot to complete/);
  assert.ok(!remote.commands.some((x) => x.startsWith("nohup sh -c")), "no bounce without an interface");
});

// ----------------------------------------------------------------- ufw

test("ufw: fresh box → allows BEFORE enable, no `ufw limit`, custom ports only; second run fully ok", async () => {
  const remote = new FakeRemote(); // sshdPorts [22], ufw installed+inactive
  const c = ctx();
  const step = ufwStep();
  const first = await step.run(remote, c);
  assert.equal(first.status, "changed");
  const cmds = remote.commands;
  const allowIdx = cmds.indexOf("ufw allow 22/tcp");
  const enableIdx = cmds.indexOf("ufw --force enable");
  assert.ok(allowIdx >= 0 && enableIdx > allowIdx, "allow before enable");
  assert.ok(!cmds.some((x) => x.includes("ufw limit")), "no ufw limit");
  assert.ok(cmds.includes("ufw allow 443/tcp") && cmds.includes("ufw allow 80/tcp"));
  assert.ok(!cmds.some((x) => x === "ufw allow 2222/tcp"), "2222 not an sshd port here");
  assert.ok(cmds.includes("ufw default deny incoming"));
  // outgoing default is already allow on a fresh box → not re-issued
  assert.ok(!cmds.includes("ufw default allow outgoing"));
  const ufwCountAfterRun1 = remote.commands.filter((x) => x.startsWith("ufw ")).length;
  const second = await step.run(remote, c);
  assert.equal(second.status, "ok");
  assert.match(second.detail ?? "", /already configured/);
  // run 2 is fully idempotent: exactly one read-only verbose status check,
  // no mutating ufw commands (allow/default/enable/reload all absent)
  const ufwCmdsRun2 = remote.commands.filter((x) => x.startsWith("ufw ")).slice(ufwCountAfterRun1);
  assert.deepEqual(ufwCmdsRun2, ["ufw status verbose"], "run 2 issues no mutating ufw commands");
  assert.equal(remote.uploads.length, 0);
});

test("ufw: non-default VPN port (2053) → config.port allowed, 443 NOT", async () => {
  const remote = new FakeRemote();
  const c = ctx({ config: { ...fixtureConfig, port: 2053 } });
  const res = await ufwStep().run(remote, c);
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("ufw allow 2053/tcp"));
  assert.ok(remote.commands.includes("ufw allow 80/tcp"));
  assert.ok(!remote.commands.includes("ufw allow 443/tcp"));
});

test("ufw: custom sshd port 2222 → 2222 allowed, 22 NOT", async () => {
  const remote = new FakeRemote({ sshdPorts: [2222] });
  const c = ctx({ config: { ...fixtureConfig, sshPort: 2222 } });
  const res = await ufwStep().run(remote, c);
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("ufw allow 2222/tcp"));
  assert.ok(!remote.commands.some((x) => x === "ufw allow 22/tcp"));
});

test("ufw: multiple sshd ports → all allowed", async () => {
  const remote = new FakeRemote({ sshdPorts: [22, 2222] });
  const res = await ufwStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("ufw allow 22/tcp"));
  assert.ok(remote.commands.includes("ufw allow 2222/tcp"));
});

test("ufw: already active with viper's rules+defaults → ok, zero mutations", async () => {
  const remote = new FakeRemote({
    ufwActive: true,
    ufwRules: ["22/tcp", "443/tcp", "80/tcp"],
    ufwDefaultIn: "deny",
    ufwDefaultOut: "allow",
  });
  const res = await ufwStep().run(remote, ctx());
  assert.equal(res.status, "ok");
  assert.deepEqual(remote.mutatingCommands(), []);
});

test("ufw: active but missing a rule → changed (rule added + reload, no enable)", async () => {
  const remote = new FakeRemote({
    ufwActive: true,
    ufwRules: ["22/tcp", "80/tcp"],
    ufwDefaultIn: "deny",
    ufwDefaultOut: "allow",
  });
  const res = await ufwStep().run(remote, ctx());
  assert.equal(res.status, "changed");
  assert.ok(remote.commands.includes("ufw allow 443/tcp"));
  assert.ok(remote.commands.includes("ufw reload"));
  assert.ok(!remote.commands.includes("ufw --force enable"));
});

test("ufw: ufw not installed → failed with hint", async () => {
  const remote = new FakeRemote({ ufwInstalled: false });
  const res = await ufwStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /ufw not available/);
});

test("ufw: no detectable sshd ports → failed (lockout refusal)", async () => {
  const remote = new FakeRemote({ sshdPorts: [] });
  const res = await ufwStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /could not detect sshd listen ports/);
  assert.ok(!remote.commands.some((x) => x.startsWith("ufw allow")));
});

test("ufw: an allow fails → failed before enable", async () => {
  const remote = new FakeRemote({ ufwAllowFails: 443 });
  const res = await ufwStep().run(remote, ctx());
  assert.equal(res.status, "failed");
  assert.match(res.detail ?? "", /failed to allow port 443/);
  assert.ok(!remote.commands.includes("ufw --force enable"));
});

test("ufw: user rules are never touched (only viper's allows issued)", async () => {
  const remote = new FakeRemote({
    ufwActive: true,
    ufwRules: ["3389/tcp"],
    ufwDefaultIn: "deny",
    ufwDefaultOut: "allow",
  });
  await ufwStep().run(remote, ctx());
  const issued = remote.commands.filter((x) => x.startsWith("ufw "));
  for (const c of issued) {
    assert.ok(!c.includes("delete"), `no rule deletion: ${c}`);
  }
  assert.ok(!remote.commands.some((x) => x.includes("3389")));
});

test("ufw: sshd port equals 443 → 443/tcp allowed exactly once (no duplicate)", async () => {
  const remote = new FakeRemote({ sshdPorts: [443] });
  const c = ctx({ config: { ...fixtureConfig, sshPort: 443 } });
  const res = await ufwStep().run(remote, c);
  assert.equal(res.status, "changed");
  assert.equal(
    remote.commands.filter((x) => x === "ufw allow 443/tcp").length,
    1,
    "443 allowed exactly once",
  );
  assert.ok(remote.commands.includes("ufw allow 80/tcp"));
});

// ------------------------------------------------------- hardeningSteps

const NAMES = {
  preflight: "Preflight",
  packages: "Install system packages",
  tz: "Set timezone to UTC",
  auto: "Enable automatic security updates",
  ssh: "Harden SSH configuration",
  f2b: "Enable fail2ban",
  bbr: "Enable BBR congestion control",
  ipv6: "Configure IPv6",
  ufw: "Configure firewall",
};

function stepNames(steps: { name: string }[]): string[] {
  return steps.map((s) => s.name);
}

test("hardeningSteps: full pipeline (harden+bbr) — the plan's order incl. M8 ipv6", () => {
  const steps = hardeningSteps(ctx(), fixtureConfig);
  assert.deepEqual(stepNames(steps), [
    NAMES.preflight,
    NAMES.packages,
    NAMES.tz,
    NAMES.auto,
    NAMES.ssh,
    NAMES.f2b,
    NAMES.bbr,
    NAMES.ipv6,
    NAMES.ufw,
  ]);
});

test("hardeningSteps: harden:false → no tz/auto/ssh/fail2ban/ufw; bbr + ipv6 kept", () => {
  const cfg = { ...fixtureConfig, harden: false };
  const steps = hardeningSteps(ctx({ config: cfg }), cfg);
  // M8: the IPv6 step is independent of the `harden` gate (own knob).
  assert.deepEqual(stepNames(steps), [NAMES.preflight, NAMES.packages, NAMES.bbr, NAMES.ipv6]);
});

test("hardeningSteps: bbr:false → no bbr; everything else kept", () => {
  const cfg = { ...fixtureConfig, bbr: false };
  const steps = hardeningSteps(ctx({ config: cfg }), cfg);
  assert.equal(steps.length, 8);
  const names = stepNames(steps);
  assert.ok(!names.includes(NAMES.bbr));
  assert.ok(names.includes(NAMES.ipv6));
  assert.ok(names.indexOf(NAMES.ipv6) < names.indexOf(NAMES.ufw), "ipv6 still before ufw");
});

test("hardeningSteps: both off → preflight + packages + ipv6", () => {
  const cfg = { ...fixtureConfig, harden: false, bbr: false };
  const steps = hardeningSteps(ctx({ config: cfg }), cfg);
  assert.deepEqual(stepNames(steps), [NAMES.preflight, NAMES.packages, NAMES.ipv6]);
});

test("hardeningSteps: allowIPv6:true does NOT drop the step (skip is a status, not an un-wire)", () => {
  const cfg = { ...fixtureConfig, allowIPv6: true };
  const steps = hardeningSteps(ctx({ config: cfg }), cfg);
  assert.ok(stepNames(steps).includes(NAMES.ipv6));
});
