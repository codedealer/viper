/**
 * Xray install step (M5) — install the hard-pinned Xray release.
 *
 * Source: official Xray GitHub release for `config.xray` (e.g.
 * "v26.3.27"): `Xray-linux-64.zip` + its `.dgst` digest file. The ZIP's
 * SHA2-256 is verified against the digest BEFORE anything is installed;
 * a missing digest or a mismatch is a hard failure (no unverified
 * binary ever reaches disk).
 *
 * Layout:
 *  - /usr/local/bin/xray                    (binary)
 *  - /usr/local/share/xray/{geoip,geosite}.dat (geo assets)
 *  - /etc/systemd/system/xray.service       (unit; enabled, not started —
 *    the deploy step's restart starts it)
 *
 * Idempotent: `xray version` matches the pin and the unit + geo assets
 * are in place → ok, zero mutating calls. Version mismatch → in-place
 * upgrade (re-download, replace binary + geo, re-check unit).
 *
 * The step ensures `unzip` (its one tool dependency) via apt if absent;
 * a viper-installed unzip is recorded in `state.installedPackages`
 * (a pre-existing one is left alone and not recorded).
 */
import type { SshConn } from "../ssh.js";
import type { Step, StepCtx, StepResult } from "./runner.js";
import { errDetail, uploadRendered, type HardeningStepOptions } from "./common.js";

export const XRAY_BIN = "/usr/local/bin/xray";
export const XRAY_UNIT = "/etc/systemd/system/xray.service";
export const XRAY_GEO_DIR = "/usr/local/share/xray";
const DOWNLOAD_DIR = "/tmp/viper-xray";
const XRAY_ZIP = "Xray-linux-64.zip";
const XRAY_ZIP_URL = (version: string) =>
  `https://github.com/XTLS/Xray-core/releases/download/${version}/${XRAY_ZIP}`;

/** Pinned version without the leading "v" (as reported by `xray version`). */
export function pinnedVersion(version: string): string {
  return version.replace(/^v/, "");
}

/**
 * Render the systemd unit (pure function, golden-tested). Working
 * directory is the geo-asset dir: Xray expects the geo dat files next
 * to its working directory at startup even when the config does not
 * use geo rules.
 */
export function renderXrayUnit(): string {
  return `[Unit]
Description=Xray Service
After=network-online.target
Wants=network-online.target

[Service]
User=root
ExecStart=${XRAY_BIN} run -config /etc/xray/config.json
WorkingDirectory=${XRAY_GEO_DIR}
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
`;
}

/** Parse the version out of `xray version` output ("Xray 26.3.27 (...) ..."). */
export function parseXrayVersion(output: string): string | undefined {
  const m = output.match(/Xray\s+(\d+(?:\.\d+)+)/);
  return m !== null ? (m[1] ?? undefined) : undefined;
}

/**
 * Ensure `unzip` is available. Returns `true` when this call installed
 * it (so the caller can record it for teardown).
 */
async function ensureUnzip(conn: SshConn): Promise<boolean> {
  const which = await conn.run("which unzip 2>/dev/null", { timeoutMs: 10_000 });
  if (which.code === 0 && which.stdout.trim() !== "") return false;
  const update = await conn.run("DEBIAN_FRONTEND=noninteractive apt-get update -qq", {
    timeoutMs: 180_000,
  });
  if (update.code !== 0) {
    throw new Error(`apt-get update failed: ${errDetail(update.stderr)}`);
  }
  const install = await conn.run("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unzip", {
    timeoutMs: 300_000,
  });
  if (install.code !== 0) {
    throw new Error(`apt-get install unzip failed: ${errDetail(install.stderr)}`);
  }
  return true;
}

/**
 * Shared by the fresh/upgrade and the geo-repair path: ensure `unzip`
 * is available, and — when THIS call installed it — record it in
 * state.installedPackages (+ persist). Both paths must bookkeep
 * identically, or teardown would miss a viper-installed unzip.
 */
async function ensureUnzipRecorded(conn: SshConn, ctx: StepCtx, opts: HardeningStepOptions): Promise<void> {
  const installed = await ensureUnzip(conn);
  if (installed && !ctx.state.installedPackages.includes("unzip")) {
    ctx.state.installedPackages.push("unzip");
    await opts.persistState?.(ctx.state);
  }
}

/** Download ZIP + digest and verify the ZIP's SHA2-256.
 *  Throws on any failure (missing digest, mismatch) after removing the
 *  downloaded artifacts. */
async function downloadAndVerify(conn: SshConn, version: string): Promise<void> {
  const zipUrl = XRAY_ZIP_URL(version);
  await conn.run(`mkdir -p ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });

  const dlZip = await conn.run(`curl -fsSL --max-time 300 ${zipUrl} -o ${DOWNLOAD_DIR}/${XRAY_ZIP}`, {
    timeoutMs: 320_000,
  });
  if (dlZip.code !== 0) {
    await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
    throw new Error(`download failed: ${errDetail(dlZip.stderr)}`);
  }

  const dlDgst = await conn.run(
    `curl -fsSL --max-time 60 ${zipUrl}.dgst -o ${DOWNLOAD_DIR}/${XRAY_ZIP}.dgst`,
    { timeoutMs: 80_000 },
  );
  if (dlDgst.code !== 0) {
    await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
    throw new Error(
      `digest asset missing or unreachable (${errDetail(dlDgst.stderr)}) — refusing to install an unverified binary`,
    );
  }

  const expected = await conn.run(`grep '^SHA2-256=' ${DOWNLOAD_DIR}/${XRAY_ZIP}.dgst | awk '{print $2}'`, {
    timeoutMs: 10_000,
  });
  const expectedHex = expected.stdout.trim();
  if (!/^[0-9a-f]{64}$/.test(expectedHex)) {
    await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
    throw new Error(`could not parse SHA2-256 from digest file (got: "${expectedHex}")`);
  }

  const actual = await conn.run(`sha256sum ${DOWNLOAD_DIR}/${XRAY_ZIP} | awk '{print $1}'`, {
    timeoutMs: 60_000,
  });
  const actualHex = actual.stdout.trim();
  if (actualHex !== expectedHex) {
    await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
    throw new Error(`SHA2-256 mismatch: expected ${expectedHex}, got ${actualHex} — refusing to install`);
  }
}

async function extractAndInstall(conn: SshConn): Promise<void> {
  // A running xray holds the binary open — cp over it fails with
  // "Text file busy". Stop it if active; the deploy step restarts it
  // (fresh installs have nothing running, so this is a no-op there).
  const active = await conn.run("systemctl is-active xray 2>/dev/null", { timeoutMs: 10_000 });
  if (active.stdout.trim() === "active") {
    await conn.run("systemctl stop xray", { timeoutMs: 30_000 });
  }

  const unzip = await conn.run(`cd ${DOWNLOAD_DIR} && unzip -o ${XRAY_ZIP}`, {
    timeoutMs: 120_000,
  });
  if (unzip.code !== 0) {
    await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
    throw new Error(`unzip failed: ${errDetail(unzip.stderr)}`);
  }

  await conn.run(`mkdir -p ${XRAY_GEO_DIR}`, { timeoutMs: 10_000 });
  const cpBin = await conn.run(`cp ${DOWNLOAD_DIR}/xray ${XRAY_BIN}`, { timeoutMs: 30_000 });
  if (cpBin.code !== 0) {
    await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
    throw new Error(`installing binary failed: ${errDetail(cpBin.stderr)}`);
  }
  await conn.run(`chmod 755 ${XRAY_BIN}`, { timeoutMs: 10_000 });
  for (const geo of ["geoip.dat", "geosite.dat"]) {
    const cpGeo = await conn.run(`cp ${DOWNLOAD_DIR}/${geo} ${XRAY_GEO_DIR}/${geo}`, {
      timeoutMs: 30_000,
    });
    if (cpGeo.code !== 0) {
      await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
      throw new Error(`installing ${geo} failed: ${errDetail(cpGeo.stderr)}`);
    }
  }
}

/** Upload unit + daemon-reload + enable (only when content differs), and
 *  re-assert the ENABLED state in both branches (stale-unit path and
 *  already-correct path): a box whose unit was disabled out-of-band would
 *  otherwise pass `deploy` and silently stop starting xray on the next
 *  reboot. Returns true when anything changed. */
async function ensureUnit(conn: SshConn): Promise<boolean> {
  const unitOut = await conn.run(`cat ${XRAY_UNIT} 2>/dev/null`, { timeoutMs: 10_000 });
  let changed = unitOut.stdout !== renderXrayUnit();
  if (changed) {
    await uploadRendered(conn, renderXrayUnit(), XRAY_UNIT, "xray.service");
    await conn.run("systemctl daemon-reload", { timeoutMs: 30_000 });
  }
  const enabled = await conn.run("systemctl is-enabled xray 2>/dev/null", { timeoutMs: 30_000 });
  if (enabled.code !== 0 || enabled.stdout.trim() !== "enabled") {
    const en = await conn.run("systemctl enable xray", { timeoutMs: 30_000 });
    if (en.code !== 0) {
      throw new Error(`systemctl enable xray failed: ${errDetail(en.stderr)}`);
    }
    changed = true;
  }
  return changed;
}

async function doInstall(conn: SshConn, ctx: StepCtx, opts: HardeningStepOptions): Promise<StepResult> {
  const pin = pinnedVersion(ctx.config.xray);

  const ver = await conn.run(`${XRAY_BIN} version 2>/dev/null`, { timeoutMs: 15_000 });
  const current = ver.code === 0 ? parseXrayVersion(ver.stdout) : undefined;

  if (current === pin) {
    // Already the pinned version — repair unit / geo assets if needed.
    const unitChanged = await ensureUnit(conn);

    const geoOut = await conn.run(`ls ${XRAY_GEO_DIR} 2>/dev/null`, { timeoutMs: 10_000 });
    const geoFiles = new Set(
      geoOut.stdout
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
    );
    let geoChanged = false;
    if (!geoFiles.has("geoip.dat") || !geoFiles.has("geosite.dat")) {
      await ensureUnzipRecorded(conn, ctx, opts);
      await downloadAndVerify(conn, ctx.config.xray);
      await extractAndInstall(conn);
      await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });
      geoChanged = true;
    }

    return unitChanged || geoChanged
      ? { status: "changed", detail: `Xray ${pin} present, repaired unit/geo assets` }
      : { status: "ok", detail: `Xray ${pin} already installed` };
  }

  // Fresh install or in-place upgrade.
  await ensureUnzipRecorded(conn, ctx, opts);

  await downloadAndVerify(conn, ctx.config.xray);
  await extractAndInstall(conn);
  await conn.run(`rm -rf ${DOWNLOAD_DIR}`, { timeoutMs: 10_000 });

  await ensureUnit(conn);

  return current === undefined
    ? { status: "changed", detail: `installed Xray ${pin}` }
    : { status: "changed", detail: `upgraded Xray ${current} → ${pin}` };
}

export function xrayInstallStep(opts: HardeningStepOptions = {}): Step {
  return {
    name: "Install pinned Xray",
    run: async (conn, ctx): Promise<StepResult> => {
      try {
        return await doInstall(conn, ctx, opts);
      } catch (err) {
        return { status: "failed", detail: err instanceof Error ? err.message : String(err) };
      }
    },
  };
}
