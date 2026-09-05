/**
 * Nginx + cert + pages steps (M6) — the public web layer on the wire.
 *
 * Deploy order (`nginxSteps`):
 *   ensure-cron → acme-install → acme-cron → acme-vhost (:80) →
 *   cert-issue → cert-deploy → page-deploy → web-vhost (:8443) →
 *   verify-page → verify-sub → verify-404 → verify-cert
 *
 * Binding decisions honored (contract §5):
 *  - D1 (+A3): `--keylength 2048` and pinned `--server letsencrypt`
 *    (current acme.sh releases default to ZeroSSL; the plan requires LE).
 *  - D2: cert-issue rc != 0/2 → step FAILED (pipeline stops).
 *  - D3: acme-cron ALWAYS re-runs `--install-cronjob` (always `changed`).
 *  - D4: install-cert always runs after a successful issue (rc 0 or 2);
 *    explicit `systemctl reload nginx` only when the deployed fullchain
 *    md5 changed.
 *  - D5: webroot `/var/www/acme`, site root `/var/www/viper/<name>`,
 *    cert dir `/etc/nginx/ssl/<domain>` (the M5 bootstrap's exact paths —
 *    the swap is in place, so Xray needs no config change or restart, D12).
 *  - D6: remote conf names `viper-acme.conf` (:80) + `viper-web.conf`
 *    (8443, replacing the M5 bootstrap file in place).
 *  - D8: all verifies go over the PUBLIC path
 *    (`curl --resolve <domain>:443:<ip>`) — proving the full Reality-fail →
 *    web vhost illusion path, not loopback.
 *
 * Teardown (`nginxTeardownSteps`, M6 scope per D10): viper's two vhosts +
 * symlinks (nginx -t + reload), the acme.sh renewal crontab entry, and the
 * web files (site root, cert dir, ACME webroot). Deliberately NOT touched:
 * the nginx package (M4's package-list ownership), `/root/.acme.sh/`
 * (plan + Meridian pitfall), and acme.sh itself.
 */
import { createHash } from "node:crypto";
import type { SshConn } from "../ssh.js";
import type { ServerConfig } from "../config.js";
import { publicHost } from "../config.js";
import type { Step, StepCtx, StepResult } from "./runner.js";
import { errDetail, uploadRendered, type HardeningStepOptions } from "./common.js";
import { renderNginx } from "../render/nginx.js";
import { PAGE_MARKER, renderPage } from "../render/page.js";
import { renderSub } from "../render/sub.js";

// ----------------------------------------------------------------- paths

export const ACME_SH = "/root/.acme.sh/acme.sh";
const ACME_WEBROOT = "/var/www/acme";
const ACME_VHOST = "/etc/nginx/sites-available/viper-acme.conf";
const ACME_VHOST_ENABLED = "/etc/nginx/sites-enabled/viper-acme.conf";
const WEB_VHOST = "/etc/nginx/sites-available/viper-web.conf";
const WEB_VHOST_ENABLED = "/etc/nginx/sites-enabled/viper-web.conf";
const CERT_DIR = (domain: string) => `/etc/nginx/ssl/${domain}`;
const SITE_ROOT = (name: string) => `/var/www/viper/${name}`;
const FULLCHAIN = (domain: string) => `${CERT_DIR(domain)}/fullchain.pem`;

/** The no-email installer form (Meridian pitfall: an `email=` arg crashes
 *  the installer with a `shift` error). */
export const ACME_INSTALL_CMD = "curl -fsSL https://get.acme.sh | sh -s --";
export const ACME_CRON_CMD = `${ACME_SH} --install-cronjob`;

const APT_UPDATE_CMD = "DEBIAN_FRONTEND=noninteractive apt-get update -qq";

const acmeIssueCmd = (domain: string) =>
  // A3: `--server letsencrypt` is pinned — current acme.sh releases default
  // to ZeroSSL, and the plan requires a Let's Encrypt cert. Pinned keeps
  // viper deterministic against future acme.sh default-CA changes.
  `${ACME_SH} --issue -d ${domain} --server letsencrypt --webroot ${ACME_WEBROOT} --keylength 2048 2>&1`;
const acmeInstallCertCmd = (domain: string) =>
  `${ACME_SH} --install-cert -d ${domain} ` +
  `--key-file ${CERT_DIR(domain)}/privkey.pem ` +
  `--fullchain-file ${FULLCHAIN(domain)} ` +
  `--reloadcmd "systemctl reload nginx" 2>&1`;

/** Public-path curl (D8): resolve <domain> to <ip> on the Xray port and hit
 *  Xray's front door — a 200 here proves Reality-fail → loopback web vhost. */
function publicCurl(ctx: StepCtx, path: string, codeOnly: boolean): string {
  const host = publicHost(ctx.config);
  const base = `curl -s --resolve ${ctx.config.domain}:${ctx.config.port}:${ctx.ip} --max-time 30`;
  const url = `https://${host}${path}`;
  return codeOnly ? `${base} -o /dev/null -w '%{http_code}' ${url}` : `${base} ${url}`;
}

/** Remote `md5sum` of a file → hex digest, or undefined when absent. */
async function remoteMd5(conn: SshConn, path: string): Promise<string | undefined> {
  const res = await conn.run(`md5sum ${path} 2>/dev/null`, { timeoutMs: 15_000 });
  if (res.code !== 0) return undefined;
  const hex = res.stdout.trim().split(/\s+/)[0];
  return hex !== undefined && /^[0-9a-f]{32}$/.test(hex) ? hex : undefined;
}

/**
 * Deploy a rendered vhost conf: check-then-act on the content (plus the
 * sites-enabled symlink), then `nginx -t` BEFORE any reload. On change:
 * SFTP upload → symlink → validate → reload.
 */
async function deployVhost(
  conn: SshConn,
  rendered: string,
  confPath: string,
  enabledPath: string,
  label: string,
): Promise<StepResult> {
  const current = await conn.run(`cat ${confPath} 2>/dev/null`, { timeoutMs: 15_000 });
  const fileMatches = current.code === 0 && current.stdout === rendered;
  const symlink = await conn.run(`test -L ${enabledPath}`, { timeoutMs: 10_000 });
  if (fileMatches && symlink.code === 0) {
    return { status: "ok", detail: `${label} unchanged` };
  }

  if (!fileMatches) {
    await uploadRendered(conn, rendered, confPath, confPath.split("/").pop() ?? "viper.conf");
  }
  const ln = await conn.run(`ln -sf ${confPath} ${enabledPath}`, { timeoutMs: 10_000 });
  if (ln.code !== 0) {
    return {
      status: "failed",
      detail: `symlinking ${enabledPath} failed: ${errDetail(ln.stderr)}`,
    };
  }
  const test = await conn.run("nginx -t", { timeoutMs: 30_000 });
  if (test.code !== 0) {
    return {
      status: "failed",
      detail: `nginx -t rejected the new config: ${errDetail(test.stderr || test.stdout)}`,
    };
  }
  const reload = await conn.run("systemctl reload nginx", { timeoutMs: 30_000 });
  if (reload.code !== 0) {
    return { status: "failed", detail: `nginx reload failed: ${errDetail(reload.stderr)}` };
  }
  return { status: "changed", detail: `${label} deployed, nginx reloaded` };
}

// ----------------------------------------------------------------- steps

/** 1 — cron package + active cron service (renewal depends on crontab). */
export function ensureCronStep(): Step {
  return {
    name: "Ensure cron service",
    run: async (conn): Promise<StepResult> => {
      // biome-ignore lint/suspicious/noTemplateCurlyInString: dpkg --showformat variable consumed by remote dpkg, not JS interpolation
      const check = await conn.run("dpkg-query -W --showformat='${Package} ${Status}\\n' cron", {
        timeoutMs: 15_000,
      });
      const installed = check.stdout.split("\n").some((line) => {
        const f = line.trim().split(/\s+/);
        return f[0] === "cron" && f[1] === "install" && f[3] === "installed";
      });

      let changed = false;
      if (!installed) {
        const update = await conn.run(APT_UPDATE_CMD, { timeoutMs: 180_000 });
        if (update.code !== 0) {
          return { status: "failed", detail: `apt-get update failed: ${errDetail(update.stderr)}` };
        }
        const install = await conn.run("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq cron", {
          timeoutMs: 300_000,
        });
        if (install.code !== 0) {
          return {
            status: "failed",
            detail: `apt-get install cron failed: ${errDetail(install.stderr)}`,
          };
        }
        changed = true;
      }

      const active = await conn.run("systemctl is-active cron", { timeoutMs: 15_000 });
      if (!(active.code === 0 && active.stdout.trim() === "active")) {
        const enable = await conn.run("systemctl enable --now cron", { timeoutMs: 30_000 });
        if (enable.code !== 0) {
          return {
            status: "failed",
            detail: `enabling cron failed: ${errDetail(enable.stderr || active.stderr)}`,
          };
        }
        changed = true;
      }

      return changed
        ? { status: "changed", detail: "cron installed/activated" }
        : { status: "ok", detail: "cron present and active" };
    },
  };
}

/** 2 — acme.sh installed (check-then-act; no email arg). */
export function acmeInstallStep(): Step {
  return {
    name: "Install acme.sh",
    run: async (conn): Promise<StepResult> => {
      const check = await conn.run(`test -f ${ACME_SH}`, { timeoutMs: 10_000 });
      if (check.code === 0) {
        return { status: "ok", detail: "already installed" };
      }
      const install = await conn.run(ACME_INSTALL_CMD, { timeoutMs: 120_000 });
      if (install.code !== 0) {
        return {
          status: "failed",
          detail: `acme.sh install failed: ${errDetail(install.stderr || install.stdout)}`,
        };
      }
      const again = await conn.run(`test -f ${ACME_SH}`, { timeoutMs: 10_000 });
      if (again.code !== 0) {
        return {
          status: "failed",
          detail: `acme.sh install reported success but ${ACME_SH} is missing`,
        };
      }
      return { status: "changed", detail: "acme.sh installed" };
    },
  };
}

/**
 * 3 — D3: ALWAYS re-run `--install-cronjob` (plan mandate: re-deploy always
 * re-installs the renewal cron). The one always-`changed` step in the list.
 */
export function acmeCronStep(): Step {
  return {
    name: "Install acme renewal cron",
    run: async (conn): Promise<StepResult> => {
      const res = await conn.run(ACME_CRON_CMD, { timeoutMs: 60_000 });
      if (res.code !== 0) {
        return {
          status: "failed",
          detail: `acme.sh --install-cronjob failed: ${errDetail(res.stderr || res.stdout)}`,
        };
      }
      return { status: "changed", detail: "renewal cron (re)installed — always, by design" };
    },
  };
}

/** 4 — :80 ACME vhost (must precede cert-issue so HTTP-01 is served). */
export function acmeVhostStep(rendered: string): Step {
  return {
    name: "Deploy ACME vhost (:80)",
    run: async (conn): Promise<StepResult> =>
      deployVhost(conn, rendered, ACME_VHOST, ACME_VHOST_ENABLED, "ACME vhost"),
  };
}

/**
 * 5 — D1/D2: issue the single-name LE domain cert (HTTP-01 via the :80
 * webroot). rc 0 = issued → changed; rc 2 = existing cert still valid →
 * ok; anything else → FAILED (stop the line).
 */
export function certIssueStep(): Step {
  return {
    name: "Issue Let's Encrypt cert",
    run: async (conn, ctx): Promise<StepResult> => {
      await conn.run(`mkdir -p ${ACME_WEBROOT}`, { timeoutMs: 10_000 });
      const res = await conn.run(acmeIssueCmd(ctx.config.domain), { timeoutMs: 300_000 });
      if (res.code === 2) {
        return { status: "ok", detail: "cert valid, skip (acme.sh rc 2)" };
      }
      if (res.code !== 0) {
        const detail = [res.stdout.trim(), res.stderr.trim()].filter(Boolean).join(" | ");
        return {
          status: "failed",
          detail: `certificate issuance failed (rc ${res.code}): ${errDetail(detail)}`,
        };
      }
      return { status: "changed", detail: `Let's Encrypt cert issued for ${ctx.config.domain}` };
    },
  };
}

/**
 * 6 — D4: ALWAYS re-run `--install-cert` after a successful issue (rc 0 or
 * 2 — re-running handles the hook-not-registered edge case and registers
 * the renewal hook). Explicit `systemctl reload nginx` only when the
 * deployed fullchain md5 changed; identical → ok, no reload.
 */
export function certDeployStep(): Step {
  return {
    name: "Deploy cert",
    run: async (conn, ctx): Promise<StepResult> => {
      const domain = ctx.config.domain;
      const fullchain = FULLCHAIN(domain);
      const md5Before = await remoteMd5(conn, fullchain);

      await conn.run(`mkdir -p ${CERT_DIR(domain)}`, { timeoutMs: 10_000 });
      const install = await conn.run(acmeInstallCertCmd(domain), { timeoutMs: 120_000 });
      if (install.code !== 0) {
        const detail = [install.stdout.trim(), install.stderr.trim()].filter(Boolean).join(" | ");
        return { status: "failed", detail: `cert install failed: ${errDetail(detail)}` };
      }

      const md5After = await remoteMd5(conn, fullchain);
      if (md5After === undefined) {
        return {
          status: "failed",
          detail: `install-cert reported success but ${fullchain} is missing`,
        };
      }
      if (md5After === md5Before) {
        return { status: "ok", detail: "cert valid, unchanged (no reload)" };
      }
      const reload = await conn.run("systemctl reload nginx", { timeoutMs: 30_000 });
      if (reload.code !== 0) {
        return {
          status: "failed",
          detail: `nginx reload after cert deploy failed: ${errDetail(reload.stderr)}`,
        };
      }
      return { status: "changed", detail: "cert deployed, nginx reloaded" };
    },
  };
}

/**
 * 7 — render locally (page + subscription), upload by SFTP with a remote
 * md5 content check (changed only when the bytes actually differ).
 * `heroBase64` is the project-dir seam (see `loadHeroBase64`).
 */
export function pageDeployStep(opts: { heroBase64?: string } = {}): Step {
  return {
    name: "Deploy page + subscription",
    run: async (conn, ctx): Promise<StepResult> => {
      if (opts.heroBase64 === undefined) {
        return {
          status: "failed",
          detail: "no heroBase64 seam provided (loadHeroBase64(projectDir))",
        };
      }
      const root = SITE_ROOT(ctx.name);
      const files: Array<[string, string]> = [
        ["index.html", renderPage(opts.heroBase64)],
        ["sub.txt", renderSub(ctx.config, ctx.state).base64],
      ];

      await conn.run(`mkdir -p ${root}`, { timeoutMs: 10_000 });
      const deployed: string[] = [];
      for (const [file, content] of files) {
        const local = createHash("md5").update(content).digest("hex");
        const remote = await remoteMd5(conn, `${root}/${file}`);
        if (remote === local) continue;
        await uploadRendered(conn, content, `${root}/${file}`, file);
        deployed.push(file);
      }
      return deployed.length > 0
        ? { status: "changed", detail: `deployed ${deployed.join(", ")}` }
        : { status: "ok", detail: "page and subscription unchanged" };
    },
  };
}

/** 8 — :8443 loopback web vhost (replaces the M5 bootstrap file in place). */
export function webVhostStep(rendered: string): Step {
  return {
    name: "Deploy web vhost (:8443)",
    run: async (conn): Promise<StepResult> =>
      deployVhost(conn, rendered, WEB_VHOST, WEB_VHOST_ENABLED, "web vhost"),
  };
}

// ------------------------------------------------------------- verifies

/** 9a — D8: the decoy page is served over the PUBLIC path at / and /login. */
export function verifyPageStep(): Step {
  return {
    name: "Verify decoy page (public path)",
    run: async (conn, ctx): Promise<StepResult> => {
      for (const path of ["/", "/login"]) {
        const codeRes = await conn.run(publicCurl(ctx, path, true), { timeoutMs: 60_000 });
        const code = codeRes.stdout.trim();
        if (code !== "200") {
          return {
            status: "failed",
            detail: `GET ${path} via public :443 returned HTTP ${code || "000"} (expected 200)`,
          };
        }
        const bodyRes = await conn.run(publicCurl(ctx, path, false), { timeoutMs: 60_000 });
        if (!bodyRes.stdout.includes(PAGE_MARKER)) {
          return { status: "failed", detail: `GET ${path} body is missing the page marker` };
        }
      }
      return { status: "ok", detail: "decoy page served at / and /login via public :443" };
    },
  };
}

/** 9b — D8: the subscription is served and is BYTE-IDENTICAL to the
 *  locally rendered artifact (vless lines with our pbk + the Happ routing
 *  line). The served file is exactly the SFTP-uploaded base64 blob, so an
 *  exact-body compare is the strongest available check: any mangling
 *  (truncation, re-encoding, a stale render) fails the step. */
export function verifySubStep(): Step {
  return {
    name: "Verify subscription (public path)",
    run: async (conn, ctx): Promise<StepResult> => {
      const path = `/${ctx.state.subHash}/sub.txt`;
      const codeRes = await conn.run(publicCurl(ctx, path, true), { timeoutMs: 60_000 });
      const code = codeRes.stdout.trim();
      if (code !== "200") {
        return {
          status: "failed",
          detail: `GET ${path} via public :443 returned HTTP ${code || "000"} (expected 200)`,
        };
      }
      const bodyRes = await conn.run(publicCurl(ctx, path, false), { timeoutMs: 60_000 });
      const expected = renderSub(ctx.config, ctx.state).base64.trim();
      const served = bodyRes.stdout.trim();
      if (served !== expected) {
        return {
          status: "failed",
          detail:
            `sub.txt does not byte-match the locally rendered subscription ` +
            `(served ${served.length} bytes, expected ${expected.length} ` +
            `— vless line with the state reality pbk + Happ routing line)`,
        };
      }
      return { status: "ok", detail: "subscription served, byte-identical to the local render" };
    },
  };
}

/** 9c — D8: unknown paths 404 over the public path. */
export function verify404Step(): Step {
  return {
    name: "Verify 404 (public path)",
    run: async (conn, ctx): Promise<StepResult> => {
      const codeRes = await conn.run(publicCurl(ctx, "/definitely-not-a-page", true), {
        timeoutMs: 60_000,
      });
      const code = codeRes.stdout.trim();
      if (code !== "404") {
        return {
          status: "failed",
          detail: `GET /definitely-not-a-page via public :443 returned HTTP ${code || "000"} (expected 404)`,
        };
      }
      return { status: "ok", detail: "unknown path 404s via public :443" };
    },
  };
}

/** 9d — the M5 carry-over verify: public :443 now presents OUR Let's
 *  Encrypt cert (Xray's Reality borrow dials 8443 live per handshake, so
 * no xray config change or restart was needed — D12). */
export function verifyCertStep(): Step {
  return {
    name: "Verify Let's Encrypt cert (public path)",
    run: async (conn, ctx): Promise<StepResult> => {
      const res = await conn.run(
        `echo | openssl s_client -connect ${ctx.ip}:443 -servername ${ctx.config.domain} ` +
          `2>/dev/null | openssl x509 -noout -issuer`,
        { timeoutMs: 60_000 },
      );
      if (!res.stdout.includes("Let's Encrypt")) {
        return {
          status: "failed",
          detail: `presented cert issuer is not Let's Encrypt (got: ${res.stdout.trim() || errDetail(res.stderr)})`,
        };
      }
      return {
        status: "ok",
        detail: "public :443 presents the Let's Encrypt cert (Reality borrow)",
      };
    },
  };
}

// ---------------------------------------------------------- step lists

export interface NginxStepOptions extends HardeningStepOptions {
  /**
   * Base64 of `assets/images/hero.webp` for the decoy page (project-dir
   * seam, M2 pattern — `loadHeroBase64(projectDir)`).
   */
  heroBase64?: string;
}

/**
 * The ordered M6 deploy list (contract §4). All confs are rendered locally
 * (pure) and travel by SFTP; every remote mutation is check-then-act except
 * the two documented always-runners (acme-cron D3, install-cert D4).
 */
export function nginxSteps(ctx: StepCtx, _config: ServerConfig, opts: NginxStepOptions = {}): Step[] {
  const confs = renderNginx(ctx.config, ctx.state);
  return [
    ensureCronStep(),
    acmeInstallStep(),
    acmeCronStep(),
    acmeVhostStep(confs["nginx-80.conf"]),
    certIssueStep(),
    certDeployStep(),
    pageDeployStep(opts),
    webVhostStep(confs["nginx-8443.conf"]),
    verifyPageStep(),
    verifySubStep(),
    verify404Step(),
    verifyCertStep(),
  ];
}

/**
 * M6-scope teardown (D10). Idempotent: nothing present → all ok, zero
 * mutating calls. Does NOT remove the nginx package (M4 ownership) or
 * `/root/.acme.sh/` (plan + Meridian pitfall) — documented in the report.
 */
export function nginxTeardownSteps(): Step[] {
  return [teardownVhostsStep(), teardownCronStep(), teardownWebFilesStep()];
}

export function teardownVhostsStep(): Step {
  return {
    name: "Remove viper nginx vhosts (teardown)",
    run: async (conn): Promise<StepResult> => {
      const present = await conn.run(`test -f ${ACME_VHOST} || test -f ${WEB_VHOST}`, {
        timeoutMs: 10_000,
      });
      if (present.code !== 0) {
        return { status: "ok", detail: "viper vhosts not present" };
      }
      const rm = await conn.run(
        `rm -f ${ACME_VHOST} ${WEB_VHOST} ${ACME_VHOST_ENABLED} ${WEB_VHOST_ENABLED}`,
        { timeoutMs: 10_000 },
      );
      if (rm.code !== 0) {
        return {
          status: "failed",
          detail: `removing viper vhosts failed: ${errDetail(rm.stderr)}`,
        };
      }
      const active = await conn.run("systemctl is-active nginx", { timeoutMs: 15_000 });
      if (active.code === 0 && active.stdout.trim() === "active") {
        const test = await conn.run("nginx -t", { timeoutMs: 30_000 });
        if (test.code !== 0) {
          return {
            status: "failed",
            detail: `nginx -t rejected the config after vhost removal: ${errDetail(test.stderr || test.stdout)}`,
          };
        }
        const reload = await conn.run("systemctl reload nginx", { timeoutMs: 30_000 });
        if (reload.code !== 0) {
          return { status: "failed", detail: `nginx reload failed: ${errDetail(reload.stderr)}` };
        }
      }
      return {
        status: "changed",
        detail: "removed viper-acme.conf + viper-web.conf (+ symlinks), nginx reloaded",
      };
    },
  };
}

export function teardownCronStep(): Step {
  return {
    name: "Remove acme renewal cron (teardown)",
    run: async (conn): Promise<StepResult> => {
      const has = await conn.run("crontab -l 2>/dev/null | grep -q 'acme.sh'", {
        timeoutMs: 15_000,
      });
      if (has.code !== 0) {
        return { status: "ok", detail: "no acme.sh cron entry" };
      }
      // Meridian's removal pattern: strip the acme.sh line(s), keep the
      // rest of the crontab. The trailing `; true` swallows the
      // empty-crontab edge; the re-check below is the arbiter.
      await conn.run("crontab -l 2>/dev/null | grep -v 'acme.sh' | crontab - 2>/dev/null; true", {
        timeoutMs: 15_000,
      });
      const after = await conn.run("crontab -l 2>/dev/null | grep -q 'acme.sh'", {
        timeoutMs: 15_000,
      });
      if (after.code === 0) {
        return { status: "failed", detail: "acme.sh cron entry still present after removal" };
      }
      return { status: "changed", detail: "acme renewal cron removed (/root/.acme.sh kept)" };
    },
  };
}

export function teardownWebFilesStep(): Step {
  return {
    name: "Remove viper web files (teardown)",
    run: async (conn, ctx): Promise<StepResult> => {
      const root = SITE_ROOT(ctx.name);
      const cert = CERT_DIR(ctx.config.domain);
      const present = await conn.run(`test -d ${root} || test -d ${cert} || test -d ${ACME_WEBROOT}`, {
        timeoutMs: 10_000,
      });
      if (present.code !== 0) {
        return { status: "ok", detail: "no viper web files" };
      }
      const rm = await conn.run(`rm -rf ${root} ${cert} ${ACME_WEBROOT}`, { timeoutMs: 30_000 });
      if (rm.code !== 0) {
        return { status: "failed", detail: `removing web files failed: ${errDetail(rm.stderr)}` };
      }
      return {
        status: "changed",
        detail: "removed site root, cert dir, ACME webroot (nginx package + /root/.acme.sh kept)",
      };
    },
  };
}
