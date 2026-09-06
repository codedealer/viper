import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import type { CommandResult, SshConn } from "../src/ssh.js";

/**
 * Stateful fake remote for the M4 step tests: emulates a minimal Ubuntu
 * host. Records every command, APPLIES the effects of mutating commands
 * (so a second step run sees the first run's final state), and returns
 * canned outputs for read-only commands. This is what makes the
 * run-twice idempotency tests meaningful: the second run must produce
 * ok/skipped with no mutating calls against the already-changed state.
 *
 * Live-OS behavior is NOT asserted here (M5/M6 wire verification).
 */

export interface FakeRemoteOptions {
  /** /etc/os-release ID (default ubuntu). */
  osId?: string;
  osVersion?: string;
  /** Free MB on / (default 5120). */
  diskFreeMb?: number;
  /** Effective sshd listen ports (default [22]). Empty = undetectable. */
  sshdPorts?: number[];
  /** sshd -t passes (default true). */
  sshdConfigOk?: boolean;
  /** Effective sshd -T settings (default: hardened + debianbanner). */
  effectiveSsh?: Record<string, string>;
  /** If set: after the neutralize loop runs once, the effective settings
   *  become this (simulates a conflicting drop-in that the loop
   *  sed-comments out). */
  effectiveSshAfterNeutralize?: Record<string, string>;
  /** /etc/os-release read fails with this stderr. */
  osReleaseFails?: string;
  /** Every SFTP upload throws with this message. */
  uploadFails?: string;
  /** Packages already installed (default: none of viper's four). */
  packages?: string[];
  /** If set: apt-get update fails with this stderr. */
  aptUpdateFails?: string;
  /** If set: apt-get install fails with this stderr. */
  aptInstallFails?: string;
  /** Current timezone (default UTC). */
  timezone?: string;
  /** timedatectl set-timezone fails (fallback ln is tried). */
  setTzFails?: boolean;
  /** ln -sf fallback fails too. */
  lnFails?: boolean;
  /** Existing /etc/apt/apt.conf.d/20auto-upgrades content (default: absent). */
  autoUpgradesFile?: string;
  /** Existing sshd drop-in content (default: absent). */
  sshdDropinFile?: string;
  /** fail2ban service active (default false). */
  fail2banActive?: boolean;
  /** Live sysctl values (default: none of bbr's). */
  sysctl?: Record<string, string>;
  /** Availability list for the singular key (default "reno cubic bbr"). */
  bbrAvailableSingular?: string;
  /** Availability list for the legacy key (default: key absent). */
  bbrAvailableLegacy?: string;
  /** sysctl -w fails with "No such file or directory" (kernel w/o BBR). */
  sysctlUnavailable?: boolean;
  /** sysctl -w fails with other stderr. */
  sysctlFails?: string;
  /** ufw installed (default true). */
  ufwInstalled?: boolean;
  /** ufw active (default false). */
  ufwActive?: boolean;
  /** Existing ufw rules, e.g. ["22/tcp"]. */
  ufwRules?: string[];
  ufwDefaultIn?: "deny" | "allow";
  ufwDefaultOut?: "deny" | "allow";
  /** The port whose `ufw allow` fails (others succeed). */
  ufwAllowFails?: number;
  /** Server host key buffer for hostKeyFingerprint (default: a fixed one). */
  hostKey?: Buffer;

  // --- xray (M5) ---
  /** xray binary installed (default false). */
  xrayInstalled?: boolean;
  /** Version reported by `xray version` (default "26.3.27"). */
  xrayVersion?: string;
  /** unzip available (default true). */
  unzipInstalled?: boolean;
  /** The release digest asset is missing (download 404). */
  dgstMissing?: boolean;
  /** sha256sum of the downloaded ZIP does not match the digest. */
  sha256Mismatch?: boolean;
  /** `xray -test` on the server config fails with this stderr. */
  xrayTestFails?: string;
  /** `xray -test` on the probe client config fails with this stderr. */
  xrayTestClientFails?: string;
  /** `systemctl restart xray` fails (unit exists but job fails). */
  xrayRestartFails?: boolean;
  /** xray unit active (default false; set by restart). */
  xrayActive?: boolean;
  /** Ports shown by `ss -tln` (default none). */
  listeningPorts?: number[];
  /** HTTP code the probe curl returns (default "204"). */
  probeCurlCode?: string;
  /** Pre-seeded unit content (default: absent). */
  xrayUnitFile?: string;
  /** xray unit enabled state (default: enabled iff the unit file was
   *  pre-seeded — a freshly uploaded unit is not enabled until viper
   *  runs `systemctl enable xray`). */
  xrayUnitEnabled?: boolean;
  /** Pre-seeded /etc/xray/config.json content (default: absent). */
  xrayConfigFile?: string;
  /** Installed but geo assets missing (default false). */
  xrayGeoMissing?: boolean;
  /** restart succeeds but the unit never becomes active. */
  xrayStaysInactive?: boolean;
  /** The probe xray binds its SOCKS port (default true). */
  probeComesUp?: boolean;
  /** Simulate a leftover orphan probe process from a previously failed run. */
  orphanProbe?: boolean;

  // --- nginx + acme (M6) ---
  /** cron package installed (default true — a stock VPS has it). */
  cronInstalled?: boolean;
  /** cron service active (default true). */
  cronServiceActive?: boolean;
  /** apt-installing cron leaves the service inactive (force the enable path). */
  cronInstallStartsService?: boolean;
  /** `systemctl enable --now cron` fails. */
  cronEnableFails?: boolean;
  /** nginx unit active (default true — M4 installed it). */
  nginxActive?: boolean;
  /** `nginx -t` rejects with this stderr. */
  nginxTestFails?: string;
  /** acme.sh already installed (default false). */
  acmeInstalled?: boolean;
  /** the acme.sh installer fails with this stderr. */
  acmeInstallFails?: string;
  /** the installer "succeeds" but leaves no acme.sh file. */
  acmeInstallLeavesNoFile?: boolean;
  /** `--install-cronjob` fails with this stderr. */
  acmeCronFails?: string;
  /** Force the `--issue` rc (default: 0 on first issue, 2 afterwards). */
  acmeIssueRc?: number;
  /** A cert was already issued before this run. */
  certIssued?: boolean;
  /** `--install-cert` fails with this stderr. */
  installCertFails?: string;
  /** The public web path answers 000 (connection failure) for every curl. */
  publicWebDown?: boolean;

  // --- status (M7) ---
  /** Per-client stats, keyed by the client NAME (the rendered config sets
   *  each user's email to the name; stat names are
   *  user>>><name>>>traffic>>>uplink|downlink). */
  stats?: Record<string, { uplink: number; downlink: number }>;
  /** `xray api statsquery` fails (unit down / API unreachable). */
  statsFails?: boolean;
  /** xray unit ActiveEnterTimestamp (default: empty = never entered active). */
  xrayActiveEnter?: string;
  /** Host uptime string (`uptime -p`). */
  hostUptime?: string;
  /** top Cpu(s) idle percent (default 95.0 → "5.0% used"). */
  cpuIdle?: number;
  /** free -m Mem total/used MB. */
  memTotalMb?: number;
  memUsedMb?: number;
  /** df -m / total/used MB. */
  diskTotalMb?: number;
  diskUsedMb?: number;
  /** Pre-seeded /var/www/viper/main/sub.txt (gives stat -c %y an mtime). */
  subFile?: string;
  /** Present cert subject/issuer/notAfter for the status cert probe. */
  certSubject?: string;
  certIssuer?: string;
  certNotAfter?: string;

  // --- IPv6 (M8) ---
  /** disable_ipv6 sysctls already 1/1 (default false = v6 enabled, like a
   *  stock provider VPS with an auto-assigned v6). */
  ipv6Disabled?: boolean;
  /** A global v6 address is present (default true; the kernel purges it
   *  when disable_ipv6 goes to 1). */
  ipv6GlobalAddr?: boolean;
  /** `sysctl -p` reports success but the sysctls stay 0 (verify-fail case). */
  ipv6Stuck?: boolean;
  /** The detached interface bounce triggers SLAAC reassignment (default
   *  true); false = the v6 address never returns (reboot-fallback path). */
  ipv6ReassignsAfterBounce?: boolean;
  /** Primary interface from the v4 default route (default "eth0"). */
  ipv6PrimaryIf?: string;
  /** The stock /etc/nginx/sites-enabled/default is present (default true —
   *  a stock Ubuntu box carries it). */
  stockDefaultSite?: boolean;
  /** The stock default site exists only as a BROKEN symlink (M1):
   *  `test -e` fails, `test -L` succeeds. */
  stockDefaultSiteBroken?: boolean;
}

/** The fake Let's Encrypt cert's md5 (stable across runs — run 2 = unchanged). */
const FAKE_LE_CERT_MD5 = "40cdd643a1940e23f59008083f062b3e";

export class FakeRemote implements SshConn {
  /** Every command run, in order. */
  commands: string[] = [];
  /** Every upload, in order (local file read at upload time). */
  uploads: Array<{ local: string; remote: string; content: string }> = [];
  /** Remote files written via upload, by path. */
  files = new Map<string, string>();

  // --- mutable remote state ---
  private packages: Set<string>;
  private timezone: string;
  private fail2banActive: boolean;
  private sysctl: Map<string, string>;
  private ufwActive: boolean;
  private ufwRules: Set<string>;
  private ufwDefaultIn: "deny" | "allow";
  private ufwDefaultOut: "deny" | "allow";
  /** xray (M5) mutable state. */
  private xrayInstalled: boolean;
  private xrayActive: boolean;
  private unzipInstalled: boolean;
  private zipDownloaded: boolean;
  private dgstDownloaded: boolean;
  private extracted: boolean;
  private geoFiles: Set<string>;
  private listeningPorts: Set<number>;
  private probeRunning: boolean;
  private probeLog: string;
  /** nginx + acme (M6) mutable state. */
  private cronServiceActive: boolean;
  private acmeInstalled: boolean;
  private crontabHasAcme: boolean;
  private certIssued: boolean;
  private deployedCertMd5: string | undefined;
  /** Effective sshd -T (mutable: the neutralize loop can fix it). */
  private effectiveSsh: Record<string, string>;
  /** xray unit enabled (mutable: enable/disable commands). */
  private xrayUnitEnabled: boolean;
  /** nginx reloads issued (idempotency assertions count these). */
  private nginxReloads = 0;
  private symlinks = new Set<string>();
  private dirs = new Set<string>();
  /** IPv6 (M8) mutable state. */
  private ipv6Disabled: boolean;
  private ipv6GlobalAddr: boolean;
  private stockDefaultSite: boolean;
  private stockDefaultSiteBroken: boolean;

  private readonly opts: Required<
    Pick<
      FakeRemoteOptions,
      | "osId"
      | "osVersion"
      | "diskFreeMb"
      | "sshdPorts"
      | "sshdConfigOk"
      | "effectiveSsh"
      | "packages"
      | "timezone"
      | "setTzFails"
      | "lnFails"
      | "fail2banActive"
      | "sysctl"
      | "bbrAvailableSingular"
      | "bbrAvailableLegacy"
      | "sysctlUnavailable"
      | "ufwInstalled"
      | "ufwActive"
      | "ufwRules"
      | "ufwDefaultIn"
      | "ufwDefaultOut"
    >
  > &
    FakeRemoteOptions;

  constructor(opts: FakeRemoteOptions = {}) {
    this.opts = {
      osId: "ubuntu",
      osVersion: "noble",
      diskFreeMb: 5120,
      sshdPorts: [22],
      sshdConfigOk: true,
      effectiveSsh: {
        passwordauthentication: "no",
        kbdinteractiveauthentication: "no",
        debianbanner: "no",
      },
      packages: [],
      timezone: "UTC",
      setTzFails: false,
      lnFails: false,
      fail2banActive: false,
      sysctl: {},
      bbrAvailableSingular: "reno cubic bbr",
      bbrAvailableLegacy: "",
      sysctlUnavailable: false,
      ufwInstalled: true,
      ufwActive: false,
      ufwRules: [],
      ufwDefaultIn: "allow",
      ufwDefaultOut: "allow",
      ...opts,
    };
    this.packages = new Set(this.opts.packages);
    if (this.opts.cronInstalled !== false) this.packages.add("cron");
    this.timezone = this.opts.timezone;
    this.fail2banActive = this.opts.fail2banActive;
    this.sysctl = new Map(Object.entries(this.opts.sysctl));
    this.ufwActive = this.opts.ufwActive;
    this.ufwRules = new Set(this.opts.ufwRules);
    this.ufwDefaultIn = this.opts.ufwDefaultIn;
    this.ufwDefaultOut = this.opts.ufwDefaultOut;
    this.xrayInstalled = this.opts.xrayInstalled ?? false;
    this.xrayActive = this.opts.xrayActive ?? false;
    this.unzipInstalled = this.opts.unzipInstalled ?? true;
    this.zipDownloaded = false;
    this.dgstDownloaded = false;
    this.extracted = false;
    this.geoFiles = new Set();
    if (this.xrayInstalled && !this.opts.xrayGeoMissing) this.geoFiles.add("geoip.dat").add("geosite.dat");
    this.listeningPorts = new Set(this.opts.listeningPorts ?? []);
    this.probeRunning = opts.orphanProbe === true;
    this.probeLog = "";
    this.effectiveSsh = { ...this.opts.effectiveSsh };
    this.xrayUnitEnabled = this.opts.xrayUnitEnabled ?? this.opts.xrayUnitFile !== undefined;
    this.cronServiceActive = this.opts.cronServiceActive ?? true;
    this.acmeInstalled = this.opts.acmeInstalled ?? false;
    this.crontabHasAcme = false;
    this.certIssued = this.opts.certIssued ?? false;
    // A valid acme.sh cert (certIssued) is NOT the same as a cert already
    // deployed to /etc/nginx/ssl — the deploy md5 starts empty.
    this.deployedCertMd5 = undefined;
    if (opts.autoUpgradesFile !== undefined) {
      this.files.set("/etc/apt/apt.conf.d/20auto-upgrades", opts.autoUpgradesFile);
    }
    if (opts.sshdDropinFile !== undefined) {
      this.files.set("/etc/ssh/sshd_config.d/00-viper.conf", opts.sshdDropinFile);
    }
    if (opts.xrayUnitFile !== undefined) {
      this.files.set("/etc/systemd/system/xray.service", opts.xrayUnitFile);
    }
    if (opts.xrayConfigFile !== undefined) {
      this.files.set("/etc/xray/config.json", opts.xrayConfigFile);
    }
    if (opts.subFile !== undefined) {
      this.files.set("/var/www/viper/main/sub.txt", opts.subFile);
    }
    this.ipv6Disabled = opts.ipv6Disabled ?? false;
    this.ipv6GlobalAddr = opts.ipv6GlobalAddr ?? true;
    this.stockDefaultSite = opts.stockDefaultSite ?? true;
    this.stockDefaultSiteBroken = opts.stockDefaultSiteBroken ?? false;
  }

  hostKeyFingerprint(): string | undefined {
    const key = this.opts.hostKey ?? Buffer.from("viper-test-host-key");
    return "SHA256:" + createHash("sha256").update(key).digest("base64").replace(/=+$/, "");
  }

  async close(): Promise<void> {}

  async upload(local: string, remote: string): Promise<void> {
    if (this.opts.uploadFails !== undefined) throw new Error(this.opts.uploadFails);
    const content = await readFile(local, "utf8");
    this.uploads.push({ local, remote, content });
    this.files.set(remote, content);
  }

  async run(cmd: string, _opts?: { timeoutMs?: number }): Promise<CommandResult> {
    this.commands.push(cmd);
    const ok = (stdout = ""): CommandResult => ({ stdout, stderr: "", code: 0 });
    const fail = (code: number, stderr: string): CommandResult => ({
      stdout: "",
      stderr,
      code,
    });

    // --- preflight ---
    if (cmd === `bash -c '. /etc/os-release && echo "$ID:$VERSION_CODENAME"'`) {
      if (this.opts.osReleaseFails !== undefined) return fail(1, this.opts.osReleaseFails);
      return ok(`${this.opts.osId}:${this.opts.osVersion}`);
    }
    if (cmd === "df -BM --output=avail / | tail -1") {
      return ok(`${this.opts.diskFreeMb}M`);
    }
    if (cmd.startsWith("sshd -T 2>/dev/null | awk")) {
      if (this.opts.sshdPorts.length === 0) return fail(1, "");
      return ok(this.opts.sshdPorts.join("\n") + "\n");
    }
    if (cmd.startsWith("grep -hEi")) {
      if (this.opts.sshdPorts.length === 0) return fail(1, "");
      return ok(this.opts.sshdPorts.join("\n") + "\n");
    }

    // --- packages ---
    // Mirrors real dpkg-query: the output fields follow the --showformat
    // string. Without `${Package}` in the format, the package name is NOT
    // printed (this is the exact divergence that broke live idempotency).
    if (cmd.startsWith("dpkg-query -W --showformat=")) {
      const m = cmd.match(/^dpkg-query -W --showformat='([^']*)' (.+)$/);
      const fmt = m !== null ? (m[1] ?? "") : "";
      const wanted = m !== null ? (m[2] ?? "").trim().split(/\s+/) : [];
      // biome-ignore lint/suspicious/noTemplateCurlyInString: dpkg --showformat variable string, not JS interpolation
      const withNames = fmt.includes("${Package}");
      const lines = wanted
        .filter((p) => this.packages.has(p))
        .map((p) => (withNames ? `${p} install ok installed` : "install ok installed"));
      const rc = lines.length === wanted.length ? 0 : 1;
      return { stdout: lines.join("\n") + (lines.length > 0 ? "\n" : ""), stderr: "", code: rc };
    }
    if (cmd === "DEBIAN_FRONTEND=noninteractive apt-get update -qq") {
      if (this.opts.aptUpdateFails !== undefined) return fail(100, this.opts.aptUpdateFails);
      return ok();
    }
    if (cmd.startsWith("DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ")) {
      if (this.opts.aptInstallFails !== undefined) return fail(100, this.opts.aptInstallFails);
      for (const p of cmd.split(/\s+/).slice(4)) {
        this.packages.add(p);
        if (p === "unzip") this.unzipInstalled = true;
        if (p === "cron" && this.opts.cronInstallStartsService !== false) this.cronServiceActive = true;
      }
      return ok();
    }

    // --- tz ---
    if (cmd === "timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null") {
      return ok(this.timezone + "\n");
    }
    if (cmd === "timedatectl set-timezone UTC") {
      if (this.opts.setTzFails) return fail(1, "Failed to set time zone: Operation not permitted");
      this.timezone = "UTC";
      return ok();
    }
    if (cmd === "ln -sf /usr/share/zoneinfo/UTC /etc/localtime") {
      if (this.opts.lnFails) return fail(1, "ln: failed to create symbolic link");
      this.timezone = "UTC";
      return ok();
    }

    // --- auto-upgrades ---
    if (cmd === "cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null") {
      const f = this.files.get("/etc/apt/apt.conf.d/20auto-upgrades");
      return f !== undefined ? ok(f) : fail(1, "");
    }
    if (cmd === "chmod 644 /etc/apt/apt.conf.d/20auto-upgrades") return ok();

    // --- ssh ---
    if (cmd === "cat /etc/ssh/sshd_config.d/00-viper.conf 2>/dev/null") {
      const f = this.files.get("/etc/ssh/sshd_config.d/00-viper.conf");
      return f !== undefined ? ok(f) : fail(1, "");
    }
    if (cmd === "chmod 644 /etc/ssh/sshd_config.d/00-viper.conf") return ok();
    if (cmd.startsWith("for f in /etc/ssh/sshd_config.d/*.conf; do")) {
      if (this.opts.effectiveSshAfterNeutralize !== undefined) {
        this.effectiveSsh = { ...this.opts.effectiveSshAfterNeutralize };
      }
      return ok();
    }
    if (cmd === "sshd -t") {
      return this.opts.sshdConfigOk ? ok() : fail(3, "/etc/ssh/sshd_config line 5: Bad configuration option");
    }
    if (cmd === "sshd -T 2>/dev/null") {
      const out = Object.entries(this.effectiveSsh)
        .map(([k, v]) => `${k} ${v}`)
        .join("\n");
      return ok(out + (out ? "\n" : ""));
    }
    if (cmd === "systemctl restart sshd 2>/dev/null || systemctl restart ssh") return ok();

    // --- fail2ban ---
    if (cmd === "systemctl is-active fail2ban") {
      return this.fail2banActive ? ok("active\n") : fail(3, "inactive\n");
    }
    if (cmd === "systemctl enable fail2ban") return ok();
    if (cmd === "systemctl restart fail2ban") {
      this.fail2banActive = true;
      return ok();
    }

    // --- bbr ---
    if (cmd === "sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null") {
      const v = this.sysctl.get("net.ipv4.tcp_congestion_control");
      return v !== undefined ? ok(v + "\n") : fail(1, "");
    }
    if (cmd === "sysctl -n net.core.default_qdisc 2>/dev/null") {
      const v = this.sysctl.get("net.core.default_qdisc");
      return v !== undefined ? ok(v + "\n") : fail(1, "");
    }
    if (cmd === "sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null") {
      const v = this.opts.bbrAvailableSingular;
      return v !== "" ? ok(v + "\n") : fail(1, "");
    }
    if (cmd === "sysctl -n net.ipv4.tcp_available_congestions 2>/dev/null") {
      const v = this.opts.bbrAvailableLegacy;
      return v !== "" ? ok(v + "\n") : fail(1, "");
    }
    if (cmd === "modprobe tcp_bbr 2>/dev/null") {
      // module "already loaded" → non-zero, ignored by the step
      return fail(1, "modprobe: FATAL: Module tcp_bbr not found in directory /lib/modules");
    }
    if (cmd === "cat /etc/sysctl.d/99-viper.conf 2>/dev/null") {
      const f = this.files.get("/etc/sysctl.d/99-viper.conf");
      return f !== undefined ? ok(f) : fail(1, "");
    }
    if (
      cmd === "sysctl -w net.core.default_qdisc=fq" ||
      cmd === "sysctl -w net.ipv4.tcp_congestion_control=bbr"
    ) {
      if (this.opts.sysctlUnavailable) {
        return fail(255, 'sysctl: cannot stat "/proc/sys/net/core/default_qdisc": No such file or directory');
      }
      if (this.opts.sysctlFails !== undefined) return fail(255, this.opts.sysctlFails);
      const key = cmd.slice("sysctl -w ".length).split("=")[0] as string;
      const value = cmd.split("=")[1] ?? "";
      this.sysctl.set(key, value);
      return ok(`${key} = ${value}`);
    }

    // --- IPv6 (M8) ---
    if (cmd === "sysctl -n net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.default.disable_ipv6") {
      const v = this.ipv6Disabled ? "1" : "0";
      return ok(`${v}\n${v}\n`);
    }
    if (cmd === "cat /etc/sysctl.d/99-viper-ipv6.conf 2>/dev/null") {
      const f = this.files.get("/etc/sysctl.d/99-viper-ipv6.conf");
      return f !== undefined ? ok(f) : fail(1, "");
    }
    if (cmd === "sysctl -p /etc/sysctl.d/99-viper-ipv6.conf") {
      if (!this.files.has("/etc/sysctl.d/99-viper-ipv6.conf")) {
        return fail(255, "sysctl: /etc/sysctl.d/99-viper-ipv6.conf: No such file or directory");
      }
      // Real sysctl -p echoes the file's contents on success.
      const echoed = (this.files.get("/etc/sysctl.d/99-viper-ipv6.conf") ?? "").trimEnd() + "\n";
      if (!this.opts.ipv6Stuck) {
        this.ipv6Disabled = true;
        // The kernel purges global v6 addresses (and the v6 default route)
        // when disable_ipv6 is set.
        this.ipv6GlobalAddr = false;
      }
      return ok(echoed);
    }
    if (cmd === "rm -f /etc/sysctl.d/99-viper-ipv6.conf") {
      this.files.delete("/etc/sysctl.d/99-viper-ipv6.conf");
      return ok();
    }
    if (cmd === "sysctl -w net.ipv6.conf.all.disable_ipv6=0") {
      this.ipv6Disabled = false;
      return ok("net.ipv6.conf.all.disable_ipv6 = 0");
    }
    if (cmd === "sysctl -w net.ipv6.conf.default.disable_ipv6=0") {
      this.ipv6Disabled = false;
      return ok("net.ipv6.conf.default.disable_ipv6 = 0");
    }
    if (cmd === "ip -6 addr show scope global") {
      if (!this.ipv6GlobalAddr || this.ipv6Disabled) return ok("");
      return ok(
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP group default \\\n" +
          "    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff\\n" +
          "    inet6 2a12:bec4:152d:100::122/56 scope global dynamic mngtmpaddr \\\n" +
          "       valid_lft forever preferred_lft forever\\n",
      );
    }
    if (cmd === "ip -6 route show default") {
      if (this.ipv6Disabled || !this.ipv6GlobalAddr) return ok("");
      return ok("default via fe80::1 dev eth0 \\n");
    }
    if (cmd === "ip -4 route show default | awk '/default/{print $5;exit}'") {
      return ok(`${this.opts.ipv6PrimaryIf ?? "eth0"}\n`);
    }
    const bounce = cmd.match(
      /^nohup sh -c 'sleep 1; ip link set dev (\S+) down; sleep 2; ip link set dev \1 up' >\/tmp\/viper-ipv6-rev\.log 2>&1 &$/,
    );
    if (bounce !== null) {
      if (this.opts.ipv6ReassignsAfterBounce !== false && !this.ipv6Disabled) {
        this.ipv6GlobalAddr = true;
      }
      return ok();
    }

    // --- stock nginx default site (M8 D3) ---
    // M1: the step checks `test -e … || test -L …` — a broken symlink
    // (target gone, link present) is still a site entry and must be removed.
    if (cmd === "test -e /etc/nginx/sites-enabled/default || test -L /etc/nginx/sites-enabled/default") {
      return this.stockDefaultSite || this.stockDefaultSiteBroken ? ok() : fail(1, "");
    }
    if (cmd === "rm /etc/nginx/sites-enabled/default") {
      if (!this.stockDefaultSite && !this.stockDefaultSiteBroken) {
        return fail(1, "rm: cannot remove '/etc/nginx/sites-enabled/default': No such file or directory");
      }
      this.stockDefaultSite = false;
      this.stockDefaultSiteBroken = false;
      return ok();
    }

    // --- ufw ---
    if (cmd === "which ufw 2>/dev/null") {
      return this.opts.ufwInstalled ? ok("/usr/sbin/ufw\n") : fail(1, "");
    }
    if (cmd === "ufw status") {
      if (!this.ufwActive) return ok("Status: inactive\n");
      // Plain `ufw status` on real Ubuntu 24.04: rule table (incl. v6)
      // but NO Default/Logging lines — the live run-2 anomaly root
      // cause (captured 2026-08-31, see live_verification.md).
      const rules = [...this.ufwRules]
        .sort()
        .map((r) => `${r}                     ALLOW IN    Anywhere`)
        .join("\n");
      return ok(
        "Status: active\n\n" +
          "To                         Action      From\n--                         ------      ----\n" +
          rules +
          "\n",
      );
    }
    if (cmd === "ufw status verbose") {
      if (!this.ufwActive) return ok("Status: inactive\n");
      const v4 = [...this.ufwRules]
        .sort()
        .map((r) => `${r}                     ALLOW IN    Anywhere`)
        .join("\n");
      const v6 = [...this.ufwRules]
        .sort()
        .map((r) => `${r} (v6)               ALLOW IN    Anywhere (v6)`)
        .join("\n");
      return ok(
        "Status: active\n" +
          "Logging: on (low)\n" +
          `Default: ${this.ufwDefaultIn} (incoming), ${this.ufwDefaultOut} (outgoing), disabled (routed)\n` +
          "New profiles: skip\n\n" +
          "To                         Action      From\n--                         ------      ----\n" +
          v4 +
          "\n" +
          v6 +
          "\n",
      );
    }
    const allow = cmd.match(/^ufw allow (\d+)\/tcp$/);
    if (allow !== null) {
      const rule = `${allow[1]}/tcp`;
      if (!this.opts.ufwInstalled) return fail(1, "ufw: command not found");
      if (this.ufwRules.has(rule)) return ok("Skipping adding existing rule\n");
      if (allow[1] !== undefined && Number(allow[1]) === this.opts.ufwAllowFails) {
        return fail(1, "ERROR: problem running ufw");
      }
      this.ufwRules.add(rule);
      return ok("Rule added\n");
    }
    if (cmd === "ufw default deny incoming") {
      this.ufwDefaultIn = "deny";
      return ok("Default incoming policy changed to 'deny'\n");
    }
    if (cmd === "ufw default allow outgoing") {
      this.ufwDefaultOut = "allow";
      return ok("Default outgoing policy changed to 'allow'\n");
    }
    if (cmd === "ufw --force enable") {
      this.ufwActive = true;
      return ok("Firewall is active and enabled on system startup\n");
    }
    if (cmd === "ufw reload") return ok("Updated rules\n");

    // --- xray install (M5) ---
    if (cmd === "which unzip 2>/dev/null") {
      return this.unzipInstalled ? ok("/usr/bin/unzip\n") : fail(1, "");
    }
    if (cmd === "/usr/local/bin/xray version 2>/dev/null") {
      if (!this.xrayInstalled) return fail(127, "");
      return ok(`Xray ${this.opts.xrayVersion ?? "26.3.27"} (Xray, Penetrates Everything) viper-fake\n`);
    }
    if (cmd === "mkdir -p /tmp/viper-xray") return ok();
    if (
      cmd.startsWith("curl -fsSL --max-time 300 ") &&
      cmd.endsWith("-o /tmp/viper-xray/Xray-linux-64.zip")
    ) {
      this.zipDownloaded = true;
      return ok();
    }
    if (
      cmd.startsWith("curl -fsSL --max-time 60 ") &&
      cmd.endsWith("-o /tmp/viper-xray/Xray-linux-64.zip.dgst")
    ) {
      if (this.opts.dgstMissing) return fail(22, "curl: (22) The requested URL returned error: 404");
      this.dgstDownloaded = true;
      return ok();
    }
    if (cmd === "grep '^SHA2-256=' /tmp/viper-xray/Xray-linux-64.zip.dgst | awk '{print $2}'") {
      if (!this.dgstDownloaded)
        return fail(2, "grep: /tmp/viper-xray/Xray-linux-64.zip.dgst: No such file or directory");
      // The real v26.3.27 asset digest (captured from the GitHub release).
      return ok("23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae\n");
    }
    if (cmd === "sha256sum /tmp/viper-xray/Xray-linux-64.zip | awk '{print $1}'") {
      if (!this.zipDownloaded)
        return fail(1, "sha256sum: /tmp/viper-xray/Xray-linux-64.zip: No such file or directory");
      const hex = this.opts.sha256Mismatch
        ? "0000000000000000000000000000000000000000000000000000000000000000"
        : "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae";
      return ok(hex + "\n");
    }
    if (cmd === "cd /tmp/viper-xray && unzip -o Xray-linux-64.zip") {
      if (!this.unzipInstalled) return fail(127, "sh: 1: unzip: not found");
      if (!this.zipDownloaded)
        return fail(9, "unzip:  cannot find zipfile directory in what was specified on command line");
      this.extracted = true;
      return ok("Archive:  Xray-linux-64.zip\n");
    }
    if (cmd === "mkdir -p /usr/local/share/xray") return ok();
    if (cmd === "cp /tmp/viper-xray/xray /usr/local/bin/xray") {
      if (!this.extracted)
        return fail(1, "cp: cannot stat '/tmp/viper-xray/xray': No such file or directory");
      this.xrayInstalled = true;
      return ok();
    }
    if (cmd === "chmod 755 /usr/local/bin/xray") return ok();
    if (cmd === "cp /tmp/viper-xray/geoip.dat /usr/local/share/xray/geoip.dat") {
      if (!this.extracted)
        return fail(1, "cp: cannot stat '/tmp/viper-xray/geoip.dat': No such file or directory");
      this.geoFiles.add("geoip.dat");
      return ok();
    }
    if (cmd === "cp /tmp/viper-xray/geosite.dat /usr/local/share/xray/geosite.dat") {
      if (!this.extracted)
        return fail(1, "cp: cannot stat '/tmp/viper-xray/geosite.dat': No such file or directory");
      this.geoFiles.add("geosite.dat");
      return ok();
    }
    if (cmd === "ls /usr/local/share/xray 2>/dev/null") {
      if (this.geoFiles.size === 0 && !this.xrayInstalled)
        return fail(2, "ls: cannot access '/usr/local/share/xray': No such file or directory");
      return ok([...this.geoFiles].sort().join("\n") + "\n");
    }
    if (cmd === "cat /etc/systemd/system/xray.service 2>/dev/null") {
      const f = this.files.get("/etc/systemd/system/xray.service");
      return f !== undefined ? ok(f) : fail(1, "");
    }
    if (cmd === "systemctl daemon-reload") return ok();
    if (cmd === "systemctl is-enabled xray 2>/dev/null") {
      if (!this.files.has("/etc/systemd/system/xray.service") || !this.xrayUnitEnabled) {
        return fail(1, "disabled\n");
      }
      return ok("enabled\n");
    }
    if (cmd === "systemctl enable xray") {
      if (!this.files.has("/etc/systemd/system/xray.service")) {
        return fail(1, "Failed to enable unit: Unit file xray.service does not exist.");
      }
      this.xrayUnitEnabled = true;
      return ok();
    }
    if (cmd === "rm -rf /tmp/viper-xray") {
      this.zipDownloaded = false;
      this.dgstDownloaded = false;
      this.extracted = false;
      return ok();
    }

    // --- xray deploy (M5) ---
    if (cmd === "mkdir -p /var/log/xray") return ok();
    if (cmd === "cat /etc/xray/config.json 2>/dev/null") {
      const f = this.files.get("/etc/xray/config.json");
      return f !== undefined ? ok(f) : fail(1, "");
    }
    if (cmd === "cd /usr/local/share/xray && xray -test -c /etc/xray/config.new.json") {
      if (!this.xrayInstalled) return fail(127, "sh: 1: xray: not found");
      if (this.opts.xrayTestFails !== undefined) return fail(2, this.opts.xrayTestFails);
      return ok();
    }
    if (cmd === "rm -f /etc/xray/config.new.json") {
      this.files.delete("/etc/xray/config.new.json");
      return ok();
    }
    if (cmd === "rm -f /etc/xray/config.json.tmp") {
      // legacy staged name (pre-.json-suffix fix) — stale-file cleanup
      this.files.delete("/etc/xray/config.json.tmp");
      return ok();
    }
    if (cmd === "mv /etc/xray/config.new.json /etc/xray/config.json") {
      const tmp = this.files.get("/etc/xray/config.new.json");
      if (tmp === undefined)
        return fail(1, "mv: cannot stat '/etc/xray/config.new.json': No such file or directory");
      this.files.set("/etc/xray/config.json", tmp);
      this.files.delete("/etc/xray/config.new.json");
      return ok();
    }
    if (cmd === "systemctl restart xray") {
      if (!this.files.has("/etc/systemd/system/xray.service")) {
        return fail(3, "Unit xray.service not found.");
      }
      if (this.opts.xrayRestartFails)
        return fail(1, "Job for xray.service failed because the control process exited with error code.");
      this.xrayActive = !this.opts.xrayStaysInactive;
      return ok();
    }
    if (cmd === "systemctl is-active xray") {
      return this.xrayActive ? ok("active\n") : fail(3, "inactive\n");
    }

    // --- xray verify (M5) ---
    if (cmd === "ss -tln") {
      const ports = [...this.listeningPorts];
      if (this.probeRunning) ports.push(10809);
      const header = "State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port";
      const lines = ports.map((p) => `LISTEN  0        511        0.0.0.0:${p}        0.0.0.0:*`);
      return ok([header, ...lines].join("\n") + "\n");
    }
    if (cmd === "mkdir -p /tmp/viper-probe") return ok();
    if (cmd === "cd /usr/local/share/xray && xray -test -c /tmp/viper-probe/config.json") {
      if (this.opts.xrayTestClientFails !== undefined) return fail(2, this.opts.xrayTestClientFails);
      return ok();
    }
    if (
      cmd ===
      "(cd /usr/local/share/xray && exec nohup xray run -c /tmp/viper-probe/config.json > /tmp/viper-probe/xray.log 2>&1 < /dev/null) & echo $!"
    ) {
      if (!this.xrayInstalled) {
        this.probeRunning = false;
        this.probeLog = "nohup: failed to run command 'xray': No such file or directory";
        return ok("99999\n");
      }
      if (this.opts.probeComesUp === false) {
        this.probeRunning = false;
        this.probeLog =
          "Xray 26.3.27 (Xray, Penetrates Everything) viper-fake\nError: listen tcp 127.0.0.1:10809: bind: address already in use";
        return ok("12345\n");
      }
      this.probeRunning = true;
      this.probeLog = "Xray 26.3.27 (Xray, Penetrates Everything) viper-fake";
      return ok("12345\n");
    }
    if (cmd.startsWith("curl --socks5-hostname 127.0.0.1:10809 ")) {
      return ok(this.opts.probeCurlCode ?? "204");
    }
    if (cmd === "tail -n 30 /tmp/viper-probe/xray.log 2>/dev/null") {
      return this.probeLog !== "" ? ok(this.probeLog + "\n") : fail(1, "");
    }
    if (cmd === "pkill -f 'xray run -c /tmp/viper-probe/[c]onfig.json' 2>/dev/null || true") {
      this.probeRunning = false;
      return ok();
    }
    if (cmd.startsWith("kill ")) {
      this.probeRunning = false;
      return ok();
    }
    if (cmd === "rm -rf /tmp/viper-probe") return ok();

    // --- xray teardown (M5) ---
    if (
      cmd ===
      "test -f /usr/local/bin/xray || test -f /etc/systemd/system/xray.service || test -f /etc/xray/config.json"
    ) {
      const present =
        this.xrayInstalled ||
        this.files.has("/etc/systemd/system/xray.service") ||
        this.files.has("/etc/xray/config.json");
      return present ? ok() : fail(1, "");
    }
    if (cmd === "systemctl disable --now xray 2>/dev/null") {
      this.xrayActive = false;
      this.xrayUnitEnabled = false;
      return ok();
    }
    if (cmd === "rm -f /etc/systemd/system/xray.service") {
      this.files.delete("/etc/systemd/system/xray.service");
      return ok();
    }
    if (cmd === "rm -f /usr/local/bin/xray") {
      this.xrayInstalled = false;
      return ok();
    }
    if (cmd === "rm -rf /usr/local/share/xray") {
      this.geoFiles.clear();
      return ok();
    }
    if (cmd === "rm -rf /etc/xray") {
      this.files.delete("/etc/xray/config.json");
      return ok();
    }

    // --- cron (M6) ---
    if (cmd === "systemctl is-active cron") {
      return this.cronServiceActive ? ok("active\n") : fail(3, "inactive\n");
    }
    if (cmd === "systemctl enable --now cron") {
      if (this.opts.cronEnableFails) return fail(1, "Failed to enable cron.service");
      this.cronServiceActive = true;
      return ok();
    }

    // --- acme.sh (M6) ---
    if (cmd === "test -f /root/.acme.sh/acme.sh") {
      return this.acmeInstalled ? ok() : fail(1, "");
    }
    if (cmd === "curl -fsSL https://get.acme.sh | sh -s --") {
      if (this.opts.acmeInstallFails !== undefined) return fail(23, this.opts.acmeInstallFails);
      if (this.opts.acmeInstallLeavesNoFile) return ok();
      this.acmeInstalled = true;
      return ok("Installing acme.sh to /root/.acme.sh/acme.sh\n");
    }
    if (cmd === "/root/.acme.sh/acme.sh --install-cronjob") {
      if (!this.acmeInstalled) return fail(127, "sh: 1: /root/.acme.sh/acme.sh: not found");
      if (this.opts.acmeCronFails !== undefined) return fail(1, this.opts.acmeCronFails);
      this.crontabHasAcme = true;
      return ok("The cron job had been installed for auto renewal.\n");
    }
    if (
      /^\/root\/\.acme\.sh\/acme\.sh --issue -d \S+ --server letsencrypt --webroot \/var\/www\/acme --keylength 2048 2>&1$/.test(
        cmd,
      )
    ) {
      if (this.opts.acmeIssueRc !== undefined) {
        if (this.opts.acmeIssueRc === 0) this.certIssued = true;
        return { stdout: "[Issue] ok\n", stderr: "", code: this.opts.acmeIssueRc };
      }
      if (!this.certIssued) {
        this.certIssued = true;
        return ok(
          "[Issue] Account updated.\n[Issue] ACME server validated our request.\n[issuance] Success\n",
        );
      }
      // acme.sh rc 2: existing cert still valid — skip renewal.
      return { stdout: "The cert is still valid, no need to renew.\n", stderr: "", code: 2 };
    }
    if (
      /^\/root\/\.acme\.sh\/acme\.sh --install-cert -d \S+ --key-file \/etc\/nginx\/ssl\/\S+\/privkey\.pem --fullchain-file \/etc\/nginx\/ssl\/\S+\/fullchain\.pem --reloadcmd "systemctl reload nginx" 2>&1$/.test(
        cmd,
      )
    ) {
      if (this.opts.installCertFails !== undefined) return fail(1, this.opts.installCertFails);
      if (!this.certIssued) return fail(1, "Can not find the cert for this domain");
      // Copies acme.sh's stored cert into place; the md5 is stable so an
      // unchanged re-run is md5-identical (the D4 no-reload path).
      this.deployedCertMd5 = FAKE_LE_CERT_MD5;
      return ok("install cert success\n");
    }

    // --- nginx vhosts (M6) ---
    if (
      cmd === "cat /etc/nginx/sites-available/viper-acme.conf 2>/dev/null" ||
      cmd === "cat /etc/nginx/sites-available/viper-web.conf 2>/dev/null"
    ) {
      const f = this.files.get(cmd.slice("cat ".length, -" 2>/dev/null".length));
      return f !== undefined ? ok(f) : fail(1, "");
    }
    if (
      cmd === "test -L /etc/nginx/sites-enabled/viper-acme.conf" ||
      cmd === "test -L /etc/nginx/sites-enabled/viper-web.conf"
    ) {
      return this.symlinks.has(cmd.slice("test -L ".length)) ? ok() : fail(1, "");
    }
    if (
      cmd === "ln -sf /etc/nginx/sites-available/viper-acme.conf /etc/nginx/sites-enabled/viper-acme.conf" ||
      cmd === "ln -sf /etc/nginx/sites-available/viper-web.conf /etc/nginx/sites-enabled/viper-web.conf"
    ) {
      this.symlinks.add(cmd.split(" ")[3] as string);
      return ok();
    }
    if (cmd === "nginx -t") {
      if (this.opts.nginxTestFails !== undefined) return fail(1, this.opts.nginxTestFails);
      // Real nginx -t writes its report to stderr even on success.
      return {
        stdout: "",
        stderr:
          "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok\n" +
          "nginx: configuration file /etc/nginx/nginx.conf test is successful",
        code: 0,
      };
    }
    if (cmd === "systemctl reload nginx") {
      this.nginxReloads++;
      return ok();
    }
    if (cmd === "systemctl is-active nginx") {
      return this.opts.nginxActive !== false ? ok("active\n") : fail(3, "inactive\n");
    }
    if (/^mkdir -p \S+$/.test(cmd)) {
      this.dirs.add(cmd.slice("mkdir -p ".length));
      return ok();
    }

    // --- md5sum (M6 content checks) ---
    const md5 = cmd.match(/^md5sum (\S+) 2>\/dev\/null$/);
    if (md5 !== null) {
      const p = md5[1] as string;
      if (p.endsWith("/fullchain.pem")) {
        return this.deployedCertMd5 !== undefined ? ok(`${this.deployedCertMd5}  ${p}\n`) : fail(1, "");
      }
      const f = this.files.get(p);
      return f !== undefined ? ok(`${createHash("md5").update(f).digest("hex")}  ${p}\n`) : fail(1, "");
    }

    // --- public web path (M6 verifies, D8: curl --resolve <domain>:<port>:<ip>) ---
    const curl = cmd.match(
      /^curl -s --resolve ([^:]+):([0-9]+):([^ ]+) --max-time 30( -o \/dev\/null -w '%{http_code}')? https:\/\/[^ ]+$/,
    );
    if (curl !== null) {
      const url = cmd.slice(cmd.lastIndexOf("https://"));
      const path = url.replace(/^https:\/\/[^/]+/, "") || "/";
      const codeOnly = curl[4] !== undefined; // groups: 1=domain 2=port 3=ip 4=code-only flag
      if (this.opts.publicWebDown) {
        return codeOnly ? ok("000") : fail(6, "curl: (6) Could not resolve host");
      }
      const webReady =
        this.symlinks.has("/etc/nginx/sites-enabled/viper-web.conf") &&
        this.files.has("/etc/nginx/sites-available/viper-web.conf") &&
        this.certIssued;
      if (!webReady) return codeOnly ? ok("000") : ok("");
      const siteKeys = [...this.files.keys()].filter((k) => k.startsWith("/var/www/viper/"));
      const indexKey = siteKeys.find((k) => k.endsWith("/index.html"));
      const subKey = siteKeys.find((k) => k.endsWith("/sub.txt"));
      let code = "404";
      let body = "";
      if ((path === "/" || path === "/login") && indexKey !== undefined) {
        code = "200";
        body = this.files.get(indexKey) ?? "";
      } else if (subKey !== undefined && path.split("/").length === 3 && path.endsWith("/sub.txt")) {
        code = "200";
        body = this.files.get(subKey) ?? "";
      }
      return codeOnly ? ok(code) : ok(body);
    }

    // --- status (M7) ---
    if (cmd === "/usr/local/bin/xray version") {
      if (!this.xrayInstalled) return fail(127, "sh: 1: /usr/local/bin/xray: not found");
      return ok(`Xray ${this.opts.xrayVersion ?? "26.3.27"} (Xray, Penetrates Everything) viper-fake\n`);
    }
    if (cmd === "systemctl show xray -p ActiveEnterTimestamp --value") {
      return ok((this.opts.xrayActiveEnter ?? "") + "\n");
    }
    if (cmd === "uptime -p") {
      return ok((this.opts.hostUptime ?? "up 3 hours, 12 minutes") + "\n");
    }
    if (cmd === "LC_ALL=C top -bn1") {
      const idle = this.opts.cpuIdle ?? 95.0;
      const busy = Math.max(0, 100 - idle);
      return ok(
        "top - 12:00:00 up 3:12,  2 users,  load average: 0.05, 0.07, 0.08\n" +
          "Tasks:   250 total,   1 running, 249 sleeping\n" +
          `%Cpu(s):  ${busy.toFixed(1)} us,  0.0 sy,  0.0 ni, ${idle.toFixed(1)} id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st\n` +
          "MiB Mem :   7828.5 total\n",
      );
    }
    if (cmd === "free -m") {
      const total = this.opts.memTotalMb ?? 7828;
      const used = this.opts.memUsedMb ?? 1234;
      return ok(
        "               total        used        free      shared  buff/cache   available\n" +
          `Mem:            ${total}       ${used}       ${total - used}         123        3138        ${total - used}\n` +
          "Swap:             0           0           0\n",
      );
    }
    if (cmd === "df -m /") {
      const total = this.opts.diskTotalMb ?? 40900;
      const used = this.opts.diskUsedMb ?? 5120;
      return ok(
        "Filesystem     1M-blocks  Used Available Use% Mounted on\n" +
          `/dev/vda1          ${total}  ${used}    ${total - used}  ${Math.round((used / total) * 100)}% /\n`,
      );
    }
    if (cmd.startsWith("/usr/local/bin/xray api statsquery --server=")) {
      if (this.opts.statsFails) return fail(1, "connection refused");
      if (!this.xrayInstalled) return fail(127, "sh: 1: /usr/local/bin/xray: not found");
      const stat: Array<{ name: string; value: string }> = [];
      for (const [name, s] of Object.entries(this.opts.stats ?? {})) {
        stat.push({ name: `user>>>${name}>>>traffic>>>uplink`, value: String(s.uplink) });
        stat.push({ name: `user>>>${name}>>>traffic>>>downlink`, value: String(s.downlink) });
      }
      return ok(JSON.stringify({ stat }));
    }
    if (cmd === "stat -c %y /var/www/viper/main/sub.txt 2>/dev/null") {
      if (!this.files.has("/var/www/viper/main/sub.txt")) {
        return fail(1, "stat: cannot statx '/var/www/viper/main/sub.txt': No such file or directory");
      }
      return ok("2026-09-01 01:00:00.000000000 +0000\n");
    }
    if (
      /^echo \| openssl s_client -connect \S+:443 -servername \S+ 2>\/dev\/null \| openssl x509 -noout -subject -issuer -enddate$/.test(
        cmd,
      )
    ) {
      if (!this.certIssued) return fail(1, "");
      return ok(
        `subject=${this.opts.certSubject ?? "CN = viper.example"}\n` +
          `issuer=${this.opts.certIssuer ?? "C = US, O = Let's Encrypt, CN = R3"}\n` +
          `notAfter=${this.opts.certNotAfter ?? "Sep 30 00:00:00 2026 GMT"}\n`,
      );
    }

    // --- cert borrow probe (M6 verify-cert) ---
    if (
      /^echo \| openssl s_client -connect \S+:443 -servername \S+ 2>\/dev\/null \| openssl x509 -noout -issuer$/.test(
        cmd,
      )
    ) {
      return this.certIssued
        ? ok("issuer=C = US, O = Let's Encrypt, CN = R3\n")
        : ok("issuer=CN = viper bootstrap self-signed\n");
    }

    // --- nginx/acme teardown (M6) ---
    if (
      cmd ===
      "test -f /etc/nginx/sites-available/viper-acme.conf || test -f /etc/nginx/sites-available/viper-web.conf"
    ) {
      return this.files.has("/etc/nginx/sites-available/viper-acme.conf") ||
        this.files.has("/etc/nginx/sites-available/viper-web.conf")
        ? ok()
        : fail(1, "");
    }
    if (
      cmd ===
      "rm -f /etc/nginx/sites-available/viper-acme.conf /etc/nginx/sites-available/viper-web.conf /etc/nginx/sites-enabled/viper-acme.conf /etc/nginx/sites-enabled/viper-web.conf"
    ) {
      this.files.delete("/etc/nginx/sites-available/viper-acme.conf");
      this.files.delete("/etc/nginx/sites-available/viper-web.conf");
      this.symlinks.delete("/etc/nginx/sites-enabled/viper-acme.conf");
      this.symlinks.delete("/etc/nginx/sites-enabled/viper-web.conf");
      return ok();
    }
    if (cmd === "crontab -l 2>/dev/null | grep -q 'acme.sh'") {
      return this.crontabHasAcme ? ok() : fail(1, "");
    }
    if (cmd === "crontab -l 2>/dev/null | grep -v 'acme.sh' | crontab - 2>/dev/null; true") {
      this.crontabHasAcme = false;
      return ok();
    }
    const testDirs = cmd.match(/^test -d (\S+) \\|\\| test -d (\S+) \\|\\| test -d (\S+)$/);
    if (testDirs !== null) {
      return this.dirs.has(testDirs[1] as string) ||
        this.dirs.has(testDirs[2] as string) ||
        this.dirs.has(testDirs[3] as string)
        ? ok()
        : fail(1, "");
    }
    const rmDirs = cmd.match(
      /^rm -rf (\/var\/www\/\S+|\/etc\/nginx\/ssl\/\S+) (\/var\/www\/\S+|\/etc\/nginx\/ssl\/\S+) (\/var\/www\/\S+|\/etc\/nginx\/ssl\/\S+)$/,
    );
    if (rmDirs !== null) {
      for (const p of [rmDirs[1], rmDirs[2], rmDirs[3]]) {
        const dir = p as string;
        this.dirs.delete(dir);
        for (const key of [...this.files.keys()]) {
          if (key === dir || key.startsWith(dir + "/")) this.files.delete(key);
        }
        if (dir.startsWith("/etc/nginx/ssl/")) this.deployedCertMd5 = undefined;
      }
      return ok();
    }

    return fail(127, `fake-remote: unhandled command: ${cmd}`);
  }

  /** nginx reloads issued (M6 idempotency assertions). */
  get nginxReloadCount(): number {
    return this.nginxReloads;
  }

  /** Test-only access to the tracked sites-enabled symlinks (M6). */
  symlinksForTest(): Set<string> {
    return this.symlinks;
  }

  /** Commands that mutate remote state (for idempotency assertions). */
  mutatingCommands(): string[] {
    const isMutating = (c: string): boolean =>
      c.includes("apt-get update") ||
      c.includes("apt-get install") ||
      c === "timedatectl set-timezone UTC" ||
      c === "ln -sf /usr/share/zoneinfo/UTC /etc/localtime" ||
      c.startsWith("chmod ") ||
      c.startsWith("for f in /etc/ssh/sshd_config.d") ||
      c === "systemctl enable fail2ban" ||
      c === "systemctl restart fail2ban" ||
      c === "systemctl restart sshd 2>/dev/null || systemctl restart ssh" ||
      c.startsWith("sysctl -w ") ||
      c.startsWith("sysctl -p ") ||
      c === "rm -f /etc/sysctl.d/99-viper-ipv6.conf" ||
      c.startsWith("nohup sh -c 'sleep 1; ip link set dev ") ||
      c === "rm /etc/nginx/sites-enabled/default" ||
      c === "modprobe tcp_bbr 2>/dev/null" ||
      c.startsWith("ufw allow ") ||
      c.startsWith("ufw default ") ||
      c === "ufw --force enable" ||
      c === "ufw reload" ||
      // xray (M5)
      c.startsWith("curl -fsSL ") ||
      c.startsWith("cp /tmp/viper-xray/") ||
      c === "systemctl enable xray" ||
      c === "systemctl restart xray" ||
      c.startsWith("systemctl disable --now xray") ||
      c === "systemctl daemon-reload" ||
      c === "mv /etc/xray/config.new.json /etc/xray/config.json" ||
      c === "rm -f /etc/xray/config.new.json" ||
      c === "rm -f /etc/xray/config.json.tmp" ||
      c.startsWith("rm -rf /tmp/viper") ||
      c.startsWith("rm -rf /etc/xray") ||
      c === "rm -f /usr/local/bin/xray" ||
      c === "rm -f /etc/systemd/system/xray.service" ||
      c.startsWith("pkill ") ||
      c.startsWith("kill ") ||
      // nginx + acme (M6)
      c === "systemctl reload nginx" ||
      c === "systemctl enable --now cron" ||
      c === "curl -fsSL https://get.acme.sh | sh -s --" ||
      c === "/root/.acme.sh/acme.sh --install-cronjob" ||
      c.includes("acme.sh --issue -d ") ||
      c.includes("acme.sh --install-cert -d ") ||
      c.startsWith("ln -sf ") ||
      c.startsWith("rm -f /etc/nginx") ||
      c.startsWith("rm -rf /var/www") ||
      c.startsWith("rm -rf /etc/nginx") ||
      c.includes("crontab -l 2>/dev/null | grep -v");
    return this.commands.filter(isMutating);
  }
}
