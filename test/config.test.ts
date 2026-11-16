import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import {
  ConfigError,
  loadServers,
  parseServerConfig,
  resolveServerName,
  type ServerConfig,
} from "../src/config.js";

const validDoc = {
  ip: "203.0.113.10",
  domain: "vpn.example.com",
  xray: "v26.3.27",
};

test("minimal config parses with defaults", () => {
  const cfg = parseServerConfig("main", validDoc);
  assert.deepEqual(cfg, {
    name: "main",
    ip: "203.0.113.10",
    domain: "vpn.example.com",
    xray: "v26.3.27",
    sshPort: 22,
    listen: "0.0.0.0",
    port: 443,
    webPort: 8443,
    fingerprint: "chrome",
    flow: "xtls-rprx-vision",
    shortId: "",
    maxTimediff: 0,
    xver: 0,
    logLevel: "warning",
    sniffing: true,
    harden: true,
    bbr: true,
    clients: [{ name: "default", limitIp: 0 }],
  });
});

test("explicit knobs are honored", () => {
  const cfg = parseServerConfig("alt", {
    ip: "198.51.100.7",
    domain: "proxy.example.org",
    xray: "v26.3.27",
    sshPort: 2222,
    sshKey: "~/.ssh/id_ed25519",
    port: 8443,
    webPort: 9443,
    fingerprint: "firefox",
    flow: "",
    shortId: "deadbeef",
    maxTimediff: 3600000,
    xver: 1,
    logLevel: "error",
    sniffing: false,
    clients: [{ name: "default", limitIp: 2 }, { name: "phone" }],
  });
  assert.equal(cfg.sshPort, 2222);
  assert.equal(cfg.sshKey, "~/.ssh/id_ed25519");
  assert.equal(cfg.webPort, 9443);
  assert.equal(cfg.fingerprint, "firefox");
  assert.equal(cfg.flow, "");
  assert.equal(cfg.shortId, "deadbeef");
  assert.equal(cfg.xver, 1);
  assert.equal(cfg.sniffing, false);
  assert.deepEqual(cfg.clients, [
    { name: "default", limitIp: 2 },
    { name: "phone", limitIp: 0 },
  ]);
});

test("allowIPv6: absent by default (v4-only is the default, M8)", () => {
  const cfg = parseServerConfig("main", validDoc);
  assert.ok(!("allowIPv6" in cfg), "allowIPv6 must be absent, not false-by-default");
});

test("allowIPv6: explicit true/false honored, non-boolean rejected (M8)", () => {
  assert.equal(parseServerConfig("main", { ...validDoc, allowIPv6: true }).allowIPv6, true);
  assert.equal(parseServerConfig("main", { ...validDoc, allowIPv6: false }).allowIPv6, false);
  expectConfigError({ ...validDoc, allowIPv6: "yes" }, "main", "expected a boolean");
  expectConfigError({ ...validDoc, allowIPv6: 1 }, "main", "expected a boolean");
});

test("harden/bbr knobs default true and honor explicit false", () => {
  const defaults = parseServerConfig("main", validDoc);
  assert.equal(defaults.harden, true);
  assert.equal(defaults.bbr, true);
  const off = parseServerConfig("main", { ...validDoc, harden: false, bbr: false });
  assert.equal(off.harden, false);
  assert.equal(off.bbr, false);
  expectConfigError({ ...validDoc, harden: "yes" }, "main", "expected a boolean");
  expectConfigError({ ...validDoc, bbr: 1 }, "main", "expected a boolean");
});

// ----------------------------------------------------------------- routing

test("routing: absent by default (opt-in by presence)", () => {
  const cfg = parseServerConfig("main", validDoc);
  assert.ok(!("routing" in cfg), "routing must be absent, not undefined-by-default");
});

test("routing: name-only block parses to an empty profile", () => {
  const cfg = parseServerConfig("main", { ...validDoc, routing: { name: "Viper" } });
  assert.deepEqual(cfg.routing, { name: "Viper", profile: {} });
});

test("routing: full override block parses (lists, string maps, enums)", () => {
  const cfg = parseServerConfig("main", {
    ...validDoc,
    routing: {
      name: "China",
      GlobalProxy: true,
      RemoteDNSType: "DoH",
      DomesticDNSType: "DoU",
      DomesticDNSDomain: "", // legal per Happ's documented custom profile
      Geoipurl: "https://example.com/geoip.dat",
      DnsHosts: { "cloudflare-dns.com": "1.1.1.1" },
      BlockSites: ["geosite:ads", { "geosite-category:ads-all": "" }],
      BlockIp: ["geoip:ads"],
      DirectSites: ["geosite:geolocation-cn"],
      DirectIp: ["geoip:cn"],
      ProxySites: [],
      ProxyIp: [],
      DomainStrategy: "AsIs",
      RouteOrder: "block-proxy-direct",
      FakeDNS: false,
    },
  });
  assert.deepEqual(cfg.routing, {
    name: "China",
    profile: {
      GlobalProxy: true,
      RemoteDNSType: "DoH",
      DomesticDNSType: "DoU",
      DomesticDNSDomain: "",
      Geoipurl: "https://example.com/geoip.dat",
      DnsHosts: { "cloudflare-dns.com": "1.1.1.1" },
      BlockSites: ["geosite:ads", { "geosite-category:ads-all": "" }],
      BlockIp: ["geoip:ads"],
      DirectSites: ["geosite:geolocation-cn"],
      DirectIp: ["geoip:cn"],
      ProxySites: [],
      ProxyIp: [],
      DomainStrategy: "AsIs",
      RouteOrder: "block-proxy-direct",
      FakeDNS: false,
    },
  });
});

test("routing: validation failures are actionable ConfigErrors", () => {
  // missing required name
  expectConfigError({ ...validDoc, routing: {} }, "main", "routing.name");
  // not a mapping
  expectConfigError({ ...validDoc, routing: ["x"] }, "main", "expected a mapping");
  // unknown keys (typo + Happ's `Name` is viper-side `name`)
  expectConfigError({ ...validDoc, routing: { name: "a", Name: "b" } }, "main", "routing.Name: unknown key");
  expectConfigError(
    { ...validDoc, routing: { name: "a", BlockSitez: [] } },
    "main",
    "routing.BlockSitez: unknown key",
  );
  // bad enums
  expectConfigError(
    { ...validDoc, routing: { name: "a", DomainStrategy: "nope" } },
    "main",
    "expected one of",
  );
  expectConfigError(
    { ...validDoc, routing: { name: "a", RouteOrder: "direct-direct-proxy" } },
    "main",
    "expected one of",
  );
  expectConfigError(
    { ...validDoc, routing: { name: "a", RemoteDNSType: "nope" } },
    "main",
    "expected one of",
  );
  // booleans must be real yml booleans (Happ's string form is render-time only)
  expectConfigError(
    { ...validDoc, routing: { name: "a", GlobalProxy: "true" } },
    "main",
    "expected a boolean",
  );
  expectConfigError({ ...validDoc, routing: { name: "a", FakeDNS: 1 } }, "main", "expected a boolean");
  // rule lists: strings or string maps only
  expectConfigError({ ...validDoc, routing: { name: "a", BlockSites: [42] } }, "main", "expected a mapping");
  expectConfigError(
    { ...validDoc, routing: { name: "a", DirectIp: "geoip:cn" } },
    "main",
    "expected a list of rules",
  );
  expectConfigError({ ...validDoc, routing: { name: "a", DnsHosts: { h: 1 } } }, "main", "expected a string");
  // documented enum values are accepted
  const ok = parseServerConfig("main", {
    ...validDoc,
    routing: { name: "a", RemoteDNSType: "DoU", DomesticDNSType: "DoU", DomainStrategy: "AsIs" },
  });
  assert.equal(ok.routing?.profile.RemoteDNSType, "DoU");
});

function expectConfigError(doc: unknown, name: string, fragment: string): void {
  assert.throws(
    () => parseServerConfig(name, doc),
    (err: unknown) => err instanceof ConfigError && err.message.includes(fragment),
    `expected error containing "${fragment}"`,
  );
}

test("validation rejects bad values with actionable messages", () => {
  expectConfigError({ ...validDoc, domain: "nope" }, "main", "not a valid domain");
  expectConfigError({ ...validDoc, ip: "300.1.2.3" }, "main", "not a valid IPv4 address");
  expectConfigError({ ...validDoc, xray: "26.3.27" }, "main", "not a valid version pin");
  expectConfigError({ ...validDoc, unknown: true }, "main", "unknown key");
  expectConfigError({ ...validDoc, fingerprint: "safari2" }, "main", "expected one of");
  expectConfigError({ ...validDoc, port: 0 }, "main", "between 1 and 65535");
  expectConfigError({ ...validDoc, shortId: "xyz" }, "main", "shortId");
  expectConfigError(
    { ...validDoc, shortId: "abcde" },
    "main",
    "shortId", // odd-length hex
  );
  expectConfigError(
    { ...validDoc, shortId: "0123456789abcdef0" },
    "main",
    "shortId", // 17 chars
  );
  // valid pins: 8 and 16 even-length hex chars
  assert.equal(parseServerConfig("main", { ...validDoc, shortId: "deadbeef" }).shortId, "deadbeef");
  assert.equal(
    parseServerConfig("main", { ...validDoc, shortId: "0123456789ABCDEF" }).shortId,
    "0123456789ABCDEF",
  );
  expectConfigError({ ...validDoc, clients: [] }, "main", "non-empty list of clients");
  expectConfigError(
    { ...validDoc, clients: [{ name: "a" }, { name: "a" }] },
    "main",
    "duplicate client name",
  );
  expectConfigError({ ip: "1.2.3.4", xray: "v1.2.3" }, "main", "domain");
});

test("loadServers finds viper.<name>.yml files and ignores others", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-cfg-"));
  try {
    const yml = "ip: 203.0.113.10\ndomain: vpn.example.com\nxray: v26.3.27\n";
    await writeFile(join(dir, "viper.main.yml"), yml);
    await writeFile(join(dir, "viper.alt.yml"), yml);
    await writeFile(join(dir, "other.yml"), yml); // not a server file
    await writeFile(join(dir, "viper.Upper.yml"), yml); // invalid name → ignored

    const servers = await loadServers(dir);
    assert.deepEqual([...servers.keys()].sort(), ["alt", "main"]);
    assert.equal(servers.get("main")?.domain, "vpn.example.com");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("loadServers reports the offending file on parse/validation errors", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-cfg-"));
  try {
    await writeFile(join(dir, "viper.bad.yml"), "ip: [unclosed\n");
    await assert.rejects(
      loadServers(dir),
      (err: unknown) => err instanceof ConfigError && err.message.includes("viper.bad.yml"),
    );
    await rm(join(dir, "viper.bad.yml"), { force: true });
    await writeFile(join(dir, "viper.bad.yml"), "domain: also-missing\n");
    await assert.rejects(
      loadServers(dir),
      (err: unknown) => err instanceof ConfigError && err.message.includes("viper.bad.yml"),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("resolveServerName: sole server defaults, multiple require --name, missing errors", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-cfg-"));
  try {
    const yml = "ip: 203.0.113.10\ndomain: vpn.example.com\nxray: v26.3.27\n";
    await writeFile(join(dir, "viper.main.yml"), yml);
    let servers = await loadServers(dir);
    assert.equal(resolveServerName(undefined, servers), "main");
    assert.equal(resolveServerName("main", servers), "main");
    assert.throws(
      () => resolveServerName("nope", servers),
      (err: unknown) => err instanceof ConfigError && err.message.includes("nope"),
    );

    await writeFile(join(dir, "viper.alt.yml"), yml);
    servers = await loadServers(dir);
    assert.throws(
      () => resolveServerName(undefined, servers),
      (err: unknown) => err instanceof ConfigError && err.message.includes("--name"),
    );
    assert.equal(resolveServerName("alt", servers), "alt");

    const empty = new Map<string, ServerConfig>();
    assert.throws(
      () => resolveServerName(undefined, empty),
      (err: unknown) => err instanceof ConfigError && err.message.includes("no server configs"),
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
