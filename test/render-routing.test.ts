import assert from "node:assert/strict";
import { test } from "node:test";
import type { RoutingConfig } from "../src/config.js";
import { renderRoutingLine, renderRoutingProfile } from "../src/render/routing.js";

const PREFIX = "happ://routing/onadd/";

/** The documented Happ default profile (routing.md "Example Default Profile"). */
const DEFAULT_PROFILE = {
  GlobalProxy: "true",
  RemoteDNSType: "DoH",
  RemoteDNSDomain: "https://cloudflare-dns.com/dns-query",
  RemoteDNSIP: "1.1.1.1",
  DomesticDNSType: "DoH",
  DomesticDNSDomain: "https://dns.google/dns-query",
  DomesticDNSIP: "8.8.8.8",
  Geoipurl: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
  Geositeurl: "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat",
  DnsHosts: {
    "cloudflare-dns.com": "1.1.1.1",
    "dns.google": "8.8.8.8",
  },
  DirectSites: [],
  DirectIp: [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255",
  ],
  DomainStrategy: "IPIfNonMatch",
  FakeDNS: "false",
};

// ------------------------------------------------------------------- M8

test("routing: {} + name renders the documented default profile plus Name", () => {
  const p = renderRoutingProfile({ name: "Viper", profile: {} });
  assert.deepEqual(p, { Name: "Viper", ...DEFAULT_PROFILE });
});

test("user overrides merge over the defaults (missing fields stay default)", () => {
  const routing: RoutingConfig = {
    name: "China",
    profile: {
      DomesticDNSType: "DoU",
      DomesticDNSDomain: "",
      DirectSites: ["geosite:geolocation-cn"],
      DirectIp: ["geoip:cn"],
      BlockSites: ["geosite:ads"],
      BlockIp: ["geoip:ads"],
    },
  };
  const p = renderRoutingProfile(routing) as Record<string, unknown>;
  // overridden fields
  assert.equal(p.Name, "China");
  assert.equal(p.DomesticDNSType, "DoU");
  assert.equal(p.DomesticDNSDomain, "");
  assert.deepEqual(p.DirectSites, ["geosite:geolocation-cn"]);
  assert.deepEqual(p.DirectIp, ["geoip:cn"]);
  assert.deepEqual(p.BlockSites, ["geosite:ads"]);
  assert.deepEqual(p.BlockIp, ["geoip:ads"]);
  // untouched fields stay at the documented defaults
  assert.equal(p.GlobalProxy, "true");
  assert.equal(p.RemoteDNSType, "DoH");
  assert.equal(p.RemoteDNSDomain, "https://cloudflare-dns.com/dns-query");
  assert.equal(p.DomainStrategy, "IPIfNonMatch");
  assert.equal(p.FakeDNS, "false");
  assert.deepEqual(p.DnsHosts, DEFAULT_PROFILE.DnsHosts);
  // no extra fields appear (no ProxySites/ProxyIp when the user didn't set them)
  assert.ok(!("ProxySites" in p));
  assert.ok(!("ProxyIp" in p));
});

test('yml booleans are normalized to Happ\'s string "true"/"false" at render time', () => {
  const p = renderRoutingProfile({ name: "a", profile: { GlobalProxy: false, FakeDNS: true } });
  assert.equal(p.GlobalProxy, "false");
  assert.equal(p.FakeDNS, "true");
});

test("config-driven line carries the name and decodes to the merged profile", () => {
  const routing: RoutingConfig = {
    name: "Viper",
    profile: { BlockSites: ["geosite:ads"], FakeDNS: true },
  };
  const line = renderRoutingLine(routing);
  assert.ok(line.startsWith(PREFIX));
  const profile = JSON.parse(Buffer.from(line.slice(PREFIX.length), "base64").toString("utf8")) as Record<
    string,
    unknown
  >;
  assert.equal(profile.Name, "Viper");
  assert.deepEqual(profile.BlockSites, ["geosite:ads"]);
  assert.equal(profile.FakeDNS, "true");
  // deterministic
  assert.equal(line, renderRoutingLine(routing));
});
