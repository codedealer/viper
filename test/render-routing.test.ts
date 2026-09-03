import assert from "node:assert/strict";
import { test } from "node:test";
import { renderRoutingLine, renderRoutingProfile } from "../src/render/routing.js";
import { assertGolden } from "./golden.js";

const PREFIX = "happ://routing/onadd/";

test("routing line — golden + documented profile decodes from it", () => {
  const line = renderRoutingLine();
  assertGolden(import.meta.url, "routing-line.txt", line + "\n");
  assert.ok(line.startsWith(PREFIX));

  const b64 = line.slice(PREFIX.length);
  assert.match(b64, /^[A-Za-z0-9+/]+=*$/);
  const profile = JSON.parse(Buffer.from(b64, "base64").toString("utf8")) as Record<string, unknown>;

  // Golden of the decoded profile (pretty-printed for diffability).
  assertGolden(import.meta.url, "routing-profile.json", JSON.stringify(profile, null, 4) + "\n");
});

test("profile matches the documented Happ default profile exactly", () => {
  const p = renderRoutingProfile();
  assert.deepEqual(p, {
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
  });
});

test("only documented field names are used", () => {
  const documented = new Set([
    "Name",
    "GlobalProxy",
    "RemoteDNSType",
    "RemoteDNSDomain",
    "RemoteDNSIP",
    "DomesticDNSType",
    "DomesticDNSDomain",
    "DomesticDNSIP",
    "Geoipurl",
    "Geositeurl",
    "LastUpdated",
    "DnsHosts",
    "DirectSites",
    "DirectIp",
    "ProxySites",
    "ProxyIp",
    "BlockSites",
    "BlockIp",
    "DomainStrategy",
    "FakeDNS",
  ]);
  for (const key of Object.keys(renderRoutingProfile())) {
    assert.ok(documented.has(key), `undocumented profile field: ${key}`);
  }
});

test("renderer is pure and deterministic", () => {
  assert.equal(renderRoutingLine(), renderRoutingLine());
  assert.deepEqual(renderRoutingProfile(), renderRoutingProfile());
  // re-rendering never mutates the profile object the caller sees
  const a = renderRoutingProfile();
  a.DirectIp = ["hacked"];
  assert.deepEqual((renderRoutingProfile().DirectIp as string[])[0], "10.0.0.0/8");
});
