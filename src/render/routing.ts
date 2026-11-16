import type { RoutingConfig } from "../config.js";

/**
 * Happ zero-config routing profile (M1.5, configurable since M8).
 *
 * The profile is embedded in the subscription body as a
 * `happ://routing/onadd/{base64}` line — per Happ's docs
 * (refs/happ_su/dev-docs/routing.md): "for subscription bodies, simply
 * including the link is sufficient". Happ adds AND activates the profile
 * on subscription import (zero-config), and re-imports update it in place
 * (same name → atomic geofile swap, no client action).
 *
 * The profile is the documented Happ default profile (routing.md
 * "Example Default Profile") with the user's validated overrides merged on
 * top, plus the required `Name` (M8, decisions 3 + 6: server-side
 * defaults, name always shipped explicitly).
 *
 * Pure function: no I/O, deterministic output.
 */
function defaultProfile(): Record<string, unknown> {
  return {
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
    // Rule order the current Happ client applies when the field is absent
    // (observed in the client UI). Shipped explicitly so the rendered
    // profile stays declarative and insures against a future change of the
    // client's built-in default.
    RouteOrder: "block-direct-proxy",
    FakeDNS: "false",
  };
}

/**
 * Render the Happ routing profile: the documented default profile +
 * `Name` + the user's explicit overrides; yml booleans are normalized to
 * Happ's string `"true"`/`"false"` here.
 */
export function renderRoutingProfile(routing: RoutingConfig): Record<string, unknown> {
  const profile = defaultProfile();
  const merged: Record<string, unknown> = { Name: routing.name, ...profile };
  for (const [key, value] of Object.entries(routing.profile)) {
    merged[key] = typeof value === "boolean" ? (value ? "true" : "false") : value;
  }
  return merged;
}

/**
 * The `happ://routing/onadd/{base64}` line that rides in `sub.txt`
 * (never in copy-paste `vless://` link output).
 */
export function renderRoutingLine(routing: RoutingConfig): string {
  const json = JSON.stringify(renderRoutingProfile(routing));
  return `happ://routing/onadd/${Buffer.from(json, "utf8").toString("base64")}`;
}
