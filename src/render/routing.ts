/**
 * Happ zero-config routing profile (M1.5).
 *
 * The profile is embedded in the subscription body as a
 * `happ://routing/onadd/{base64}` line — per Happ's docs
 * (refs/happ_su/dev-docs/routing.md): "for subscription bodies, simply
 * including the link is sufficient". Happ adds AND activates the profile
 * on subscription import (zero-config), and re-imports update it in place
 * (same name → atomic geofile swap, no client action).
 *
 * The profile is the documented Happ **default profile**, verbatim
 * (routing.md "Example Default Profile"): no knobs in v1 — the plan defers
 * profile knobs to "later if ever needed".
 *
 * Pure function: no I/O, deterministic output.
 */
export function renderRoutingProfile(): Record<string, unknown> {
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
    FakeDNS: "false",
  };
}

/**
 * The `happ://routing/onadd/{base64}` line that rides in `sub.txt`
 * (never in copy-paste `vless://` link output).
 */
export function renderRoutingLine(): string {
  const json = JSON.stringify(renderRoutingProfile());
  return `happ://routing/onadd/${Buffer.from(json, "utf8").toString("base64")}`;
}
