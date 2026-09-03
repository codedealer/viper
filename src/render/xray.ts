import type { ServerConfig } from "../config.js";
import { shortIdOf, type State } from "../state.js";

/**
 * Render the full Xray `config.json` (pure function).
 *
 * Field names verified against the PINNED Xray v26.3.27 source
 * (Xray-core-26.3.27/infra/conf) — refs/Xray-docs-next is AHEAD of the
 * pinned binary and must not be trusted for names:
 *  - vless INBOUND `settings.clients` (per-user id/email/flow/limitIp)
 *    — pinned `VLessInboundConfig.Clients` has `json:"clients"`
 *    (vless.go:33). `users` is only the outbound vnext key. docs-next
 *    shows `users` for the inbound, but the pinned binary silently
 *    ignores it (inbound boots with zero users → every REALITY
 *    handshake fails at uuid auth with "invalid request user id").
 *  - reality `shortIds` (array) — pinned `json:"shortIds"`
 *    (transport_internet.go:792)
 *  - reality `maxTimeDiff` (camelCase D) — pinned `json:"maxTimeDiff"`
 *    (transport_internet.go:791)
 *  - stats API via the simplified `api` block — pinned `tag`/`listen`/
 *    `services` (api.go:17-19); NOT the old dokodemo-door "stats" inbound
 *
 * Topology (steal oneself, single domain):
 *  - vless/reality inbound listens directly on 0.0.0.0:443
 *  - serverNames = [<domain>], dest = 127.0.0.1:<webPort> (loopback
 *    nginx web vhost — Reality-failed / junk-SNI traffic lands on the
 *    faux login page)
 *
 * Note: `limitIp` is absent from the pinned source entirely (grep
 * zero hits); it is still emitted when set (config knob, ignored by
 * the binary) and v1 fixtures never set it.
 */
export function renderXray(config: ServerConfig, state: State): string {
  const shortId = shortIdOf(config, state);
  const uuidByName = new Map(state.clients.map((c) => [c.name, c.uuid]));

  const clients = config.clients.map((c) => {
    const uuid = uuidByName.get(c.name);
    if (uuid === undefined) {
      throw new Error(
        `render/xray: state has no uuid for client "${c.name}" — re-run render to regenerate state`,
      );
    }
    const user: Record<string, string | number> = {
      id: uuid,
      email: c.name,
    };
    if (config.flow !== "") user.flow = config.flow;
    if (c.limitIp > 0) user.limitIp = c.limitIp;
    return user;
  });

  const cfg = {
    log: {
      access: "/var/log/xray/access.log",
      error: "/var/log/xray/error.log",
      loglevel: config.logLevel,
    },
    api: {
      tag: "api",
      listen: "127.0.0.1:10085",
      services: ["StatsService"],
    },
    inbounds: [
      {
        listen: config.listen,
        port: config.port,
        protocol: "vless",
        tag: "vless-in",
        settings: {
          clients,
          decryption: "none",
        },
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            dest: `127.0.0.1:${config.webPort}`,
            privateKey: state.reality.privateKey,
            serverNames: [config.domain],
            shortIds: [shortId],
            show: false,
            maxTimeDiff: config.maxTimediff,
            fingerprint: config.fingerprint,
            xver: config.xver,
          },
        },
      },
    ],
    outbounds: [
      {
        protocol: "freedom",
        tag: "direct",
      },
      {
        protocol: "blackhole",
        tag: "block",
      },
    ],
    dns: {},
    stats: {},
    sniffing:
      config.sniffing === true ? { enabled: true, destOverride: ["http", "tls"] } : { enabled: false },
  };

  return JSON.stringify(cfg, null, 2) + "\n";
}
