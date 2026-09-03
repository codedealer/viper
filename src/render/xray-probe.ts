import type { ServerConfig } from "../config.js";
import { shortIdOf, type State } from "../state.js";

/** Probe sandbox on the server — created and removed by the probe step. */
export const PROBE_DIR = "/tmp/viper-probe";
/** Loopback SOCKS port of the probe client (no collision with 10085 API). */
export const PROBE_SOCKS_PORT = 10809;

/**
 * Render the client side of the REALITY handshake probe (pure function).
 *
 * A minimal Xray client: SOCKS inbound on 127.0.0.1:10809 →
 * vless/reality outbound to 127.0.0.1:<config.port>. Used by the M5
 * verify step to prove, end-to-end, that the deployed server accepts
 * our uuid/shortId/flow over REALITY with the pinned binary.
 *
 * `clientName` selects which config/state client pair to probe (default:
 * the first client). The verify step probes EVERY client: each client's
 * uuid is the credential a real client will present.
 *
 * Field names per the pinned v26.3.27 docs:
 *  - client-side reality `password` holds the server PUBLIC key
 *    (renamed from `publicKey` in older versions)
 *  - vless outbound uses the flat settings form
 *    (address/port/id/encryption/flow) shown in the pinned docs
 */
export function renderXrayProbeClient(
  config: ServerConfig,
  state: State,
  clientName?: string,
): string {
  const name = clientName ?? config.clients[0]?.name;
  if (name === undefined) {
    throw new Error("render/xray-probe: config has no clients");
  }
  const uuid = state.clients.find((c) => c.name === name)?.uuid;
  if (uuid === undefined) {
    throw new Error(
      `render/xray-probe: state has no uuid for client "${name}" — re-run render to regenerate state`,
    );
  }

  const userSettings: Record<string, string | number> = {
    address: "127.0.0.1",
    port: config.port,
    id: uuid,
    encryption: "none",
  };
  if (config.flow !== "") userSettings.flow = config.flow;

  const cfg = {
    log: {
      loglevel: "warning",
    },
    inbounds: [
      {
        listen: "127.0.0.1",
        port: PROBE_SOCKS_PORT,
        protocol: "socks",
        tag: "probe-socks",
        settings: {
          auth: "noauth",
          udp: false,
        },
      },
    ],
    outbounds: [
      {
        protocol: "vless",
        tag: "probe-direct",
        settings: userSettings,
        streamSettings: {
          network: "tcp",
          security: "reality",
          realitySettings: {
            serverName: config.domain,
            fingerprint: config.fingerprint,
            shortId: shortIdOf(config, state),
            password: state.reality.publicKey,
          },
        },
      },
    ],
  };

  return JSON.stringify(cfg, null, 2) + "\n";
}