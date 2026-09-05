import type { ServerConfig } from "../config.js";
import { publicHost } from "../config.js";
import { shortIdOf, type State, type StateClient } from "../state.js";
import { renderRoutingLine } from "./routing.js";

export interface Subscription {
  /** One `vless://` line per client (in config order) — the copy-paste links, kept bare. */
  lines: string[];
  /**
   * The single `happ://routing/onadd/{base64}` line — present iff the config
   * has a `routing:` block (M8: absence = no routing line in `sub.txt`).
   */
  routingLine?: string;
  /** vless lines (+ routing line when shipped), base6-encoded — the `sub.txt` body. */
  base64: string;
  /** Public subscription URL: https://<domain>[:port]/<hash>/sub.txt (explicit port iff not 443). */
  url: string;
}

/**
 * Build a single `vless://` link line.
 * Format per Happ's open-format docs:
 * vless://uuid@<domain>:<port>?encryption=none&flow=...&security=reality
 *   &sni=...&fp=...&pbk=...&sid=...&type=tcp&headerType=none#<name>
 */
export function vlessLine(config: ServerConfig, state: State, client: StateClient): string {
  const params = new URLSearchParams();
  params.set("encryption", "none");
  if (config.flow !== "") params.set("flow", config.flow);
  params.set("security", "reality");
  params.set("sni", config.domain);
  params.set("fp", config.fingerprint);
  params.set("pbk", state.reality.publicKey);
  const shortId = shortIdOf(config, state);
  if (shortId !== "") params.set("sid", shortId);
  params.set("type", "tcp");
  params.set("headerType", "none");
  return `vless://${client.uuid}@${config.domain}:${config.port}?${params.toString()}#${encodeURIComponent(client.name)}`;
}

/**
 * Render the Happ subscription (pure function): `vless://` line(s) + — iff
 * the config ships a `routing:` block (M8) — the `happ://routing/onadd/`
 * line, base64-encoded as one blob (what `/<hash>/sub.txt` serves). The
 * `vless://` lines themselves stay bare either way — the routing line rides
 * only in the subscription body.
 */
export function renderSub(config: ServerConfig, state: State): Subscription {
  const uuidByName = new Map(state.clients.map((c) => [c.name, c.uuid]));
  const lines = config.clients.map((c) => {
    const uuid = uuidByName.get(c.name);
    if (uuid === undefined) {
      throw new Error(
        `render/sub: state has no uuid for client "${c.name}" — re-run render to regenerate state`,
      );
    }
    return vlessLine(config, state, { name: c.name, uuid });
  });
  const routingLine = config.routing !== undefined ? renderRoutingLine(config.routing) : undefined;
  const body = [...lines, ...(routingLine !== undefined ? [routingLine] : [])].join("\n") + "\n";
  return {
    lines,
    ...(routingLine !== undefined ? { routingLine } : {}),
    base64: Buffer.from(body, "utf8").toString("base64"),
    url: `https://${publicHost(config)}/${state.subHash}/sub.txt`,
  };
}
