import assert from "node:assert/strict";
import { test } from "node:test";
import { renderXray } from "../src/render/xray.js";
import {
  fixtureConfig,
  fixtureState,
  knobConfig,
  knobState,
  multiClientConfig,
  multiClientState,
} from "./fixtures.js";
import { assertGolden } from "./golden.js";

function parse(actual: string): Record<string, unknown> {
  return JSON.parse(actual) as Record<string, unknown>;
}

test("default knobs — golden config.json", () => {
  const actual = renderXray(fixtureConfig, fixtureState);
  assertGolden(import.meta.url, "xray-default.json", actual);

  const cfg = parse(actual);
  const inbounds = cfg.inbounds as Array<Record<string, unknown>>;
  assert.equal(inbounds.length, 1, "single inbound (stats moved to the api block)");
  const vless = inbounds[0] as Record<string, unknown>;
  const stream = (vless.streamSettings as Record<string, unknown>).realitySettings as Record<string, unknown>;

  // Binding topology: Xray direct on 0.0.0.0:443, serverNames=[domain],
  // dest = 127.0.0.1:8443 loopback web vhost.
  assert.equal(vless.listen, "0.0.0.0");
  assert.equal(vless.port, 443);
  assert.equal(vless.protocol, "vless");
  assert.deepEqual(stream.serverNames, [fixtureConfig.domain]);
  assert.equal(stream.dest, "127.0.0.1:8443");
  assert.equal(stream.privateKey, fixtureState.reality.privateKey);
  // Pinned v26.3.27 field names (M1's shortId/maxTimediff/clients are
  // silently ignored by the pinned binary).
  assert.deepEqual(stream.shortIds, [fixtureState.shortId]);
  assert.equal(stream.maxTimeDiff, 0);

  // vless INBOUND user list uses the pinned name `clients` (NOT docs-next's
  // `users`, which the pinned binary silently ignores → zero-user inbound).
  const clients = (
    (vless.settings as Record<string, unknown>).clients as Array<Record<string, unknown>>
  )[0] as Record<string, unknown>;
  assert.equal(clients.id, fixtureState.clients[0]?.uuid);
  assert.equal(clients.email, "default");
  assert.equal(clients.flow, "xtls-rprx-vision");
  assert.equal(clients.limitIp, 2); // fixture client limitIp: 2 → emitted
  assert.equal(
    (vless.settings as Record<string, unknown>).users,
    undefined,
    "no docs-next `users` key emitted",
  );

  // Simplified stats API block (NOT a dokodemo-door inbound).
  const api = cfg.api as Record<string, unknown>;
  assert.equal(api.tag, "api");
  assert.equal(api.listen, "127.0.0.1:10085");
  assert.deepEqual(api.services, ["StatsService"]);

  const outbounds = cfg.outbounds as Array<Record<string, unknown>>;
  assert.deepEqual(
    outbounds.map((o) => o.protocol),
    ["freedom", "blackhole"],
  );
  assert.ok(cfg.dns);
  assert.ok(cfg.stats);
});

test("multi-client — golden config.json", () => {
  const actual = renderXray(multiClientConfig, multiClientState);
  assertGolden(import.meta.url, "xray-multi-client.json", actual);

  const cfg = parse(actual);
  const vless = (cfg.inbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  const clients = (vless.settings as Record<string, unknown>).clients as Array<Record<string, unknown>>;
  assert.deepEqual(
    clients.map((u) => u.id),
    multiClientState.clients.map((c) => c.uuid),
  );
  // email = client name (distinguishes users in stats/logs).
  assert.deepEqual(
    clients.map((u) => u.email),
    ["default", "phone", "work"],
  );
  assert.ok(clients.every((u) => u.flow === "xtls-rprx-vision"));
  // limitIp emitted only when > 0 (config: default=2, phone=0, work=1)
  assert.equal(clients[0]?.limitIp, 2);
  assert.equal(clients[1]?.limitIp, undefined);
  assert.equal(clients[2]?.limitIp, 1);
});

test("knob variations — golden config.json", () => {
  const actual = renderXray(knobConfig, knobState);
  assertGolden(import.meta.url, "xray-knobs.json", actual);

  const cfg = parse(actual);
  const vless = (cfg.inbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  const stream = (vless.streamSettings as Record<string, unknown>).realitySettings as Record<string, unknown>;

  assert.equal(stream.dest, "127.0.0.1:9443");
  assert.deepEqual(stream.serverNames, [knobConfig.domain]);
  assert.deepEqual(stream.shortIds, [knobConfig.shortId]); // config pin wins
  assert.equal(stream.fingerprint, "firefox");
  assert.equal(stream.maxTimeDiff, 3600000);
  assert.equal(stream.xver, 1);

  const client = (
    (vless.settings as Record<string, unknown>).clients as Array<Record<string, unknown>>
  )[0] as Record<string, unknown>;
  assert.equal(client.flow, undefined); // flow disabled → field omitted
  assert.equal(client.limitIp, undefined); // limitIp 0 → field omitted
  assert.equal(client.email, "default");

  const sniffing = cfg.sniffing as Record<string, unknown>;
  assert.equal(sniffing.enabled, false);
  const log = cfg.log as Record<string, unknown>;
  assert.equal(log.loglevel, "error");
});

test("missing client uuid fails loudly", () => {
  assert.throws(
    () => renderXray({ ...fixtureConfig, clients: [{ name: "ghost", limitIp: 0 }] }, fixtureState),
    /no uuid for client/,
  );
});
