import assert from "node:assert/strict";
import { test } from "node:test";
import {
  PROBE_DIR,
  PROBE_SOCKS_PORT,
  publicProbeAddress,
  renderXrayProbeClient,
} from "../src/render/xray-probe.js";
import {
  fixtureConfig,
  fixtureState,
  knobConfig,
  knobState,
  multiClientConfig,
  multiClientState,
} from "./fixtures.js";
import { assertGolden } from "./golden.js";

test("default knobs — golden probe client config", () => {
  const actual = renderXrayProbeClient(fixtureConfig, fixtureState);
  assertGolden(import.meta.url, "xray-probe-default.json", actual);

  const cfg = JSON.parse(actual) as Record<string, unknown>;
  const inbound = (cfg.inbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  assert.equal(inbound.protocol, "socks");
  assert.equal(inbound.listen, "127.0.0.1");
  assert.equal(inbound.port, PROBE_SOCKS_PORT);

  const outbound = (cfg.outbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  assert.equal(outbound.protocol, "vless");
  const settings = outbound.settings as Record<string, unknown>;
  assert.equal(settings.address, "127.0.0.1");
  assert.equal(settings.port, fixtureConfig.port);
  assert.equal(settings.id, fixtureState.clients[0]?.uuid);
  assert.equal(settings.encryption, "none");
  assert.equal(settings.flow, "xtls-rprx-vision");

  // Pinned v26.3.27 client-side reality fields: `password` holds the
  // server PUBLIC key (renamed from `publicKey`); singular shortId.
  const stream = (outbound.streamSettings as Record<string, unknown>).realitySettings as Record<
    string,
    unknown
  >;
  assert.equal(stream.serverName, fixtureConfig.domain);
  assert.equal(stream.fingerprint, "chrome");
  assert.equal(stream.shortId, fixtureState.shortId);
  assert.equal(stream.password, fixtureState.reality.publicKey);
  assert.ok(!("publicKey" in stream), "no old `publicKey` field");
  assert.ok(!("dest" in stream), "client config must not set the server-side target");
});

test("knob variations — config pin wins for shortId, flow omitted when disabled", () => {
  const actual = renderXrayProbeClient(knobConfig, knobState);

  const cfg = JSON.parse(actual) as Record<string, unknown>;
  const outbound = (cfg.outbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  const settings = outbound.settings as Record<string, unknown>;
  assert.equal(settings.flow, undefined); // flow disabled
  assert.equal(settings.port, knobConfig.port);

  const stream = (outbound.streamSettings as Record<string, unknown>).realitySettings as Record<
    string,
    unknown
  >;
  assert.equal(stream.shortId, knobConfig.shortId); // config pin wins
  assert.equal(stream.serverName, knobConfig.domain);
  assert.equal(stream.fingerprint, "firefox");
});

test("missing client uuid fails loudly", () => {
  assert.throws(
    () => renderXrayProbeClient({ ...fixtureConfig, clients: [{ name: "ghost", limitIp: 0 }] }, fixtureState),
    /no uuid for client/,
  );
});

test("M9: public variant — outbound dials the domain, loopback stays byte-identical", () => {
  const publicCfg = renderXrayProbeClient(fixtureConfig, fixtureState, undefined, {
    address: publicProbeAddress(fixtureConfig),
  });
  assertGolden(import.meta.url, "xray-probe-public.json", publicCfg);

  const cfg = JSON.parse(publicCfg) as Record<string, unknown>;
  const outbound = (cfg.outbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  const settings = outbound.settings as Record<string, unknown>;
  assert.equal(settings.address, fixtureConfig.domain);
  assert.equal(settings.port, fixtureConfig.port);
  assert.equal(settings.id, fixtureState.clients[0]?.uuid);
  // SOCKS inbound is still loopback-only; only the outbound target moved.
  const inbound = (cfg.inbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  assert.equal(inbound.listen, "127.0.0.1");
  assert.equal(inbound.port, PROBE_SOCKS_PORT);

  // publicProbeAddress is just the domain (the plan's trivial helper).
  assert.equal(publicProbeAddress(fixtureConfig), fixtureConfig.domain);

  // Loopback default: explicit "127.0.0.1" and omitted are byte-identical
  // to the pre-M9 rendering (the existing golden asserts this).
  assert.equal(
    renderXrayProbeClient(fixtureConfig, fixtureState, undefined, { address: "127.0.0.1" }),
    renderXrayProbeClient(fixtureConfig, fixtureState),
  );
});

test("M9: public variant per client — every client's uuid with the domain address", () => {
  const phone = renderXrayProbeClient(multiClientConfig, multiClientState, "phone", {
    address: publicProbeAddress(multiClientConfig),
  });
  const cfg = JSON.parse(phone) as Record<string, unknown>;
  const outbound = (cfg.outbounds as Array<Record<string, unknown>>)[0] as Record<string, unknown>;
  const settings = outbound.settings as Record<string, unknown>;
  assert.equal(settings.address, multiClientConfig.domain);
  assert.equal(settings.id, multiClientState.clients[1]?.uuid);
});

test("probe sandbox constants", () => {
  assert.equal(PROBE_DIR, "/tmp/viper-probe");
  assert.equal(PROBE_SOCKS_PORT, 10809);
});
