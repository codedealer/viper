import assert from "node:assert/strict";
import { test } from "node:test";
import { renderSub, vlessLine } from "../src/render/sub.js";
import {
  fixtureConfig,
  fixtureState,
  knobConfig,
  knobState,
  multiClientConfig,
  multiClientState,
} from "./fixtures.js";
import { assertGolden } from "./golden.js";

test("single client — golden vless line + base64 subscription", () => {
  const sub = renderSub(fixtureConfig, fixtureState);
  assertGolden(import.meta.url, "sub-single.txt", sub.lines.join("\n") + "\n");
  assertGolden(import.meta.url, "sub-single.b64.txt", sub.base64 + "\n");
  assert.equal(sub.url, "https://vpn.example.com/deadbeefcafebabe1234567890abcdef/sub.txt");

  // base64 decodes back to the vless lines + the routing line (Happ open format)
  const decoded = Buffer.from(sub.base64, "base64").toString("utf8");
  assert.equal(decoded, [...sub.lines, sub.routingLine].join("\n") + "\n");

  const [line] = sub.lines;
  assert.ok(line);
  assert.ok(line.startsWith("vless://123e4567-e89b-42d3-a456-426614174000@vpn.example.com:443?"));
  const params = new URLSearchParams(line.split("?")[1]?.split("#")[0]);
  assert.equal(params.get("encryption"), "none");
  assert.equal(params.get("flow"), "xtls-rprx-vision");
  assert.equal(params.get("security"), "reality");
  assert.equal(params.get("sni"), "vpn.example.com");
  assert.equal(params.get("fp"), "chrome");
  assert.equal(params.get("pbk"), fixtureState.reality.publicKey);
  assert.equal(params.get("sid"), fixtureState.shortId);
  assert.equal(params.get("type"), "tcp");
  assert.equal(params.get("headerType"), "none");
  assert.ok(line.endsWith("#default"));
});

test("multi-client — golden sub (one line per client, config order)", () => {
  const sub = renderSub(multiClientConfig, multiClientState);
  assertGolden(import.meta.url, "sub-multi-client.txt", sub.lines.join("\n") + "\n");
  assert.equal(sub.lines.length, 3);
  assert.ok(sub.lines[0]?.endsWith("#default"));
  assert.ok(sub.lines[1]?.endsWith("#phone"));
  assert.ok(sub.lines[2]?.endsWith("#work"));
  // decoded body = vless lines + one routing line at the end
  const decoded = Buffer.from(sub.base64, "base64").toString("utf8").trimEnd().split("\n");
  assert.equal(decoded.length, 4);
  assert.ok(decoded[3]?.startsWith("happ://routing/onadd/"));
  assert.ok(decoded.slice(0, 3).every((l) => l.startsWith("vless://")));
});

test("routing line present, last, and decodes to the documented profile", () => {
  const sub = renderSub(fixtureConfig, fixtureState);
  const decoded = Buffer.from(sub.base64, "base64").toString("utf8");
  const lines = decoded.split("\n").filter((l) => l !== "");
  const [routing] = lines.slice(-1);
  assert.ok(routing, "routing line must be present");
  assert.ok(routing.startsWith("happ://routing/onadd/"));
  assert.equal(routing, sub.routingLine);

  // the local half of M6's "routing line present + decodes to valid profile"
  const profile = JSON.parse(
    Buffer.from(routing.slice("happ://routing/onadd/".length), "base64").toString("utf8"),
  ) as Record<string, unknown>;
  assert.equal(profile.GlobalProxy, "true");
  assert.equal(profile.DomainStrategy, "IPIfNonMatch");
  assert.deepEqual(profile.DirectIp, [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255",
  ]);
  assert.equal(
    profile.Geoipurl,
    "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat",
  );
});

test("copy-paste vless lines stay bare (no routing line in `lines`)", () => {
  const sub = renderSub(fixtureConfig, fixtureState);
  assert.ok(sub.lines.every((l) => l.startsWith("vless://")));
  assert.ok(!sub.lines.some((l) => l.startsWith("happ://")));
});

test("no routing: config → no routing line anywhere (M8 opt-out)", () => {
  const config = { ...fixtureConfig };
  delete config.routing;
  const sub = renderSub(config, fixtureState);
  assert.equal(sub.routingLine, undefined);
  // base64 body decodes to vless-only lines
  const decoded = Buffer.from(sub.base64, "base64").toString("utf8");
  assert.equal(decoded, sub.lines.join("\n") + "\n");
  assert.ok(
    decoded
      .split("\n")
      .filter((l) => l !== "")
      .every((l) => l.startsWith("vless://")),
  );
  assert.ok(!decoded.includes("happ://"));
});

test("routing present → line last in the body, Name shipped in the profile", () => {
  const sub = renderSub(fixtureConfig, fixtureState);
  const decoded = Buffer.from(sub.base64, "base64").toString("utf8");
  const lines = decoded.split("\n").filter((l) => l !== "");
  const [last] = lines.slice(-1);
  assert.ok(last, "routing line must be present");
  assert.ok(last.startsWith("happ://routing/onadd/"));
  assert.equal(last, sub.routingLine);
  const profile = JSON.parse(
    Buffer.from(last.slice("happ://routing/onadd/".length), "base64").toString("utf8"),
  ) as Record<string, unknown>;
  assert.equal(profile.Name, "Viper"); // fixture routing name
});

test("sub path hash changes the URL only, not the vless lines", () => {
  const a = renderSub(fixtureConfig, fixtureState);
  const otherHash = { ...fixtureState, subHash: "00112233445566778899aabbccddeeff" };
  const b = renderSub(fixtureConfig, otherHash);
  assert.deepEqual(a.lines, b.lines);
  assert.equal(b.url, "https://vpn.example.com/00112233445566778899aabbccddeeff/sub.txt");
});

test("knob variations — flow omitted, shortId from config pin, custom port", () => {
  const line = vlessLine(knobConfig, knobState, {
    name: "default",
    uuid: "123e4567-e89b-42d3-a456-426614174000",
  });
  assertGolden(import.meta.url, "sub-knobs.txt", line + "\n");
  assert.ok(line.startsWith("vless://123e4567-e89b-42d3-a456-426614174000@proxy.example.org:443?"));
  const params = new URLSearchParams(line.split("?")[1]?.split("#")[0]);
  assert.equal(params.get("flow"), null);
  assert.equal(params.get("fp"), "firefox");
  assert.equal(params.get("sid"), "deadbeef"); // config pin beats state
  assert.equal(params.get("sni"), "proxy.example.org");
});

test("client names are percent-encoded in the fragment", () => {
  const line = vlessLine(fixtureConfig, fixtureState, {
    name: "my phone (2)",
    uuid: "123e4567-e89b-42d3-a456-426614174000",
  });
  assert.ok(line.endsWith(`#${encodeURIComponent("my phone (2)")}`));
});

test("non-default port (2053) — explicit port in vless line and subscription URL", () => {
  const sub = renderSub({ ...fixtureConfig, port: 2053 }, fixtureState);
  assert.equal(sub.url, "https://vpn.example.com:2053/deadbeefcafebabe1234567890abcdef/sub.txt");
  const [line] = sub.lines;
  assert.ok(line);
  assert.ok(line.startsWith("vless://123e4567-e89b-42d3-a456-426614174000@vpn.example.com:2053?"));
});
