import { test } from "node:test";
import assert from "node:assert/strict";
import { rotateState } from "../src/rotate.js";
import { parseState, serializeState, type State } from "../src/state.js";

const baseState: State = {
  reality: {
    publicKey: "RRaBqa-l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0",
    privateKey: "KE9dFWwBEA5xCSZV0Efu-m7RdHZEPFQhpY4ka_HmiHA",
  },
  shortId: "0123456789abcdef",
  subHash: "deadbeefcafebabe1234567890abcdef",
  clients: [
    { name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" },
    { name: "phone", uuid: "00000000-0000-4000-8000-000000000000" },
  ],
  hostKey: { fingerprint: "SHA256:icvLSHs6iu1cK3vQnxO9wLdoNJS+tNbf+Vh2M+myvWc" },
  installedPackages: ["nginx", "unzip"],
};

const UUID_V4_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const KEY_URL_B64_RE = /^[A-Za-z0-9_-]{43}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;

test("rotateState: regenerates keypair, every uuid, and the sub hash", () => {
  const rotated = rotateState(baseState);

  assert.notEqual(rotated.reality.publicKey, baseState.reality.publicKey);
  assert.notEqual(rotated.reality.privateKey, baseState.reality.privateKey);
  assert.match(rotated.reality.publicKey, KEY_URL_B64_RE);
  assert.match(rotated.reality.privateKey, KEY_URL_B64_RE);

  assert.equal(rotated.clients.length, baseState.clients.length);
  rotated.clients.forEach((c, i) => {
    const before = baseState.clients[i] as (typeof baseState.clients)[number];
    assert.equal(c.name, before.name);
    assert.notEqual(c.uuid, before.uuid);
    assert.match(c.uuid, UUID_V4_RE);
  });
  // distinct uuids across clients
  assert.equal(new Set(rotated.clients.map((c) => c.uuid)).size, rotated.clients.length);

  assert.notEqual(rotated.subHash, baseState.subHash);
  assert.match(rotated.subHash, HEX32_RE);
});

test("rotateState: preserves shortId, hostKey, installedPackages", () => {
  const rotated = rotateState(baseState);

  assert.equal(rotated.shortId, baseState.shortId);
  assert.deepEqual(rotated.hostKey, baseState.hostKey);
  assert.deepEqual(rotated.installedPackages, baseState.installedPackages);
  // copy, not alias — a later mutation must not leak back into the input
  rotated.installedPackages.push("cron");
  assert.deepEqual(baseState.installedPackages, ["nginx", "unzip"]);
});

test("rotateState: result round-trips through the canonical state codec", () => {
  const rotated = rotateState(baseState);
  const reparsed = parseState(JSON.parse(JSON.stringify(rotated)));
  assert.deepEqual(reparsed, rotated);
  // canonical serialization is deterministic for the rotated state
  assert.equal(
    serializeState(parseState(JSON.parse(JSON.stringify(rotated)))),
    serializeState(rotated),
  );
});