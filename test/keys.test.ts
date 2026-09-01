import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import {
  generateRealityKeypair,
  generateShortId,
  generateSubHash,
  generateUuid,
  type RealityKeypair,
} from "../src/keys.js";
import { fixtureState } from "./fixtures.js";

const KEY_B64URL_RE = /^[A-Za-z0-9_-]{43}$/;

function toJwkMaterial(pair: RealityKeypair): { d: string; x: string } {
  return {
    d: Buffer.from(pair.privateKey, "base64url").toString("base64url"),
    x: Buffer.from(pair.publicKey, "base64url").toString("base64url"),
  };
}

/**
 * x25519 private KeyObjects cannot re-derive their public key, so pair
 * consistency is proven with ECDH: shared(privA, pubB) === shared(privB, pubA)
 * only holds when pubB belongs to privA (for independent random keys).
 */
function assertKeypairConsistent(pair: RealityKeypair): void {
  const { d, x } = toJwkMaterial(pair);
  const jwkBase = { kty: "OKP" as const, crv: "X25519" as const };
  const privA = createPrivateKey({ key: { ...jwkBase, d, x }, format: "jwk" });
  const pubB = createPublicKey({ key: { ...jwkBase, x }, format: "jwk" });
  const probe = generateKeyPairSync("x25519");
  const s1 = diffieHellman({ privateKey: privA, publicKey: probe.publicKey });
  const s2 = diffieHellman({ privateKey: probe.privateKey, publicKey: pubB });
  assert.ok(s1.equals(s2), "private key does not match public key");
}

test("generateRealityKeypair produces canonical base64url keys (raw 32 bytes, no padding)", () => {
  const pair = generateRealityKeypair();
  for (const key of [pair.publicKey, pair.privateKey]) {
    assert.match(key, KEY_B64URL_RE);
    const raw = Buffer.from(key, "base64url");
    assert.equal(raw.length, 32);
  }
  assert.notEqual(pair.publicKey, pair.privateKey);
  assertKeypairConsistent(pair);
});

test("generated keypairs are unique", () => {
  const a = generateRealityKeypair();
  const b = generateRealityKeypair();
  assert.notEqual(a.privateKey, b.privateKey);
  assert.notEqual(a.publicKey, b.publicKey);
});

test("fixture keypair is a real, consistent x25519 pair", () => {
  assertKeypairConsistent(fixtureState.reality);
});

test("generateUuid yields UUIDv4", () => {
  const uuid = generateUuid();
  assert.match(
    uuid,
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  );
  assert.notEqual(uuid, generateUuid());
});

test("generateShortId yields 16 hex chars", () => {
  assert.match(generateShortId(), /^[0-9a-f]{16}$/);
});

test("generateSubHash yields 32 hex chars", () => {
  assert.match(generateSubHash(), /^[0-9a-f]{32}$/);
});