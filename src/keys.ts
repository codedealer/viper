import { generateKeyPairSync, randomBytes, randomUUID } from "node:crypto";

/**
 * Xray REALITY keypair in the pinned binary's canonical on-disk format:
 * raw 32-byte keys as **base64url without padding** (43 chars). Verified
 * against Xray v26.3.27: `x25519.go` decodes `privateKey`/`password`
 * (public key) with `base64.RawURLEncoding`, and the binary's own
 * `xray x25519` generator emits exactly this form.
 */
export interface RealityKeypair {
  /** Base64url (no padding) of the raw 32-byte public key (Xray `pbk`/`password`). */
  publicKey: string;
  /** Base64url (no padding) of the raw 32-byte private key (Xray `privateKey`). */
  privateKey: string;
}

/**
 * Node's x25519 JWK export (`x` / `d`) is the raw 32-byte key in
 * base64url; Xray's canonical form is base64url without padding — the
 * JWK material already is, so we re-encode to drop any padding.
 */
function jwkMaterialToBase64Url(jwk: { x?: string; d?: string }, field: "x" | "d"): string {
  const encoded = jwk[field];
  if (typeof encoded !== "string" || encoded.length === 0) {
    throw new Error(`malformed x25519 JWK: missing key material ("${field}")`);
  }
  const raw = Buffer.from(encoded, "base64url");
  if (raw.length !== 32) {
    throw new Error(`malformed x25519 key: expected 32 raw bytes, got ${raw.length}`);
  }
  return raw.toString("base64url");
}

/** Generate a fresh x25519 keypair (native crypto, no dependencies). */
export function generateRealityKeypair(): RealityKeypair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  // NB: the private JWK export also carries `x`; take `d` explicitly.
  return {
    publicKey: jwkMaterialToBase64Url(publicKey.export({ format: "jwk" }), "x"),
    privateKey: jwkMaterialToBase64Url(privateKey.export({ format: "jwk" }), "d"),
  };
}

/** UUIDv4 client id. */
export function generateUuid(): string {
  return randomUUID();
}

/** 16 hex chars — auto-generated Reality shortId. */
export function generateShortId(): string {
  return randomBytes(8).toString("hex");
}

/** 32 hex chars — unguessable subscription path hash. */
export function generateSubHash(): string {
  return randomBytes(16).toString("hex");
}