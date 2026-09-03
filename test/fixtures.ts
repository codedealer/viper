import type { ServerConfig } from "../src/config.js";
import type { State } from "../src/state.js";

/**
 * Deterministic fixtures for golden-file tests.
 * The reality keypair is a real x25519 pair (see test/keys.test.ts for
 * the consistency check); uuids/shortId/subHash are fixed values.
 */
export const fixtureConfig: ServerConfig = {
  name: "main",
  ip: "203.0.113.10",
  domain: "vpn.example.com",
  xray: "v26.3.27",
  sshPort: 22,
  listen: "0.0.0.0",
  port: 443,
  webPort: 8443,
  fingerprint: "chrome",
  flow: "xtls-rprx-vision",
  shortId: "",
  maxTimediff: 0,
  xver: 0,
  logLevel: "warning",
  sniffing: true,
  harden: true,
  bbr: true,
  clients: [{ name: "default", limitIp: 2 }],
};

export const fixtureState: State = {
  reality: {
    publicKey: "RRaBqa-l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0",
    privateKey: "KE9dFWwBEA5xCSZV0Efu-m7RdHZEPFQhpY4ka_HmiHA",
  },
  shortId: "0123456789abcdef",
  subHash: "deadbeefcafebabe1234567890abcdef",
  clients: [{ name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" }],
  hostKey: null,
  installedPackages: [],
};

export const multiClientConfig: ServerConfig = {
  ...fixtureConfig,
  clients: [
    { name: "default", limitIp: 2 },
    { name: "phone", limitIp: 0 },
    { name: "work", limitIp: 1 },
  ],
};

export const multiClientState: State = {
  ...fixtureState,
  clients: [
    { name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" },
    { name: "phone", uuid: "00000000-0000-4000-8000-000000000000" },
    { name: "work", uuid: "f47ac10b-58cc-4372-a567-0e02b2c3d479" },
  ],
  hostKey: null,
  installedPackages: [],
};

/** Same topology, different knobs: custom web port, pinned shortId,
 * different fingerprint, no flow, sniffing off, custom log level. */
export const knobConfig: ServerConfig = {
  ...fixtureConfig,
  name: "alt",
  domain: "proxy.example.org",
  ip: "198.51.100.7",
  listen: "0.0.0.0",
  port: 443,
  webPort: 9443,
  fingerprint: "firefox",
  flow: "",
  shortId: "deadbeef",
  maxTimediff: 3600000,
  xver: 1,
  logLevel: "error",
  sniffing: false,
  harden: true,
  bbr: true,
  sshPort: 2222,
  clients: [{ name: "default", limitIp: 0 }],
};

export const knobState: State = {
  ...fixtureState,
  shortId: "", // config pins shortId — state stays empty
  subHash: "00112233445566778899aabbccddeeff",
};
