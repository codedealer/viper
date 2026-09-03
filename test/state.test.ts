import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { parse as parseYaml } from "yaml";
import type { ServerConfig } from "../src/config.js";
import {
  ensureState,
  loadState,
  parseState,
  saveState,
  serializeState,
  shortIdOf,
  statePath,
  type State,
} from "../src/state.js";
import { fixtureConfig } from "./fixtures.js";

const baseConfig = (clients: { name: string }[] = [{ name: "default" }]): ServerConfig => ({
  ...fixtureConfig,
  clients: clients.map((c) => ({ ...c, limitIp: 0 })),
});

test("ensureState creates state/<name>.yml with mode 0600 and valid secrets", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    const { state, created } = await ensureState(dir, baseConfig());
    assert.equal(created, true);

    const st = await stat(statePath(dir, "main"));
    assert.equal(st.mode & 0o777, 0o600, "state file must be chmod 600");

    const reloaded = await loadState(statePath(dir, "main"));
    assert.deepEqual(reloaded, state);
    assert.equal(Buffer.from(state.reality.privateKey, "base64").length, 32);
    assert.equal(Buffer.from(state.reality.publicKey, "base64").length, 32);
    assert.match(state.subHash, /^[0-9a-f]{32}$/);
    const client = state.clients[0];
    assert.ok(client);
    assert.equal(client.name, "default");
    assert.match(client.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("ensureState is idempotent — re-run reuses all secrets", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    const first = await ensureState(dir, baseConfig());
    const second = await ensureState(dir, baseConfig());
    assert.equal(second.created, false);
    assert.deepEqual(second.state, first.state);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("no-op re-render does not touch the state file (mtime stable)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    await ensureState(dir, baseConfig());
    const path = statePath(dir, "main");
    const before = await stat(path);
    const second = await ensureState(dir, baseConfig());
    assert.equal(second.created, false);
    const after = await stat(path);
    assert.equal(after.mtimeMs, before.mtimeMs, "mtime must not advance on an unchanged re-render");
    assert.equal(after.mode & 0o777, 0o600);

    // a changed config (new client) DOES rewrite the file
    await ensureState(dir, baseConfig([{ name: "default" }, { name: "phone" }]));
    const changed = await stat(path);
    assert.deepEqual(
      (await loadState(path)).clients.map((c) => c.name),
      ["default", "phone"],
    );
    assert.ok(changed.size >= before.size);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("ensureState adds uuids for new clients, keeps existing ones", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    const first = await ensureState(dir, baseConfig());
    const second = await ensureState(dir, baseConfig([{ name: "default" }, { name: "phone" }]));
    assert.equal(second.created, false);
    const byName = new Map(second.state.clients.map((c) => [c.name, c.uuid]));
    assert.equal(byName.get("default"), first.state.clients[0]?.uuid);
    assert.match(byName.get("phone") as string, /^[\da-f-]{36}$/i);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("auto shortId is generated once; explicit pin stays out of state", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    const { state } = await ensureState(dir, baseConfig());
    assert.match(state.shortId, /^[0-9a-f]{16}$/);
    assert.equal(shortIdOf(baseConfig(), state), state.shortId);

    const pinned: ServerConfig = { ...baseConfig(), shortId: "cafebabe" };
    const pinnedState = await ensureState(dir, pinned);
    // existing state keeps its shortId; the config pin wins in rendering
    assert.equal(pinnedState.state.shortId, state.shortId);
    assert.equal(shortIdOf(pinned, pinnedState.state), "cafebabe");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("fresh state with explicit shortId pin leaves state.shortId empty", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    const pinned: ServerConfig = { ...baseConfig(), shortId: "cafebabe" };
    const { state } = await ensureState(dir, pinned);
    assert.equal(state.shortId, "");
    assert.equal(shortIdOf(pinned, state), "cafebabe");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("parseState rejects corrupted state", () => {
  const ok: State = {
    reality: {
      publicKey: "RRaBqa-l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0",
      privateKey: "KE9dFWwBEA5xCSZV0Efu-m7RdHZEPFQhpY4ka_HmiHA",
    },
    shortId: "",
    subHash: "deadbeefcafebabe1234567890abcdef",
    clients: [{ name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" }],
    hostKey: null,
    installedPackages: [],
  };
  assert.deepEqual(parseState(ok), ok);
  assert.throws(() => parseState({ ...ok, reality: { ...ok.reality, publicKey: "!!!" } }), /publicKey/);
  assert.throws(() => parseState({ ...ok, subHash: "xyz" }), /subHash/);
  assert.throws(
    () => parseState({ ...ok, shortId: "abc" }),
    /shortId/, // odd-length hex
  );
  assert.throws(
    () => parseState({ ...ok, shortId: "0123456789abcdef0" }),
    /shortId/, // > 16 chars
  );
  assert.throws(
    () =>
      parseState({
        ...ok,
        clients: [{ name: "default", uuid: "not-a-uuid" }],
      }),
    /uuid/,
  );
});

test("parseState normalizes legacy standard-base64 keys to canonical base64url", () => {
  const legacy: State = {
    reality: {
      publicKey: "RRaBqa+l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0=",
      privateKey: "KE9dFWwBEA5xCSZV0Efu+m7RdHZEPFQhpY4ka/HmiHA=",
    },
    shortId: "",
    subHash: "deadbeefcafebabe1234567890abcdef",
    clients: [{ name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" }],
    hostKey: null,
    installedPackages: [],
  };
  const parsed = parseState(legacy);
  assert.equal(parsed.reality.publicKey, "RRaBqa-l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0");
  assert.equal(parsed.reality.privateKey, "KE9dFWwBEA5xCSZV0Efu-m7RdHZEPFQhpY4ka_HmiHA");
  // canonical keys pass through unchanged
  const canonical = parseState(parsed);
  assert.deepEqual(canonical.reality, parsed.reality);
});

test("M4 state fields: hostKey + installedPackages parse, validate, round-trip", () => {
  const fp = "SHA256:" + "A".repeat(43);
  const doc = {
    reality: {
      publicKey: "RRaBqa+l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0=",
      privateKey: "KE9dFWwBEA5xCSZV0Efu+m7RdHZEPFQhpY4ka/HmiHA=",
    },
    shortId: "",
    subHash: "deadbeefcafebabe1234567890abcdef",
    clients: [{ name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" }],
    hostKey: { fingerprint: fp },
    installedPackages: ["nginx", "ufw"],
  };
  const state = parseState(doc);
  assert.equal(state.hostKey?.fingerprint, fp);
  assert.deepEqual(state.installedPackages, ["nginx", "ufw"]);

  // round-trip through YAML serialization
  assert.deepEqual(parseYaml(serializeState(state)), state);

  // invalid values rejected
  assert.throws(() => parseState({ ...doc, hostKey: { fingerprint: "md5:abcd" } }), /hostKey.fingerprint/);
  assert.throws(
    () => parseState({ ...doc, hostKey: { fingerprint: "sha256:short" } }),
    /hostKey.fingerprint/,
  );
  // lowercase "sha256:" is NOT the stored format (OpenSSH uses SHA256:)
  assert.throws(
    () => parseState({ ...doc, hostKey: { fingerprint: "sha256:" + "A".repeat(43) } }),
    /hostKey.fingerprint/,
  );
  assert.throws(() => parseState({ ...doc, hostKey: "plain" }), /hostKey/);
  assert.throws(() => parseState({ ...doc, installedPackages: "nginx" }), /installedPackages/);
  assert.throws(() => parseState({ ...doc, installedPackages: ["nginx", ""] }), /installedPackages/);
});

test("M4 state fields: old files missing them still load (defaults)", () => {
  const oldDoc = {
    reality: {
      publicKey: "RRaBqa+l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0=",
      privateKey: "KE9dFWwBEA5xCSZV0Efu+m7RdHZEPFQhpY4ka/HmiHA=",
    },
    shortId: "",
    subHash: "deadbeefcafebabe1234567890abcdef",
    clients: [{ name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" }],
  };
  const state = parseState(oldDoc);
  assert.equal(state.hostKey, null);
  assert.deepEqual(state.installedPackages, []);

  // explicit null hostKey (new format, not yet captured) also loads
  const state2 = parseState({ ...oldDoc, hostKey: null, installedPackages: [] });
  assert.equal(state2.hostKey, null);
  assert.deepEqual(state2.installedPackages, []);
});

test("new state writes always include hostKey + installedPackages keys", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    await ensureState(dir, baseConfig());
    const onDisk = await readFile(statePath(dir, "main"), "utf8");
    assert.match(onDisk, /hostKey: null/);
    assert.match(onDisk, /installedPackages: \[\]/);

    // after a capture + save, the fields persist
    const withKey: State = {
      ...(await loadState(statePath(dir, "main"))),
      hostKey: { fingerprint: "SHA256:" + "B".repeat(43) },
      installedPackages: ["nginx"],
    };
    await saveState(statePath(dir, "main"), withKey);
    const reloaded = await loadState(statePath(dir, "main"));
    assert.deepEqual(reloaded.hostKey, { fingerprint: "SHA256:" + "B".repeat(43) });
    assert.deepEqual(reloaded.installedPackages, ["nginx"]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("saveState overwrites an existing file and keeps mode 0600", async () => {
  const dir = await mkdtemp(join(tmpdir(), "viper-state-"));
  try {
    const path = join(dir, "state", "main.yml");
    const state = {
      reality: {
        publicKey: "RRaBqa-l0ks8eBBQsFhxYUL6jPKwKXBtvVlflQqyaD0",
        privateKey: "KE9dFWwBEA5xCSZV0Efu-m7RdHZEPFQhpY4ka_HmiHA",
      },
      shortId: "",
      subHash: "deadbeefcafebabe1234567890abcdef",
      clients: [{ name: "default", uuid: "123e4567-e89b-42d3-a456-426614174000" }],
      hostKey: null,
      installedPackages: [],
    };
    await saveState(path, state);
    const mutated = {
      ...state,
      subHash: "00112233445566778899aabbccddeeff",
    };
    await saveState(path, mutated);
    const st = await stat(path);
    assert.equal(st.mode & 0o777, 0o600);
    assert.deepEqual(await loadState(path), mutated);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
