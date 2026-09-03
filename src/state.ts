import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { parse, stringify } from "yaml";
import { ConfigError, SHORT_ID_RE } from "./config.js";
import type { ServerConfig } from "./config.js";
import {
  generateRealityKeypair,
  generateShortId,
  generateSubHash,
  generateUuid,
  type RealityKeypair,
} from "./keys.js";

export interface StateClient {
  name: string;
  uuid: string;
}

/**
 * `state/<name>.yml` — viper-generated secrets, machine-owned. Never
 * re-rendered from the template; regenerated only by `viper rotate`
 * (a later milestone). Written locally BEFORE anything is pushed to
 * the server (Meridian rule).
 */
export interface State {
  reality: RealityKeypair;
  /** "" when the config pins shortId explicitly. */
  shortId: string;
  subHash: string;
  clients: StateClient[];
  /**
   * Server host key captured on first deploy (M4); verified on later
   * deploys. `null` until captured (also the shape of older state files
   * that predate the field).
   */
  hostKey: { fingerprint: string } | null;
  /** Packages viper itself installed (for teardown, M7+). */
  installedPackages: string[];
}

/**
 * Reality keys are canonical base64url without padding (43 chars) — the
 * form the pinned Xray binary requires (`base64.RawURLEncoding`). State
 * files written by older viper versions hold standard base64 (with
 * padding); both are accepted and normalized on load.
 */
const KEY_STD_B64_RE = /^[A-Za-z0-9+/]{43}=$/;
const KEY_URL_B64_RE = /^[A-Za-z0-9_-]{43}$/;

function normalizeKey(value: string): string {
  if (KEY_STD_B64_RE.test(value)) {
    return Buffer.from(value, "base64").toString("base64url");
  }
  if (KEY_URL_B64_RE.test(value)) {
    return Buffer.from(value, "base64url").toString("base64url");
  }
  return value; // invalid — the caller reports it
}
const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX_RE = /^[0-9a-f]+$/i;
/** SHA256:<base64-no-padding of a 32-byte digest> — 43 base64 chars (OpenSSH format). */
const FINGERPRINT_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;

function fail(path: string, message: string): never {
  throw new ConfigError(`state: ${path}: ${message}`);
}

/** Strictly parse a state document (refuses to render on corruption). */
export function parseState(doc: unknown): State {
  const root = "state";
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) {
    fail(root, "expected a mapping");
  }
  const d = doc as Record<string, unknown>;

  const reality = d.reality as Record<string, unknown> | undefined;
  if (typeof reality !== "object" || reality === null) {
    fail(`${root}.reality`, "expected a mapping");
  }
  let publicKey = "";
  let privateKey = "";
  for (const key of ["publicKey", "privateKey"] as const) {
    const value = reality[key];
    if (typeof value !== "string") {
      fail(`${root}.reality.${key}`, "expected base64 of a raw 32-byte key");
    }
    if (!KEY_STD_B64_RE.test(value) && !KEY_URL_B64_RE.test(value)) {
      fail(`${root}.reality.${key}`, "expected base64 of a raw 32-byte key");
    }
    const normalized = normalizeKey(value);
    if (key === "publicKey") publicKey = normalized;
    else privateKey = normalized;
  }

  const shortId = d.shortId;
  if (typeof shortId !== "string" || !SHORT_ID_RE.test(shortId)) {
    fail(`${root}.shortId`, "expected 0–16 hex chars, even length");
  }

  const subHash = d.subHash;
  if (typeof subHash !== "string" || subHash.length !== 32 || !HEX_RE.test(subHash)) {
    fail(`${root}.subHash`, "expected 32 hex chars");
  }

  if (!Array.isArray(d.clients) || d.clients.length === 0) {
    fail(`${root}.clients`, "expected a non-empty list");
  }
  const clients: StateClient[] = [];
  const seen = new Set<string>();
  (d.clients as unknown[]).forEach((item, i) => {
    const c = item as Record<string, unknown>;
    if (typeof c !== "object" || c === null) {
      fail(`${root}.clients[${i}]`, "expected a mapping");
    }
    const name = c.name;
    const uuid = c.uuid;
    if (typeof name !== "string" || name.length === 0) {
      fail(`${root}.clients[${i}].name`, "expected a non-empty string");
    }
    if (seen.has(name)) {
      fail(`${root}.clients[${i}].name`, `duplicate client name "${name}"`);
    }
    seen.add(name);
    if (typeof uuid !== "string" || !UUID_V4_RE.test(uuid)) {
      fail(`${root}.clients[${i}].uuid`, "expected a UUIDv4");
    }
    clients.push({ name, uuid });
  });

  // hostKey (M4, additive): absent/null in state files written before M4.
  let hostKey: State["hostKey"] = null;
  if (d.hostKey !== undefined && d.hostKey !== null) {
    const hk = d.hostKey;
    if (typeof hk !== "object" || hk === null || Array.isArray(hk)) {
      fail(`${root}.hostKey`, "expected a mapping or null");
    }
    const fingerprint = (hk as Record<string, unknown>).fingerprint;
    if (typeof fingerprint !== "string" || !FINGERPRINT_RE.test(fingerprint)) {
      fail(`${root}.hostKey.fingerprint`, "expected SHA256:<base64-no-padding> (OpenSSH format)");
    }
    hostKey = { fingerprint };
  }

  // installedPackages (M4, additive): absent in state files written before M4.
  let installedPackages: string[] = [];
  if (d.installedPackages !== undefined) {
    if (!Array.isArray(d.installedPackages)) {
      fail(`${root}.installedPackages`, "expected a list of package names");
    }
    installedPackages = (d.installedPackages as unknown[]).map((p, i) => {
      if (typeof p !== "string" || p.length === 0) {
        fail(`${root}.installedPackages[${i}]`, "expected a non-empty string");
      }
      return p;
    });
  }

  return {
    reality: { publicKey, privateKey },
    shortId,
    subHash,
    clients,
    hostKey,
    installedPackages,
  };
}

export function statePath(projectDir: string, name: string): string {
  return join(projectDir, "state", `${name}.yml`);
}

/** Load and validate an existing state file. */
export async function loadState(path: string): Promise<State> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (err) {
    throw new ConfigError(`state: cannot read ${path}: ${(err as Error).message}`);
  }
  try {
    return parseState(parse(text));
  } catch (err) {
    if (err instanceof ConfigError) throw err;
    throw new ConfigError(`state: ${path}: ${(err as Error).message}`);
  }
}

/** Canonical serialization of a state document (deterministic). */
export function serializeState(state: State): string {
  return stringify(state, { lineWidth: 0 });
}

/**
 * Persist state with mode 0600 (secrets file — owner read/write only).
 * chmod is applied explicitly because writeFile's mode is masked by
 * umask and does not apply to existing files.
 */
export async function saveState(path: string, state: State): Promise<void> {
  await writeStateText(path, serializeState(state));
}

async function writeStateText(path: string, text: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, text, { encoding: "utf8", mode: 0o600 });
  await chmod(path, 0o600);
}

/**
 * Load state, or create + persist it (keypair, uuids, sub path hash).
 * Idempotent: on re-run the existing secrets are reused; clients added
 * to the config since the last run get a fresh uuid, existing ones keep
 * theirs. Returns `created` so the CLI can report state lifecycle.
 */
export async function ensureState(
  projectDir: string,
  config: ServerConfig,
): Promise<{ state: State; created: boolean }> {
  const path = statePath(projectDir, config.name);
  const existing = existsSync(path) ? await loadState(path) : undefined;

  if (existing !== undefined) {
    const byName = new Map(existing.clients.map((c) => [c.name, c.uuid]));
    const clients: StateClient[] = config.clients.map((c) => {
      const uuid = byName.get(c.name) ?? generateUuid();
      byName.set(c.name, uuid);
      return { name: c.name, uuid };
    });
    const state: State = {
      ...existing,
      shortId: existing.shortId !== "" || config.shortId !== "" ? existing.shortId : generateShortId(),
      clients,
    };
    // Skip the write when nothing changed: a no-op re-render must not
    // touch the file (mtime stability, no writer race).
    const onDisk = await readFile(path, "utf8").catch(() => undefined);
    if (onDisk !== serializeState(state)) {
      await writeStateText(path, serializeState(state));
    }
    return { state, created: false };
  }

  const state: State = {
    reality: generateRealityKeypair(),
    shortId: config.shortId === "" ? generateShortId() : "",
    subHash: generateSubHash(),
    clients: config.clients.map((c) => ({ name: c.name, uuid: generateUuid() })),
    hostKey: null,
    installedPackages: [],
  };
  await saveState(path, state);
  return { state, created: true };
}

/** Effective Reality shortId: the config pin wins; otherwise state. */
export function shortIdOf(config: ServerConfig, state: State): string {
  return config.shortId !== "" ? config.shortId : state.shortId;
}
