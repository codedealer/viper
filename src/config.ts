import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { parse } from "yaml";

/** Error with a human-readable, actionable message for config problems. */
export class ConfigError extends Error {}

export interface ClientConfig {
  name: string;
  /** Max concurrent IPs per client; 0 = unlimited (Xray default). */
  limitIp: number;
}

/**
 * A validated `viper.<name>.yml` server definition with defaults applied.
 * Names/domains are used exactly as supplied — viper never derives or
 * prefixes subdomains.
 */
export interface ServerConfig {
  /** Server name — taken from the `viper.<name>.yml` filename. */
  name: string;
  ip: string;
  domain: string;
  /** Hard-pinned Xray version, e.g. `v26.3.27`. */
  xray: string;
  sshPort: number;
  sshKey?: string;
  listen: string;
  port: number;
  /** Loopback nginx web vhost port (Xray Reality `dest`). */
  webPort: number;
  fingerprint: string;
  /** "" disables flow. */
  flow: string;
  /** "" = auto-generate once into state/<name>.yml. */
  shortId: string;
  maxTimediff: number;
  xver: number;
  logLevel: string;
  sniffing: boolean;
  clients: ClientConfig[];
  /** Gates tz/auto-upgrades/ssh/fail2ban/ufw hardening steps (default true). */
  harden: boolean;
  /** Gates the BBR step (default true). */
  bbr: boolean;
}

const SERVER_FILE_RE = /^viper\.([a-z0-9][a-z0-9-]*)\.yml$/;
const IP_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/**
 * Validate an IPv4 address, throwing a ConfigError on failure. Shared by
 * the `ip` config field and the CLI `--ip` override (M7, D2).
 */
export function assertValidIpv4(ip: string, path: string): void {
  const m = ip.match(IP_RE);
  if (!m || m.slice(1, 5).some((o) => Number(o) > 255)) {
    fail(`${path}.ip`, `"${ip}" is not a valid IPv4 address`);
  }
}
const XRAY_PIN_RE = /^v\d+\.\d+\.\d+$/;
/** Reality shortId: 0–16 hex chars, even length (Xray reality docs). */
export const SHORT_ID_RE = /^(?:[0-9a-f]{2}){0,8}$/i;
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

const FINGERPRINTS = new Set([
  "chrome",
  "firefox",
  "safari",
  "ios",
  "android",
  "edge",
  "360",
  "qq",
  "random",
]);
const LOG_LEVELS = new Set(["debug", "info", "warning", "error"]);
const FLOWS = new Set(["", "xtls-rprx-vision"]);

function fail(path: string, message: string): never {
  throw new ConfigError(`config: ${path}: ${message}`);
}

function asRecord(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(path, "expected a mapping");
  }
  return value as Record<string, unknown>;
}

function stringField(doc: Record<string, unknown>, key: string, path: string): string {
  const value = doc[key];
  if (typeof value !== "string" || value.length === 0) {
    fail(`${path}.${key}`, "expected a non-empty string");
  }
  return value;
}

function optionalStringField(doc: Record<string, unknown>, key: string, path: string): string | undefined {
  const value = doc[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string" || value.length === 0) {
    fail(`${path}.${key}`, "expected a non-empty string");
  }
  return value;
}

function intField(
  doc: Record<string, unknown>,
  key: string,
  path: string,
  min: number,
  max: number,
  def: number,
): number {
  const value = doc[key];
  if (value === undefined) return def;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    fail(`${path}.${key}`, "expected an integer");
  }
  if (value < min || value > max) {
    fail(`${path}.${key}`, `expected an integer between ${min} and ${max}`);
  }
  return value;
}

function boolField(doc: Record<string, unknown>, key: string, path: string, def: boolean): boolean {
  const value = doc[key];
  if (value === undefined) return def;
  if (typeof value !== "boolean") fail(`${path}.${key}`, "expected a boolean");
  return value;
}

function enumField(
  doc: Record<string, unknown>,
  key: string,
  path: string,
  allowed: Set<string>,
  def: string,
): string {
  const value = doc[key];
  if (value === undefined) return def;
  if (typeof value !== "string" || !allowed.has(value)) {
    fail(`${path}.${key}`, `expected one of: ${[...allowed].sort().join(", ")}`);
  }
  return value;
}

function parseClients(value: unknown, path: string): ClientConfig[] {
  if (!Array.isArray(value) || value.length === 0) {
    fail(`${path}.clients`, "expected a non-empty list of clients");
  }
  const seen = new Set<string>();
  const clients: ClientConfig[] = [];
  value.forEach((item, i) => {
    const cpath = `${path}.clients[${i}]`;
    const c = asRecord(item, cpath);
    const name = stringField(c, "name", cpath);
    if (seen.has(name)) fail(`${cpath}.name`, `duplicate client name "${name}"`);
    seen.add(name);
    clients.push({
      name,
      limitIp: intField(c, "limitIp", cpath, 0, 65535, 0),
    });
  });
  return clients;
}

/** Parse + validate a `viper.<name>.yml` document, applying defaults. */
export function parseServerConfig(name: string, doc: unknown): ServerConfig {
  const root = `viper.${name}.yml`;
  const d = asRecord(doc, root);

  const allowed = new Set([
    "ip",
    "domain",
    "xray",
    "sshPort",
    "sshKey",
    "listen",
    "port",
    "webPort",
    "fingerprint",
    "flow",
    "shortId",
    "maxTimediff",
    "xver",
    "logLevel",
    "sniffing",
    "harden",
    "bbr",
    "clients",
  ]);
  for (const key of Object.keys(d)) {
    if (!allowed.has(key)) {
      fail(`${root}.${key}`, "unknown key (typo? see the knob reference)");
    }
  }

  const ip = stringField(d, "ip", root);
  assertValidIpv4(ip, root);

  const domain = stringField(d, "domain", root);
  if (!DOMAIN_RE.test(domain)) {
    fail(`${root}.domain`, `"${domain}" is not a valid domain name`);
  }

  const xray = stringField(d, "xray", root);
  if (!XRAY_PIN_RE.test(xray)) {
    fail(`${root}.xray`, `"${xray}" is not a valid version pin (expected e.g. v26.3.27)`);
  }

  const shortId = optionalStringField(d, "shortId", root) ?? "";
  if (!SHORT_ID_RE.test(shortId)) {
    fail(`${root}.shortId`, `"${shortId}" is not valid (0–16 hex chars, even length; omit for auto)`);
  }

  const maxTimediff = intField(d, "maxTimediff", root, 0, Number.MAX_SAFE_INTEGER, 0);
  const sshKey = optionalStringField(d, "sshKey", root);

  return {
    name,
    ip,
    domain,
    xray,
    sshPort: intField(d, "sshPort", root, 1, 65535, 22),
    ...(sshKey !== undefined ? { sshKey } : {}),
    listen: optionalStringField(d, "listen", root) ?? "0.0.0.0",
    port: intField(d, "port", root, 1, 65535, 443),
    webPort: intField(d, "webPort", root, 1, 65535, 8443),
    fingerprint: enumField(d, "fingerprint", root, FINGERPRINTS, "chrome"),
    flow: enumField(d, "flow", root, FLOWS, "xtls-rprx-vision"),
    shortId,
    maxTimediff,
    xver: intField(d, "xver", root, 0, 255, 0),
    logLevel: enumField(d, "logLevel", root, LOG_LEVELS, "warning"),
    sniffing: boolField(d, "sniffing", root, true),
    harden: boolField(d, "harden", root, true),
    bbr: boolField(d, "bbr", root, true),
    clients: parseClients(d.clients ?? [{ name: "default" }], root),
  };
}

/**
 * Load every `viper.<name>.yml` in the project directory.
 * Returns a map of name → validated config.
 */
export async function loadServers(projectDir: string): Promise<Map<string, ServerConfig>> {
  let entries: string[];
  try {
    entries = await readdir(projectDir);
  } catch (err) {
    throw new ConfigError(`config: cannot read project directory "${projectDir}": ${(err as Error).message}`);
  }
  const servers = new Map<string, ServerConfig>();
  for (const entry of entries.sort()) {
    const m = entry.match(SERVER_FILE_RE);
    if (!m) continue;
    const name = m[1] ?? "";
    let text: string;
    try {
      text = await readFile(join(projectDir, entry), "utf8");
    } catch (err) {
      throw new ConfigError(`config: cannot read ${entry}: ${(err as Error).message}`);
    }
    let doc: unknown;
    try {
      doc = parse(text);
    } catch (err) {
      throw new ConfigError(`config: ${entry}: YAML parse error: ${(err as Error).message}`);
    }
    servers.set(name, parseServerConfig(name, doc));
  }
  return servers;
}

/**
 * Resolve the target server name:
 * - explicit `--name` must exist,
 * - otherwise the sole server is used,
 * - otherwise a clear error (none found / multiple servers).
 */
export function resolveServerName(requested: string | undefined, servers: Map<string, ServerConfig>): string {
  if (requested !== undefined) {
    if (!servers.has(requested)) {
      const known = [...servers.keys()].sort().join(", ") || "(none)";
      throw new ConfigError(`config: no server named "${requested}" (available: ${known})`);
    }
    return requested;
  }
  if (servers.size === 0) {
    throw new ConfigError(
      "config: no server configs found — create a viper.<name>.yml in the project directory",
    );
  }
  if (servers.size === 1) {
    return [...servers.keys()][0] as string;
  }
  const known = [...servers.keys()].sort().join(", ");
  throw new ConfigError(`config: multiple servers (${known}) — pass --name`);
}
