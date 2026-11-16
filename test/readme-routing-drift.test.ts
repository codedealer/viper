import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";
import { HAPP_ROUTE_ORDERS } from "../src/config.js";
import { renderRoutingProfile } from "../src/render/routing.js";

/**
 * README ↔ code drift guard for the routing knob reference: the `RouteOrder`
 * documentation in README.md must stay in sync with the validator's allow-list
 * (`HAPP_ROUTE_ORDERS` in src/config.ts) and the pinned render default
 * (src/render/routing.ts).
 */
function readmeRoutingBlock(): string {
  const readme = readFileSync(join(import.meta.dirname, "..", "README.md"), "utf8");
  const blocks = [...readme.matchAll(/```yaml\n([\s\S]*?)```/g)].map((m) => m[1] as string);
  const block = blocks.find((b) => /\bRouteOrder:\s/.test(b));
  assert.ok(block, "README.md: no yaml block containing a RouteOrder line");
  return block as string;
}

test("README pins the same RouteOrder as the rendered default profile", () => {
  const block = readmeRoutingBlock();
  const pinned = block.match(/\bRouteOrder:\s*([A-Za-z0-9-]+)/)?.[1];
  assert.ok(pinned, "README.md: RouteOrder line has no value");
  const rendered = renderRoutingProfile({ name: "drift-check", profile: {} });
  assert.equal(
    pinned,
    rendered.RouteOrder,
    `README pins RouteOrder "${pinned}" but the rendered default is "${String(rendered.RouteOrder)}"`,
  );
});

test("README documents every accepted RouteOrder value", () => {
  const block = readmeRoutingBlock();
  const missing = [...HAPP_ROUTE_ORDERS].filter((value) => !block.includes(value));
  assert.deepEqual(
    missing,
    [],
    `README.md routing example is missing RouteOrder value(s): ${missing.join(", ")}`,
  );
});

test("README RouteOrder values are all valid per the code allow-list", () => {
  const block = readmeRoutingBlock();
  const values = [...block.matchAll(/\b(block|proxy|direct)(?:-(?:block|proxy|direct)){2}\b/g)].map(
    (m) => m[0],
  );
  assert.ok(values.length > 0, "README.md: no RouteOrder-looking values found");
  const invalid = [...new Set(values)].filter((v) => !HAPP_ROUTE_ORDERS.has(v));
  assert.deepEqual(invalid, [], `README.md lists value(s) the validator would reject: ${invalid.join(", ")}`);
});
