import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Minimal golden-file helper.
 *
 * - Golden files live in `test/golden/<name>` next to the test file.
 * - First run: missing goldens are written (so a fresh checkout passes).
 * - Later runs: byte-for-byte comparison.
 * - Regeneration is explicit: `GOLDEN_UPDATE=1 pnpm test`.
 */
export function assertGolden(fileUrl: string, name: string, actual: string): void {
  const dir = join(dirname(fileURLToPath(fileUrl)), "golden");
  const path = join(dir, name);

  if (process.env.GOLDEN_UPDATE === "1" || !existsSync(path)) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(path, actual);
    return;
  }

  const expected = readFileSync(path, "utf8");
  assert.equal(
    actual,
    expected,
    `golden mismatch for "${name}" — if the change is intentional, regenerate with GOLDEN_UPDATE=1 pnpm test`,
  );
}
