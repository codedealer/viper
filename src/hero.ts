import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { ConfigError } from "./config.js";

/** Project-relative location of the decoy-page hero image (M2). */
export const HERO_REL = join("assets", "images", "hero.webp");

/**
 * Read the hero image and return its base64 encoding for inlining into
 * the page (data-URI). The renderer itself stays pure — no fs in
 * src/render. Shared by the CLI (M2) and the M6 page-deploy step seam.
 */
export async function loadHeroBase64(projectDir: string): Promise<string> {
  const path = join(projectDir, HERO_REL);
  try {
    return await readFile(path, "base64");
  } catch (err) {
    throw new ConfigError(
      `hero: missing hero image "${HERO_REL}" (required for the decoy page) ` +
        `— put assets/images/hero.webp in the project directory and re-run`,
    );
  }
}
