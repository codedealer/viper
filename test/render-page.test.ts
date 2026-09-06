import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { PAGE_MARKER, renderPage } from "../src/render/page.js";
import { assertGolden } from "./golden.js";

// The committed asset is the golden's fixed fixture — deterministic while
// it is unchanged (contract: the CLI reads the asset, tests inject it).
const HERO = new URL("../assets/images/hero.webp", import.meta.url);
const heroBase64: string = await readFile(HERO, "base64");

test("faux SaaS login page — golden HTML (hero inlined as data-URI)", () => {
  const html = renderPage(heroBase64);
  assertGolden(import.meta.url, "page.html", html);
  assert.match(html, /<!doctype html>/i);
  assert.match(html, /type="password"/);
  assert.match(html, /Invalid email or password/i);
});

test("hero is present exactly once, inlined as a webp data-URI", () => {
  const html = renderPage(heroBase64);
  const needle = `src="data:image/webp;base64,${heroBase64}"`;
  assert.equal(html.split(needle).length - 1, 1, "hero must appear exactly once");
});

test("zero outbound network requests from the page", () => {
  const html = renderPage(heroBase64);
  assert.ok(!/https?:\/\//i.test(html), "no external URLs anywhere");
  assert.ok(!/fetch\(|XMLHttpRequest|navigator\.sendBeacon/i.test(html));
  assert.ok(!/@import|url\(\s*["']?http/i.test(html), "no remote CSS/fonts");
  const srcs = [...html.matchAll(/\ssrc="([^"]*)"/g)].map((m) => m[1] as string);
  assert.ok(srcs.length > 0);
  assert.ok(
    srcs.every((s) => s.startsWith("data:")),
    `the only asset is inlined (got: ${srcs.join(", ")})`,
  );
  assert.ok(!/href="[^"]*:/i.test(html), "no absolute-URL links");
});

test("form is inert: always fails, no success path", () => {
  const html = renderPage(heroBase64);
  assert.match(html, /type="email"/);
  assert.match(html, /type="password"/);
  assert.match(html, /e\.preventDefault\(\)/, "submit is cancelled client-side");
  assert.match(html, /login-error/, "a generic invalid-credentials message exists");
  assert.ok(
    !/success|logged in|signed in|welcome back/i.test(html),
    "no success/login state anywhere in the page",
  );
  assert.ok(!/location\.(href|replace|assign)|window\.open/i.test(html), "no navigation away from the page");
  // exactly one script block: the inert submit handler
  assert.equal(html.match(/<script>/g)?.length, 1);
});

test("no framework, build or generation fingerprints", () => {
  const html = renderPage(heroBase64);
  // Check the markup only — the inlined image payload is binary base64
  // and can coincidentally contain any ASCII substring (e.g. "vUE").
  const markup = html.replace(/data:[^"\n]+/g, "data:…");
  assert.ok(
    !/react|vue|angular|jquery|svelte|solid-js|preact|webpack|vite|__NEXT|data-astro|nuxt/i.test(markup),
    "no JS framework names",
  );
  assert.ok(!/<meta\s+name="generator"/i.test(markup), "no generator meta");
  assert.ok(!/<!--/.test(markup), "no HTML comments");
});

test("layout: full-screen hero background, form card centered above it", () => {
  const html = renderPage(heroBase64);
  assert.match(html, /object-fit:cover/, "hero covers the viewport");
  assert.match(html, /100vh/, "full-screen background height");
  assert.match(html, /display:flex/, "card container is flex");
  assert.match(html, /align-items:center/, "card centered vertically");
  assert.match(html, /justify-content:center/, "card centered horizontally");
  assert.match(html, /footer\{position:fixed/, "footer anchored to the viewport bottom");
});

test("stable page marker is present in the rendered page", () => {
  const html = renderPage(heroBase64);
  assert.ok(PAGE_MARKER.length > 0, "marker constant must be non-empty");
  assert.ok(html.includes(PAGE_MARKER), "renderPage output must contain the PAGE_MARKER");
});

test("page is deterministic (no timestamps/randomness)", () => {
  assert.equal(renderPage(heroBase64), renderPage(heroBase64));
});

test("renderer is pure — output depends only on the injected base64", () => {
  // a different (small, fixture) encoding flows straight through
  assert.ok(renderPage("aGVsbG8=").includes('src="data:image/webp;base64,aGVsbG8="'));
  assert.notEqual(renderPage("aGVsbG8="), renderPage("aGV5dA=="));
});
