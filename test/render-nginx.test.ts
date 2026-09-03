import assert from "node:assert/strict";
import { test } from "node:test";
import { renderNginx } from "../src/render/nginx.js";
import { fixtureConfig, fixtureState, knobConfig, knobState } from "./fixtures.js";
import { assertGolden } from "./golden.js";

test("default knobs — golden :80 ACME vhost", () => {
  const confs = renderNginx(fixtureConfig, fixtureState);
  assertGolden(import.meta.url, "nginx-80.conf", confs["nginx-80.conf"]);

  const c80 = confs["nginx-80.conf"];
  assert.match(c80, /listen 80;/);
  assert.match(c80, /server_name vpn\.example\.com;/);
  assert.match(c80, /location \^~ \/\.well-known\/acme-challenge\//);
  assert.match(c80, /return 404;/);
  assert.match(c80, /server_tokens off;/);
  assert.ok(!/return 301|return 302/.test(c80), "no redirects on :80 (contradiction signal)");
});

test("default knobs — golden :8443 loopback web vhost", () => {
  const confs = renderNginx(fixtureConfig, fixtureState);
  assertGolden(import.meta.url, "nginx-8443.conf", confs["nginx-8443.conf"]);

  const c8443 = confs["nginx-8443.conf"];
  assert.match(c8443, /listen 127\.0\.0\.1:8443 ssl http2;/);
  assert.match(c8443, /server_name vpn\.example\.com;/);
  assert.match(c8443, /location = \/ \{[^}]*root \/var\/www\/viper\/main;/s);
  assert.match(c8443, /location = \/index\.html \{[^}]*root \/var\/www\/viper\/main;/s);
  assert.match(c8443, /location = \/login \{[^}]*alias \/var\/www\/viper\/main\/index\.html;/s);
  assert.match(
    c8443,
    /location = \/deadbeefcafebabe1234567890abcdef\/sub\.txt \{[^}]*alias \/var\/www\/viper\/main\/sub\.txt;/s,
  );
  assert.match(c8443, /return 404;/);
  assert.match(c8443, /server_tokens off;/);
  assert.ok(!/auth_basic/.test(c8443), "no auth on the loopback vhost (v1)");
});

test("knob variations — different domain, name, web port and sub hash", () => {
  const confs = renderNginx(knobConfig, knobState);
  assertGolden(import.meta.url, "nginx-knobs-80.conf", confs["nginx-80.conf"]);
  assertGolden(import.meta.url, "nginx-knobs-8443.conf", confs["nginx-8443.conf"]);

  assert.match(confs["nginx-80.conf"], /server_name proxy\.example\.org;/);
  const c8443 = confs["nginx-8443.conf"];
  assert.match(c8443, /listen 127\.0\.0\.1:9443 ssl http2;/);
  assert.match(c8443, /alias \/var\/www\/viper\/alt\/index\.html;/);
  assert.match(c8443, /location = \/00112233445566778899aabbccddeeff\/sub\.txt/);
  assert.match(c8443, /ssl_certificate \/etc\/nginx\/ssl\/proxy\.example\.org\/fullchain\.pem;/);
});

test("render is pure — repeated calls give identical output", () => {
  const a = renderNginx(fixtureConfig, fixtureState);
  const b = renderNginx(fixtureConfig, fixtureState);
  assert.deepEqual(a, b);
});

// Regression guard for the 2026-09-01 live HTTP 500 on `/`: with
// `alias <file>` in `location = /`, nginx's index module appends
// `index.html` to the already-computed file path
// (`/var/www/viper/main/index.htmlindex.html`) → 500. Unit fakes cannot
// exercise real nginx alias/index semantics — this render-level guard is
// the regression net. The fix: `root` in `location = /` + a
// `location = /index.html` catch block (internal redirect, clean path).
test("root URI uses root, not alias — live 500 regression (2026-09-01)", () => {
  const confs = renderNginx(fixtureConfig, fixtureState);
  const c8443 = confs["nginx-8443.conf"];
  const rootLoc = c8443.match(/location = \/ \{[^}]*\}/);
  assert.ok(rootLoc, "has an exact-match root location");
  assert.match(rootLoc[0], /root \/var\/www\/viper\/main;/, "root URI location uses root");
  assert.ok(!/alias/.test(rootLoc[0]), "root URI location must NOT use alias");
  assert.match(
    c8443,
    /location = \/index\.html \{[^}]*root \/var\/www\/viper\/main;/s,
    "has the /index.html internal-redirect catch block",
  );
  // /login is proven working live with alias — keep it unchanged.
  assert.match(c8443, /location = \/login \{[^}]*alias \/var\/www\/viper\/main\/index\.html;/s);
});
