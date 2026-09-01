import type { ServerConfig } from "../config.js";
import type { State } from "../state.js";

export interface NginxConfs {
  "nginx-80.conf": string;
  "nginx-8443.conf": string;
}

const ACME_WEBROOT = "/var/www/acme";
const SITE_ROOT = (name: string) => `/var/www/viper/${name}`;
const CERT_DIR = (domain: string) => `/etc/nginx/ssl/${domain}`;

/**
 * Port 80: ACME HTTP-01 challenges only, 404 for everything else.
 * No redirect (contradiction signal — Meridian lesson).
 */
function renderPort80(config: ServerConfig): string {
  return `# viper: ACME HTTP-01 challenges only — 404 for everything else.
# Managed by viper; do not edit by hand (re-rendered on deploy).
server {
    listen 80;
    server_name ${config.domain};
    server_tokens off;

    location ^~ /.well-known/acme-challenge/ {
        root ${ACME_WEBROOT};
    }

    location / {
        return 404;
    }
}
`;
}

/**
 * Loopback web vhost on 127.0.0.1:<webPort> — never exposed directly;
 * reached solely via Xray's Reality-fail fallback (`dest`). TLS is
 * terminated here with our single-name LE cert. `http2` (nginx 1.24
 * listen-line syntax — 24.04 ships 1.24) keeps the borrowed site
 * browser-plausible (ALPN h2 on the forwarded connection).
 *
 *  - / and /login : faux SaaS login page (inert)
 *  - /index.html : internal-redirect target of `/` (index module)
 *  - /<hash>/sub.txt : Happ subscription (no auth — unguessable path)
 *  - everything else : 404 (no fingerprintable custom error pages)
 *
 *  NOTE: `/` uses `root` (NOT `alias`): for the root URI nginx's index
 *  module would append `index.html` to an alias file path, doubling it
 *  (`.../index.htmlindex.html`) → HTTP 500. `root` + a `location =
 *  /index.html` catch block serves the file via a clean internal
 *  redirect (live 500 fix, 2026-09-01).
 */
function renderWebVhost(config: ServerConfig, state: State): string {
  const root = SITE_ROOT(config.name);
  return `# viper: loopback web vhost — reached only via Xray Reality-fail fallback (dest).
# Managed by viper; do not edit by hand (re-rendered on deploy).
server {
    listen 127.0.0.1:${config.webPort} ssl http2;
    server_name ${config.domain};
    server_tokens off;

    ssl_certificate ${CERT_DIR(config.domain)}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR(config.domain)}/privkey.pem;

    location = / {
        root ${root};
    }
    location = /index.html {
        root ${root};
    }
    location = /login {
        alias ${root}/index.html;
    }
    location = /${state.subHash}/sub.txt {
        alias ${root}/sub.txt;
        default_type text/plain;
    }

    location / {
        return 404;
    }
}
`;
}

/** Render the two http vhost confs (pure function). */
export function renderNginx(config: ServerConfig, state: State): NginxConfs {
  return {
    "nginx-80.conf": renderPort80(config),
    "nginx-8443.conf": renderWebVhost(config, state),
  };
}