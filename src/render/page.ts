/**
 * Faux SaaS login page (M2 — one fixed, generic, inert artifact).
 *
 * Served at `/` and `/login` on the 127.0.0.1:8443 loopback vhost, which
 * is reached only via Xray's Reality-fail fallback. The page is generic and
 * INERT: the form always fails with a generic "invalid credentials" — no
 * success path, no session, no accounts. Zero outbound network requests
 * (no CDNs, fonts, analytics or beacons); the hero image is the only
 * asset, inlined as a base64 data-URI. No JS framework, no build or
 * generator fingerprints, no comments.
 *
 * No knobs in v1 (plan: one fixed page, identical per server). The
 * renderer stays pure — the caller (CLI) reads the asset and injects its
 * base64 encoding here.
 */

/**
 * Stable marker that identifies the decoy page in a served response body.
 * Single source of truth: the M6 public-path verify step asserts its
 * presence (never a copy of the string in the step — M4 lesson: steps and
 * renderers must not drift).
 */
export const PAGE_MARKER = "Cloud Console — all rights reserved";

export function renderPage(heroBase64: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cloud Console — Sign in</title>
<style>
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f4f5f7;color:#1f2933}
.hero{width:100%;display:block}
.card{max-width:360px;margin:32px auto;background:#fff;border:1px solid #e4e7eb;border-radius:10px;padding:28px;box-shadow:0 1px 3px rgba(16,24,40,.08)}
h1{font-size:17px;margin:0 0 4px}
.sub{margin:0 0 22px;font-size:13px;color:#667085}
label{display:block;font-size:13px;font-weight:500;margin-bottom:6px}
input{width:100%;padding:9px 11px;margin-bottom:14px;border:1px solid #d0d5dd;border-radius:6px;font-size:14px}
button{width:100%;padding:10px;background:#2563eb;color:#fff;border:0;border-radius:6px;font-size:14px;cursor:pointer}
button:hover{background:#1d4ed8}
.error{display:none;margin-bottom:14px;padding:9px 11px;background:#fef3f2;border:1px solid #fecdca;border-radius:6px;color:#b42318;font-size:13px}
footer{margin:0 0 28px;text-align:center;font-size:12px;color:#98a2b3}
</style>
</head>
<body>
<img class="hero" src="data:image/webp;base64,${heroBase64}" alt="">
<div class="card">
<h1>Sign in to Cloud Console</h1>
<p class="sub">Access your team workspace</p>
<form id="login-form" action="#" method="post">
<div class="error" id="login-error">Invalid email or password. Please try again.</div>
<label for="email">Email</label>
<input id="email" name="email" type="email" autocomplete="username">
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
</div>
<footer>${PAGE_MARKER}</footer>
<script>
(function(){var f=document.getElementById("login-form");f.addEventListener("submit",function(e){e.preventDefault();document.getElementById("login-error").style.display="block";});})();
</script>
</body>
</html>
`;
}
