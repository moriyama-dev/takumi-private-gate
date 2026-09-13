# Takumi Private Gate

**Turn a WordPress install into a fully private site — nothing is reachable without logging in first.**

Built for diaries, internal tools, staging sites and client notes sites that should never be publicly visible or crawlable. Zero dependencies, one admin screen, multisite aware.

![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4?style=flat&logo=php&logoColor=white)
![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-21759B?style=flat&logo=wordpress&logoColor=white)
![License](https://img.shields.io/badge/License-GPLv2-blue?style=flat)
![Version](https://img.shields.io/badge/version-1.2.4-green?style=flat)

Published on WordPress.org: <https://wordpress.org/plugins/takumi-private-gate/>

---

## Why this exists

Most "force login" plugins close the front door and leave the windows open — the REST API still answers, `xmlrpc.php` still accepts authenticated calls, and brute-force attempts run unthrottled. Takumi Private Gate closes all four surfaces in one plugin, without pulling in a security suite.

| Surface | Behaviour |
|---|---|
| Front end | Every page, post and feed redirects unauthenticated visitors to `wp-login.php` |
| REST API | Unauthenticated requests to `/wp-json/` return `401 Unauthorized` |
| XML-RPC | Authenticated XML-RPC methods are refused via `xmlrpc_enabled`. `/xmlrpc.php` still responds — it is not taken offline |
| Login form | IP locked out after N failed attempts (default 5 / 30 min), Application Passwords included |

## Features

- **Site-wide lockdown** — no content, feeds or crawlers get through without a session.
- **Per-IP lockout**, not per-username — so credential stuffing across many usernames still trips it.
- **Silent by default** — a locked-out attacker sees the generic "incorrect username or password" message, not confirmation that their IP is blocked. Configurable.
- **Login log** — rolling 1000-entry log of date, IP, username and result, with auto-pruning.
- **Lockout list** with one-click manual unlock.
- **Email alert** to the admin address when an IP crosses the threshold (not on every failed attempt).
- **IP whitelist** — single IPs or CIDR ranges bypass lockdown, API blocking and lockout, so you can't lock yourself out.
- **Optional TOTP 2FA**, enrolled per user from their own profile screen. Works with Google Authenticator, Authy, 1Password. No QR code is generated on purpose — that would mean sending the shared secret to a third-party image service; manual-entry keys and an `otpauth://` URI work everywhere.
- **Multisite network-activation aware** — per-site defaults and login-log table on every site, including sites created later.
- **Clean uninstall** — removes its options, its log table and any 2FA secrets.

## Architecture

Each concern is one class, loaded from `includes/`:

```
takumi-private-gate.php          Bootstrap, activation/deactivation, multisite setup
includes/
  class-prvgate-access-control.php  Front-end lockdown & redirects
  class-prvgate-api-blocker.php     REST API 401 + XML-RPC refusal
  class-prvgate-lockout.php         Failed-attempt counting, lockout state, unlock
  class-prvgate-login-logger.php    Rolling login-attempt log + pruning
  class-prvgate-ip-whitelist.php    Single-IP and CIDR matching
  class-prvgate-two-factor.php      TOTP enrolment and verification
  class-prvgate-admin.php           Admin screen, settings registration
admin/views/                     Settings and lockout-log templates
bin/deploy.sh                    Copy the tree into a local WordPress install
uninstall.php                    Full teardown
```

All input is sanitised, all output escaped, and every admin action is capability- and nonce-checked.

## Installation

1. Install from the Plugins screen, or upload the `takumi-private-gate` folder to `/wp-content/plugins/`.
2. Activate via **Plugins › Installed Plugins**.
3. Configure at **Private Gate** in the admin sidebar.

Add your own IP to the whitelist first if you are working from a fixed address.

## FAQ

**Will this lock me out of my own site?** Only if you exceed the failed-attempt threshold. `wp-login.php` is never blocked — it's the only way to authenticate. Whitelist your IP to be certain.

**Does it block search engines and RSS readers?** Yes. That is the point: no unauthenticated client reaches any content.

**Does the log grow forever?** No — only the most recent 1000 attempts are kept, and per-IP lockout records expire rather than accumulating.

**Multisite?** Network-activate it and each site gets its own settings and log table. 2FA is tied to the user account and applies network-wide.

## Changelog

**1.2.4** — Own item in the admin sidebar instead of an entry under Settings; unlock redirect follows the screen.
**1.2.3** — 2FA could not be switched on or off from the profile screen; Application Password attempts now count toward the lockout; per-IP records expire.
**1.2.2** — Removed bundled translation files; translation moved to translate.wordpress.org.
**1.2.1** — Internationalised the source strings and prefixed the admin asset handles.
**1.2.0** — IP whitelist (single/CIDR), optional per-user TOTP 2FA, multisite network-activation support.
**1.1.0** — Lockout list with manual unlock, login attempt log, email notification on lockout.
**1.0.0** — Initial release: lockdown, REST API blocking, XML-RPC refusal, failed-login lockout.

## License

GPLv2 or later. Developed and maintained by [Yoshiro Moriyama](https://github.com/moriyama-dev), founder of [Takumi Web Services](https://www.takumi.ca) — a WordPress development studio in Toronto, Canada.
