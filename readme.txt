=== Takumi Private Gate ===
Contributors: yoshiromoriyama
Donate link: https://takumi.ca
Tags: login, security, private, lockout, rest-api
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.2.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Lock down your private WordPress site. Force login for all visitors, block REST API and XML-RPC, and lock out repeated failed login attempts.

== Description ==

Takumi Private Gate turns a WordPress install into a fully private site: nothing is reachable without logging in first. It's built for people running a diary, notes site, or internal tool on WordPress that should never be publicly visible or crawlable.

Unlike most "force login" or "password protect" plugins, Takumi Private Gate combines four protections in a single, dependency-free plugin:

* **Site-wide lockdown**: every page, post, and feed redirects unauthenticated visitors to the standard WordPress login screen.
* **REST API blocking**: unauthenticated requests to `/wp-json/` receive a `401 Unauthorized` response.
* **XML-RPC turned off**: every XML-RPC method that requires authentication is refused, so `/xmlrpc.php` cannot be used to log in, post, or brute-force credentials.
* **Failed-login lockout**: an IP address is locked out for a configurable amount of time after too many failed login attempts, and by default the plugin says nothing that would tell an attacker they're locked out.

Developed and maintained by Yoshiro Moriyama, founder of Takumi Web Services, a WordPress development studio based in Toronto, Canada.

= Features =

* Redirects every unauthenticated front-end request to `wp-login.php`.
* Returns `401 Unauthorized` for unauthenticated REST API requests.
* Turns off XML-RPC by refusing every authenticated XML-RPC method (`xmlrpc_enabled`), which closes the login, publishing, and brute-force paths. WordPress still answers `/xmlrpc.php` for its own unauthenticated introspection methods such as `system.listMethods`; blocking the file outright is a job for the web server.
* Locks out an IP address after a configurable number of failed login attempts (default: 5 attempts / 30 minutes).
* Counts failed Application Password attempts (REST and XML-RPC) toward the same per-IP limit, and refuses Application Password authentication while an IP is locked out.
* Lockout state is stored per IP address, not per username.
* Lists every currently locked-out IP with a one-click unlock button.
* Keeps a rolling log (most recent 1000 attempts) of login attempts with date, IP, username, and result.
* Emails the site admin address whenever an IP gets locked out (can be turned off).
* IP whitelist (single IPs or CIDR ranges) that bypasses the lockdown, the API blocking, and the lockout entirely.
* Optional per-user TOTP two-factor authentication (compatible with Google Authenticator, Authy, 1Password, etc.) enrolled from each user's own profile screen.
* Network-activation aware: sets up per-site defaults and its login-log table on every site of a multisite network.
* Single settings screen under Settings > Private Gate.
* Uninstalling the plugin removes its options, its login-log table, and any 2FA secrets.

== Installation ==

1. Upload the `takumi-private-gate` folder to `/wp-content/plugins/`, or install it directly from the Plugins screen.
2. Activate the plugin through the "Plugins" screen in WordPress.
3. Go to Settings > Private Gate to adjust the failed-login threshold and lockout duration.

== Frequently Asked Questions ==

= Will this lock me out of my own site? =

Only if you fail to log in more times than the configured threshold (5 by default). `wp-login.php` itself is never blocked, since it's the only way to authenticate.

= Does this block search engines and RSS readers too? =

Yes. Since the entire site requires authentication, no unauthenticated client (including search engine crawlers and feed readers) can access any content.

= Why doesn't the login form say I'm locked out? =

By default, Takumi Private Gate intentionally shows a generic "incorrect username or password" message instead of revealing that the IP is locked out. This keeps an attacker running a brute-force attempt from learning that their requests are being blocked outright. This can be changed in Settings > Private Gate.

= Will I get emailed every time someone fails to log in? =

No. An email is only sent when an IP actually crosses the failed-attempt threshold and gets locked out, not on every failed attempt. This can be turned off in Settings > Private Gate.

= Does the login log grow forever? =

No. Only the most recent 1000 login attempts are kept; older entries are pruned automatically.

= Can I make sure I never get locked out? =

Yes. Add your own IP address (or a CIDR range covering it) to the whitelist in Settings > Private Gate. Whitelisted IPs bypass the site-wide lockdown, the REST API/XML-RPC blocking, and the failed-login lockout.

= How do I set up two-factor authentication? =

Go to your own Users > Profile screen, find the "Takumi Private Gate: Two-Factor Authentication (2FA)" section, add the displayed key to an authenticator app, enter the 6-digit code it shows, then click "Update Profile" at the bottom of the page. To turn 2FA off later, tick the box in that same section and click "Update Profile" again. No QR code is generated by the plugin, since that would mean sending your secret to a third-party image service; the manual-entry key works with every authenticator app.

= Does /xmlrpc.php still respond? =

The file still exists and WordPress still answers its unauthenticated introspection methods (for example `system.listMethods`), but every method that requires authentication is refused, so it cannot be used to log in, publish, or brute-force credentials. If you want the file itself to return 403 or 404, block it in your web server configuration -- a plugin runs too late in the request to do that.

= Does this work on a multisite network? =

Yes. If you network-activate the plugin, each site gets its own settings and login-log table, including sites created after activation. Two-factor authentication is tied to the user account and applies network-wide.

== Screenshots ==

1. Settings screen under Settings > Private Gate.

== Changelog ==

= 1.2.3 =
* Fixed: the "Enable 2FA" and "Disable 2FA" buttons on the profile screen never did anything. Their form was nested inside the profile form, which browsers discard, so the request was never sent. The controls are now part of the profile form itself and are applied with the "Update Profile" button.
* Fixed: failed Application Password attempts (REST and XML-RPC) were neither logged nor counted toward the lockout, because that code path does not run the `authenticate` filter. They now count like any other failed login, and Application Password authentication is refused while an IP is locked out.
* Fixed: per-IP lockout and attempt records stayed in `wp_options` forever. They now expire and a daily cleanup event removes them.
* Changed: failed attempts now expire after the configured lockout duration, so an old, isolated failure no longer contributes to a later lockout. Existing attempt counters reset once on upgrade; active lockouts are unaffected.
* Changed: corrected the XML-RPC description. The plugin refuses authenticated XML-RPC methods; it does not make `/xmlrpc.php` stop responding entirely.

= 1.2.2 =
* Removed bundled .po/.mo translation files; translations are now handled via translate.wordpress.org.

= 1.2.1 =
* Internationalized the plugin: source strings are now in English with a bundled Japanese (ja) translation.
* Unique-prefixed the admin asset handles to avoid conflicts with other plugins.

= 1.2.0 =
* Added an IP whitelist (single IPs or CIDR ranges) that bypasses the lockdown, API blocking, and lockout.
* Added optional per-user TOTP two-factor authentication, enrolled from the user's own profile screen.
* Added proper multisite network-activation support (per-site setup on activation and on new site creation).

= 1.1.0 =
* Added a list of currently locked-out IPs with a manual unlock button.
* Added a login attempt log (date, IP, username, result), capped at the most recent 1000 entries.
* Added an email notification to the site admin address when an IP is locked out.

= 1.0.0 =
* Initial release: site-wide lockdown, REST API blocking, XML-RPC disabling, and failed-login lockout.

== Upgrade Notice ==

= 1.2.3 =
Fixes two-factor authentication, which could not be switched on or off from the profile screen at all in earlier versions. Also closes an Application Password gap in the lockout and stops per-IP records accumulating in the database.

= 1.2.2 =
Bundled translation files have been removed for guideline compliance; translations are now provided through translate.wordpress.org.

= 1.2.1 =
Internationalization (English source strings plus a Japanese translation) and conflict-safe admin asset handles.

= 1.2.0 =
Adds an IP whitelist, optional TOTP two-factor authentication, and multisite network-activation support.

= 1.1.0 =
Adds a lockout list with manual unlock, a login attempt log, and email notifications on lockout.
