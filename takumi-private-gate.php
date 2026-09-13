<?php
/**
 * Plugin Name:       Takumi Private Gate
 * Plugin URI:        https://github.com/moriyama-dev/takumi-private-gate
 * Description:       Lock down your private WordPress site. Force login for all visitors, block REST API and XML-RPC, and lock out repeated failed login attempts.
 * Version:           1.2.3
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Yoshiro Moriyama (Takumi Web Services)
 * Author URI:        https://takumi.ca
 * License:           GPLv2 or later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       takumi-private-gate
 * Domain Path:       /languages
 */

defined( 'ABSPATH' ) || exit;

define( 'PRVGATE_VERSION', '1.2.3' );
define( 'PRVGATE_DB_VERSION', '1.1.0' );
define( 'PRVGATE_PLUGIN_FILE', __FILE__ );
define( 'PRVGATE_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'PRVGATE_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require_once PRVGATE_PLUGIN_DIR . 'includes/class-prvgate-ip-whitelist.php';
require_once PRVGATE_PLUGIN_DIR . 'includes/class-prvgate-access-control.php';
require_once PRVGATE_PLUGIN_DIR . 'includes/class-prvgate-api-blocker.php';
require_once PRVGATE_PLUGIN_DIR . 'includes/class-prvgate-login-logger.php';
require_once PRVGATE_PLUGIN_DIR . 'includes/class-prvgate-lockout.php';
require_once PRVGATE_PLUGIN_DIR . 'includes/class-prvgate-two-factor.php';
require_once PRVGATE_PLUGIN_DIR . 'includes/class-prvgate-admin.php';

/**
 * Sets default options on activation so the settings screen always has a value to render.
 */
function prvgate_activate_single_site() {
	add_option( 'prvgate_max_attempts', 5 );
	add_option( 'prvgate_lockout_duration', 30 );
	add_option( 'prvgate_show_lockout_message', false );
	add_option( 'prvgate_email_notifications', true );
	add_option( 'prvgate_ip_whitelist', '' );
	PrvGate_Login_Logger::create_table();
	update_option( 'prvgate_db_version', PRVGATE_DB_VERSION );
	prvgate_schedule_cleanup();
}

/**
 * Schedules the daily sweep that removes expired lockout and attempt rows.
 * Safe to call repeatedly; WP-Cron keeps a single scheduled event.
 */
function prvgate_schedule_cleanup() {
	if ( ! wp_next_scheduled( PrvGate_Lockout::CLEANUP_HOOK ) ) {
		wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', PrvGate_Lockout::CLEANUP_HOOK );
	}
}

function prvgate_unschedule_cleanup() {
	wp_clear_scheduled_hook( PrvGate_Lockout::CLEANUP_HOOK );
}

/**
 * On a multisite network activation WordPress does not loop over every site
 * for us — it calls this hook once with $network_wide = true and leaves
 * per-site setup to the plugin. Without this, every site would silently be
 * missing its login-log table (and defaults) until its first page load
 * triggers prvgate_maybe_upgrade_db() below.
 */
function prvgate_activate( $network_wide = false ) {
	if ( is_multisite() && $network_wide ) {
		foreach ( get_sites( array( 'fields' => 'ids' ) ) as $site_id ) {
			switch_to_blog( $site_id );
			prvgate_activate_single_site();
			restore_current_blog();
		}
		return;
	}
	prvgate_activate_single_site();
}
register_activation_hook( PRVGATE_PLUGIN_FILE, 'prvgate_activate' );

/**
 * Removes the scheduled cleanup event. Options, the login log and 2FA secrets
 * are deliberately left alone here -- deactivation is not uninstallation, and
 * uninstall.php handles the full teardown.
 */
function prvgate_deactivate( $network_wide = false ) {
	if ( is_multisite() && $network_wide ) {
		foreach ( get_sites( array( 'fields' => 'ids' ) ) as $site_id ) {
			switch_to_blog( $site_id );
			prvgate_unschedule_cleanup();
			restore_current_blog();
		}
		return;
	}
	prvgate_unschedule_cleanup();
}
register_deactivation_hook( PRVGATE_PLUGIN_FILE, 'prvgate_deactivate' );

/**
 * Runs the same per-site setup when a new site is created on a network
 * where the plugin is already network-activated.
 */
function prvgate_new_site_init( $new_site ) {
	if ( ! is_multisite() ) {
		return;
	}
	if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	if ( ! is_plugin_active_for_network( plugin_basename( PRVGATE_PLUGIN_FILE ) ) ) {
		return;
	}

	switch_to_blog( $new_site->blog_id );
	prvgate_activate_single_site();
	restore_current_blog();
}
add_action( 'wp_initialize_site', 'prvgate_new_site_init' );

/**
 * Brings an existing install up to date when the plugin is upgraded in place
 * (e.g. via the Plugins screen), which does not fire the activation hook.
 */
function prvgate_maybe_upgrade() {
	if ( get_option( 'prvgate_db_version' ) !== PRVGATE_DB_VERSION ) {
		PrvGate_Login_Logger::create_table();
		update_option( 'prvgate_db_version', PRVGATE_DB_VERSION );
	}

	if ( get_option( 'prvgate_version' ) !== PRVGATE_VERSION ) {
		// 1.2.3 introduced the daily cleanup event; installs upgrading from an
		// earlier version have never had it scheduled.
		prvgate_schedule_cleanup();
		update_option( 'prvgate_version', PRVGATE_VERSION );
	}
}
add_action( 'plugins_loaded', 'prvgate_maybe_upgrade' );

function prvgate_init() {
	PrvGate_Access_Control::init();
	PrvGate_Api_Blocker::init();
	PrvGate_Lockout::init();
	PrvGate_Two_Factor::init();
	PrvGate_Admin::init();
}
add_action( 'plugins_loaded', 'prvgate_init' );
