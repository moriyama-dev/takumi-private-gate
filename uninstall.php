<?php
/**
 * Removes all plugin options, including the per-IP lockout/attempt entries,
 * when the plugin is deleted from the Plugins screen.
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- prefix lookup across dynamically-named options has no options-API equivalent; runs once on uninstall.
$prvgate_option_names = $wpdb->get_col(
	$wpdb->prepare(
		"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( 'prvgate_lockout_ip_' ) . '%',
		$wpdb->esc_like( 'prvgate_attempts_ip_' ) . '%'
	)
);

foreach ( $prvgate_option_names as $prvgate_option_name ) {
	delete_option( $prvgate_option_name );
}

delete_option( 'prvgate_max_attempts' );
delete_option( 'prvgate_lockout_duration' );
delete_option( 'prvgate_show_lockout_message' );
delete_option( 'prvgate_email_notifications' );
delete_option( 'prvgate_ip_whitelist' );
delete_option( 'prvgate_db_version' );
delete_option( 'prvgate_version' );

wp_clear_scheduled_hook( 'prvgate_cleanup_expired' );

// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- dropping the plugin's own custom table on uninstall, no API equivalent.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}prvgate_login_log" );

// 2FA secrets/flags live in usermeta (shared across a multisite network by
// design), so they're removed separately rather than via the options loop.
delete_metadata( 'user', 0, 'prvgate_2fa_enabled', '', true );
delete_metadata( 'user', 0, '_prvgate_2fa_secret', '', true );
