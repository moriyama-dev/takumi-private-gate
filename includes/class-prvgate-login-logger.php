<?php
/**
 * Stores a rolling log of login attempts (success / failure / lockout) in
 * a dedicated table, so the admin screen can show recent activity.
 */

defined( 'ABSPATH' ) || exit;

class PrvGate_Login_Logger {

	const MAX_LOG_ENTRIES = 1000;

	public static function table_name() {
		global $wpdb;
		return $wpdb->prefix . 'prvgate_login_log';
	}

	public static function create_table() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table_name      = self::table_name();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
			ip_address VARCHAR(45) NOT NULL,
			username VARCHAR(200) NOT NULL DEFAULT '',
			result VARCHAR(10) NOT NULL,
			attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY  (id),
			KEY ip_address (ip_address),
			KEY attempted_at (attempted_at)
		) {$charset_collate};";

		dbDelta( $sql );
	}

	public static function log( $ip, $username, $result ) {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- custom table has no caching API equivalent for inserts.
		$wpdb->insert(
			self::table_name(),
			array(
				'ip_address'   => $ip,
				'username'     => $username,
				'result'       => $result,
				'attempted_at' => current_time( 'mysql' ),
			),
			array( '%s', '%s', '%s', '%s' )
		);

		self::prune();
	}

	private static function prune() {
		global $wpdb;

		$table = self::table_name();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- custom table row count, not cacheable/user-facing, $table is not user input.
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" );

		if ( $count <= self::MAX_LOG_ENTRIES ) {
			return;
		}

		$excess = $count - self::MAX_LOG_ENTRIES;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- custom table prune, $table is not user input.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} ORDER BY id ASC LIMIT %d", $excess ) );
	}

	/**
	 * Returns the most recent log entries, newest first.
	 */
	public static function get_recent_entries( $limit = 100 ) {
		global $wpdb;

		$table = self::table_name();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- custom table, admin-only read.
		return $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $table is not user input.
				"SELECT ip_address, username, result, attempted_at FROM {$table} ORDER BY id DESC LIMIT %d",
				$limit
			)
		);
	}
}
