<?php
/**
 * Tracks failed login attempts per IP address and locks out an IP once it
 * crosses the configured threshold. Lockout state lives in wp_options
 * (no dedicated DB table) keyed by an md5 hash of the IP address; the raw
 * IP is kept in the option value so the admin screen can list it.
 */

defined( 'ABSPATH' ) || exit;

class PrvGate_Lockout {

	// Deliberately not "prvgate_lockout_" — that would collide with the
	// prvgate_lockout_duration setting when matched via a LIKE/prefix search.
	const LOCKOUT_OPTION_PREFIX  = 'prvgate_lockout_ip_';
	const ATTEMPTS_OPTION_PREFIX = 'prvgate_attempts_ip_';

	const CLEANUP_HOOK = 'prvgate_cleanup_expired';

	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'block_if_locked_out' ), 30, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'record_failed_attempt' ) );
		add_action( 'wp_login', array( __CLASS__, 'clear_attempts_on_success' ) );

		// Application Passwords never pass through the 'authenticate' filter --
		// wp_validate_application_password() calls
		// wp_authenticate_application_password() directly -- so without these
		// two hooks the REST/XML-RPC app-password path bypasses both the
		// lockout and the login log entirely.
		add_filter( 'application_password_is_api_request', array( __CLASS__, 'block_app_password_if_locked_out' ) );
		add_action( 'application_password_failed_authentication', array( __CLASS__, 'record_failed_app_password_attempt' ) );

		add_action( self::CLEANUP_HOOK, array( __CLASS__, 'cleanup_expired' ) );
	}

	private static function get_client_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	private static function get_lockout( $ip ) {
		return get_option( self::LOCKOUT_OPTION_PREFIX . md5( $ip ) );
	}

	private static function is_locked_out( $ip ) {
		$lockout = self::get_lockout( $ip );
		return $lockout && isset( $lockout['until'] ) && $lockout['until'] > time();
	}

	/**
	 * How long a run of failed attempts stays "hot". Attempts older than this
	 * no longer count toward the threshold, which both matches how people
	 * expect a lockout to behave and gives the stored counter an expiry.
	 */
	private static function get_attempt_window() {
		$minutes = max( 1, (int) get_option( 'prvgate_lockout_duration', 30 ) );
		return $minutes * MINUTE_IN_SECONDS;
	}

	/**
	 * Reads the attempt counter for an IP, treating an expired counter (and a
	 * pre-1.2.3 counter, which carries no expiry) as a fresh start.
	 */
	private static function get_attempts( $ip ) {
		$attempts = get_option( self::ATTEMPTS_OPTION_PREFIX . md5( $ip ) );

		if ( ! is_array( $attempts ) || ! isset( $attempts['expires'] ) || (int) $attempts['expires'] <= time() ) {
			return array(
				'ip'    => $ip,
				'count' => 0,
			);
		}

		$attempts['count'] = isset( $attempts['count'] ) ? (int) $attempts['count'] : 0;
		return $attempts;
	}

	public static function block_if_locked_out( $user, $username, $password ) {
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$ip = self::get_client_ip();
		if ( '' === $ip || PrvGate_Ip_Whitelist::is_whitelisted( $ip ) ) {
			return $user;
		}

		$lockout = self::get_lockout( $ip );
		if ( ! $lockout || ! isset( $lockout['until'] ) || $lockout['until'] <= time() ) {
			return $user;
		}

		if ( get_option( 'prvgate_show_lockout_message', false ) ) {
			$minutes_left = (int) ceil( ( $lockout['until'] - time() ) / MINUTE_IN_SECONDS );
			return new WP_Error(
				'prvgate_too_many_attempts',
				sprintf(
					/* translators: %d: minutes remaining until the IP is unlocked. */
					__( 'Too many failed login attempts. Please try again in %d minutes.', 'takumi-private-gate' ),
					$minutes_left
				)
			);
		}

		// Default: mimic a normal invalid-credentials error so an attacker
		// can't distinguish a lockout from a wrong password.
		return new WP_Error(
			'prvgate_too_many_attempts',
			__( '<strong>Error</strong>: The username or password is incorrect.', 'takumi-private-gate' )
		);
	}

	/**
	 * Fires on every failed login (including attempts made while already
	 * locked out, since wp_signon() calls wp_login_failed whenever the
	 * authenticate chain resolves to a WP_Error, regardless of which
	 * filter produced it).
	 */
	public static function record_failed_attempt( $username ) {
		$ip = self::get_client_ip();
		if ( '' === $ip || PrvGate_Ip_Whitelist::is_whitelisted( $ip ) ) {
			return;
		}

		$username = sanitize_text_field( $username );

		if ( self::is_locked_out( $ip ) ) {
			PrvGate_Login_Logger::log( $ip, $username, 'lockout' );
			return;
		}

		$attempts_key = self::ATTEMPTS_OPTION_PREFIX . md5( $ip );
		$attempts     = self::get_attempts( $ip );

		$attempts['ip']      = $ip;
		$attempts['count']   = (int) $attempts['count'] + 1;
		$attempts['expires'] = time() + self::get_attempt_window();

		$max_attempts = max( 1, (int) get_option( 'prvgate_max_attempts', 5 ) );

		if ( $attempts['count'] >= $max_attempts ) {
			$lockout_minutes = max( 1, (int) get_option( 'prvgate_lockout_duration', 30 ) );
			$until           = time() + ( $lockout_minutes * MINUTE_IN_SECONDS );

			update_option(
				self::LOCKOUT_OPTION_PREFIX . md5( $ip ),
				array( 'ip' => $ip, 'until' => $until ),
				false
			);
			delete_option( $attempts_key );

			PrvGate_Login_Logger::log( $ip, $username, 'lockout' );
			self::maybe_send_lockout_email( $ip, $until );
			return;
		}

		update_option( $attempts_key, $attempts, false );
		PrvGate_Login_Logger::log( $ip, $username, 'failure' );
	}

	public static function clear_attempts_on_success( $user_login ) {
		$ip = self::get_client_ip();
		if ( '' === $ip ) {
			return;
		}
		delete_option( self::ATTEMPTS_OPTION_PREFIX . md5( $ip ) );
		PrvGate_Login_Logger::log( $ip, sanitize_text_field( $user_login ), 'success' );
	}

	/* ---------------------------------------------------------------------
	 * Application Passwords
	 * ------------------------------------------------------------------- */

	/**
	 * Stops Application Password authentication while the IP is locked out.
	 *
	 * Returning false here makes wp_authenticate_application_password() bail
	 * before it compares any credentials, which is the earliest point the
	 * plugin can intervene without affecting the Application Passwords admin
	 * UI. The request simply continues unauthenticated, and the REST blocker
	 * answers it with the usual 401.
	 *
	 * @param bool $is_api_request Whether app passwords may be used here.
	 * @return bool
	 */
	public static function block_app_password_if_locked_out( $is_api_request ) {
		if ( ! $is_api_request ) {
			return $is_api_request;
		}

		$ip = self::get_client_ip();
		if ( '' === $ip || PrvGate_Ip_Whitelist::is_whitelisted( $ip ) ) {
			return $is_api_request;
		}

		return self::is_locked_out( $ip ) ? false : $is_api_request;
	}

	/**
	 * Counts a rejected Application Password against the same per-IP budget as
	 * a rejected wp-login.php submission.
	 *
	 * Core passes the WP_Error only, so the attempted login name is read from
	 * the HTTP Basic credentials that core itself used.
	 *
	 * @param WP_Error $error The authentication error from core.
	 */
	public static function record_failed_app_password_attempt( $error ) {
		unset( $error );

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- HTTP Basic credentials on an API request; there is no nonce to check.
		$username = isset( $_SERVER['PHP_AUTH_USER'] ) ? sanitize_text_field( wp_unslash( $_SERVER['PHP_AUTH_USER'] ) ) : '';

		self::record_failed_attempt( $username );
	}

	/* ---------------------------------------------------------------------
	 * Housekeeping
	 * ------------------------------------------------------------------- */

	/**
	 * Deletes lockout and attempt rows that have passed their expiry.
	 *
	 * Both are stored as individual options keyed by a hash of the IP, so a
	 * spread-out credential-stuffing run would otherwise leave one row per
	 * source address in wp_options forever. Runs daily via WP-Cron.
	 */
	public static function cleanup_expired() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- prefix lookup across dynamically-named options has no options-API equivalent.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
				$wpdb->esc_like( self::LOCKOUT_OPTION_PREFIX ) . '%',
				$wpdb->esc_like( self::ATTEMPTS_OPTION_PREFIX ) . '%'
			)
		);

		$now     = time();
		$deleted = 0;

		foreach ( $rows as $row ) {
			$value = maybe_unserialize( $row->option_value );

			if ( ! is_array( $value ) ) {
				delete_option( $row->option_name );
				++$deleted;
				continue;
			}

			// Lockouts carry 'until'; attempt counters carry 'expires'. A row
			// with neither predates 1.2.3 and is no longer meaningful.
			$expiry = 0;
			if ( isset( $value['until'] ) ) {
				$expiry = (int) $value['until'];
			} elseif ( isset( $value['expires'] ) ) {
				$expiry = (int) $value['expires'];
			}

			if ( $expiry <= $now ) {
				delete_option( $row->option_name );
				++$deleted;
			}
		}

		return $deleted;
	}

	private static function maybe_send_lockout_email( $ip, $until ) {
		if ( ! get_option( 'prvgate_email_notifications', true ) ) {
			return;
		}

		$to = get_option( 'admin_email' );
		if ( ! $to ) {
			return;
		}

		$subject = sprintf(
			/* translators: %s: site name. */
			__( '[%s] An IP address has been locked out', 'takumi-private-gate' ),
			wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
		);

		$body = sprintf(
			/* translators: 1: IP address, 2: lockout expiry date/time. */
			__( "The IP address %1\$s exceeded the failed login limit and has been locked out until %2\$s.", 'takumi-private-gate' ),
			$ip,
			wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $until )
		);

		wp_mail( $to, $subject, $body );
	}

	/**
	 * Returns every currently active lockout as an array of
	 * [ 'option_name' => string, 'ip' => string, 'until' => int ].
	 */
	public static function get_active_lockouts() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- prefix LOOKUP across dynamically-named options has no options-API equivalent.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
				$wpdb->esc_like( self::LOCKOUT_OPTION_PREFIX ) . '%'
			)
		);

		$lockouts = array();
		$now      = time();

		foreach ( $rows as $row ) {
			$value = maybe_unserialize( $row->option_value );
			if ( ! is_array( $value ) || ! isset( $value['until'] ) || $value['until'] <= $now ) {
				continue;
			}
			$lockouts[] = array(
				'option_name' => $row->option_name,
				'ip'          => isset( $value['ip'] ) ? $value['ip'] : __( '(unknown)', 'takumi-private-gate' ),
				'until'       => (int) $value['until'],
			);
		}

		return $lockouts;
	}

	/**
	 * Deletes a lockout option after validating it actually matches our
	 * naming pattern, so a crafted request can't be used to delete an
	 * arbitrary option.
	 */
	public static function unlock_by_option_name( $option_name ) {
		if ( ! preg_match( '/^' . self::LOCKOUT_OPTION_PREFIX . '[a-f0-9]{32}$/', $option_name ) ) {
			return false;
		}
		return delete_option( $option_name );
	}
}
