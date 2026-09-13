<?php
/**
 * Registers the plugin's single settings screen under Settings > Private Gate.
 */

defined( 'ABSPATH' ) || exit;

class PrvGate_Admin {

	const OPTION_GROUP = 'prvgate_settings_group';
	const PAGE_SLUG     = 'takumi-private-gate';

	private static $settings_page_hook = '';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'add_settings_page' ) );
		add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_assets' ) );
		add_action( 'admin_post_prvgate_unlock_ip', array( __CLASS__, 'handle_unlock_ip' ) );
		add_action( 'admin_notices', array( __CLASS__, 'render_unlock_notice' ) );
	}

	public static function add_settings_page() {
		self::$settings_page_hook = add_options_page(
			__( 'Private Gate', 'takumi-private-gate' ),
			__( 'Private Gate', 'takumi-private-gate' ),
			'manage_options',
			self::PAGE_SLUG,
			array( __CLASS__, 'render_settings_page' )
		);
	}

	public static function enqueue_assets( $hook_suffix ) {
		if ( $hook_suffix !== self::$settings_page_hook ) {
			return;
		}

		wp_enqueue_style(
			'prvgate-admin',
			PRVGATE_PLUGIN_URL . 'admin/css/takumi-private-gate-admin.css',
			array(),
			PRVGATE_VERSION
		);

		wp_enqueue_script(
			'prvgate-admin',
			PRVGATE_PLUGIN_URL . 'admin/js/takumi-private-gate-admin.js',
			array(),
			PRVGATE_VERSION,
			true
		);
	}

	public static function register_settings() {
		register_setting( self::OPTION_GROUP, 'prvgate_max_attempts', array(
			'type'              => 'integer',
			'sanitize_callback' => array( __CLASS__, 'sanitize_max_attempts' ),
			'default'           => 5,
		) );

		register_setting( self::OPTION_GROUP, 'prvgate_lockout_duration', array(
			'type'              => 'integer',
			'sanitize_callback' => array( __CLASS__, 'sanitize_lockout_duration' ),
			'default'           => 30,
		) );

		register_setting( self::OPTION_GROUP, 'prvgate_show_lockout_message', array(
			'type'              => 'boolean',
			'sanitize_callback' => array( __CLASS__, 'sanitize_checkbox' ),
			'default'           => false,
		) );

		add_settings_section(
			'prvgate_main_section',
			__( 'Lockout Settings', 'takumi-private-gate' ),
			'__return_false',
			self::PAGE_SLUG
		);

		add_settings_field(
			'prvgate_max_attempts',
			__( 'Allowed failed login attempts', 'takumi-private-gate' ),
			array( __CLASS__, 'render_max_attempts_field' ),
			self::PAGE_SLUG,
			'prvgate_main_section'
		);

		add_settings_field(
			'prvgate_lockout_duration',
			__( 'Lockout duration (minutes)', 'takumi-private-gate' ),
			array( __CLASS__, 'render_lockout_duration_field' ),
			self::PAGE_SLUG,
			'prvgate_main_section'
		);

		add_settings_field(
			'prvgate_show_lockout_message',
			__( 'Show lockout message', 'takumi-private-gate' ),
			array( __CLASS__, 'render_show_lockout_message_field' ),
			self::PAGE_SLUG,
			'prvgate_main_section'
		);

		register_setting( self::OPTION_GROUP, 'prvgate_email_notifications', array(
			'type'              => 'boolean',
			'sanitize_callback' => array( __CLASS__, 'sanitize_checkbox' ),
			'default'           => true,
		) );

		add_settings_field(
			'prvgate_email_notifications',
			__( 'Email notification on lockout', 'takumi-private-gate' ),
			array( __CLASS__, 'render_email_notifications_field' ),
			self::PAGE_SLUG,
			'prvgate_main_section'
		);

		register_setting( self::OPTION_GROUP, 'prvgate_ip_whitelist', array(
			'type'              => 'string',
			'sanitize_callback' => array( __CLASS__, 'sanitize_ip_whitelist' ),
			'default'           => '',
		) );

		add_settings_section(
			'prvgate_whitelist_section',
			__( 'IP Whitelist', 'takumi-private-gate' ),
			array( __CLASS__, 'render_whitelist_section_intro' ),
			self::PAGE_SLUG
		);

		add_settings_field(
			'prvgate_ip_whitelist',
			__( 'Allowed IP / CIDR', 'takumi-private-gate' ),
			array( __CLASS__, 'render_ip_whitelist_field' ),
			self::PAGE_SLUG,
			'prvgate_whitelist_section'
		);
	}

	public static function render_whitelist_section_intro() {
		echo '<p>' . esc_html__( 'IP addresses listed here are excluded from the site-wide lockdown, REST API / XML-RPC blocking, and failed-login lockout. Enter one entry per line: a single IP (e.g. 203.0.113.10) or a CIDR range (e.g. 203.0.113.0/24).', 'takumi-private-gate' ) . '</p>';
	}

	public static function sanitize_max_attempts( $value ) {
		return max( 1, absint( $value ) );
	}

	public static function sanitize_lockout_duration( $value ) {
		return max( 1, absint( $value ) );
	}

	public static function sanitize_checkbox( $value ) {
		// wp_validate_boolean() normalises the string "false" (and "0") to false,
		// unlike a plain (bool) cast which treats any non-empty string as true.
		return wp_validate_boolean( $value );
	}

	/**
	 * Keeps only lines that look like a valid single IP or CIDR range, so a
	 * typo can't silently create a rule that never matches (or, worse, one
	 * that behaves unpredictably).
	 */
	public static function sanitize_ip_whitelist( $value ) {
		$lines = preg_split( '/\r\n|\r|\n/', (string) $value );
		$clean = array();

		foreach ( $lines as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}

			list( $address, $bits ) = array_pad( explode( '/', $line, 2 ), 2, null );

			if ( false === filter_var( $address, FILTER_VALIDATE_IP ) ) {
				continue;
			}
			if ( null !== $bits ) {
				// Reject prefixes wider than the address family allows: /0-/32 for
				// IPv4, /0-/128 for IPv6. ctype_digit also rejects "" and negatives.
				if ( ! ctype_digit( (string) $bits ) ) {
					continue;
				}
				$max_bits = filter_var( $address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? 128 : 32;
				if ( (int) $bits > $max_bits ) {
					continue;
				}
			}

			$clean[] = $line;
		}

		return implode( "\n", $clean );
	}

	public static function render_max_attempts_field() {
		printf(
			'<input type="number" min="1" step="1" name="prvgate_max_attempts" value="%s" class="small-text" />',
			esc_attr( get_option( 'prvgate_max_attempts', 5 ) )
		);
	}

	public static function render_lockout_duration_field() {
		printf(
			'<input type="number" min="1" step="1" name="prvgate_lockout_duration" value="%s" class="small-text" /> %s',
			esc_attr( get_option( 'prvgate_lockout_duration', 30 ) ),
			esc_html__( 'minutes', 'takumi-private-gate' )
		);
	}

	public static function render_show_lockout_message_field() {
		printf(
			'<label><input type="checkbox" name="prvgate_show_lockout_message" value="1" %s /> %s</label>',
			checked( (bool) get_option( 'prvgate_show_lockout_message', false ), true, false ),
			esc_html__( 'Show on the login form that the IP is locked out (hidden by default)', 'takumi-private-gate' )
		);
	}

	public static function render_email_notifications_field() {
		printf(
			'<label><input type="checkbox" name="prvgate_email_notifications" value="1" %s /> %s</label>',
			checked( (bool) get_option( 'prvgate_email_notifications', true ), true, false ),
			esc_html__( 'Notify the admin address (from General Settings) when a lockout occurs', 'takumi-private-gate' )
		);
	}

	public static function render_ip_whitelist_field() {
		printf(
			'<textarea name="prvgate_ip_whitelist" rows="5" cols="40" class="large-text code" placeholder="203.0.113.10&#10;203.0.113.0/24">%s</textarea>',
			esc_textarea( get_option( 'prvgate_ip_whitelist', '' ) )
		);
	}

	public static function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		require PRVGATE_PLUGIN_DIR . 'admin/views/settings.php';
		require PRVGATE_PLUGIN_DIR . 'admin/views/lockout-log.php';
	}

	/**
	 * Handles the "unlock" button submitted from the lockout list. Validates
	 * capability, nonce, and the option-name shape before deleting anything.
	 */
	public static function handle_unlock_ip() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'takumi-private-gate' ) );
		}

		$option_name = isset( $_POST['prvgate_option_name'] ) ? sanitize_text_field( wp_unslash( $_POST['prvgate_option_name'] ) ) : '';

		check_admin_referer( 'prvgate_unlock_ip_' . $option_name, 'prvgate_unlock_nonce' );

		$unlocked = PrvGate_Lockout::unlock_by_option_name( $option_name );

		$redirect_url = add_query_arg(
			'prvgate_unlocked',
			$unlocked ? '1' : '0',
			admin_url( 'options-general.php?page=' . self::PAGE_SLUG )
		);

		wp_safe_redirect( $redirect_url );
		exit;
	}

	public static function render_unlock_notice() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice display after wp_safe_redirect, no state change.
		if ( ! isset( $_GET['page'] ) || self::PAGE_SLUG !== $_GET['page'] || ! isset( $_GET['prvgate_unlocked'] ) ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice display after wp_safe_redirect, no state change.
		if ( '1' === $_GET['prvgate_unlocked'] ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'The IP address has been unlocked.', 'takumi-private-gate' ) . '</p></div>';
		} else {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Failed to unlock the IP address.', 'takumi-private-gate' ) . '</p></div>';
		}
	}
}
