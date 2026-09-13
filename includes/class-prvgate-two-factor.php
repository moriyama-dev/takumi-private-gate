<?php
/**
 * Optional per-user TOTP (RFC 6238) two-factor authentication. Each user
 * enrolls their own account from their profile screen; no QR image is
 * generated locally or fetched from a third party, since that would mean
 * sending the secret to an external service. Users add the account to an
 * authenticator app (Google Authenticator, Authy, 1Password, etc.) by typing
 * in the "manual entry" secret shown on screen.
 */

defined( 'ABSPATH' ) || exit;

class PrvGate_Two_Factor {

	const SECRET_META_KEY  = '_prvgate_2fa_secret';
	const ENABLED_META_KEY = 'prvgate_2fa_enabled';

	const NOTICE_TRANSIENT_PREFIX = 'prvgate_2fa_notice_';

	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'verify_code_on_login' ), 40, 3 );
		add_action( 'login_form', array( __CLASS__, 'render_login_code_field' ) );

		add_action( 'show_user_profile', array( __CLASS__, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'render_profile_section' ) );

		// The 2FA controls live inside core's own profile <form>, so they are
		// saved by core's "Update Profile" button rather than by a form of
		// their own. A nested <form> is discarded by the HTML parser, which is
		// why the previous admin-post.php submission never ran.
		add_action( 'personal_options_update', array( __CLASS__, 'handle_profile_update' ) );
		add_action( 'edit_user_profile_update', array( __CLASS__, 'handle_profile_update' ) );

		add_action( 'admin_notices', array( __CLASS__, 'render_notice' ) );
	}

	public static function is_enabled( $user_id ) {
		return (bool) get_user_meta( $user_id, self::ENABLED_META_KEY, true );
	}

	/* ---------------------------------------------------------------------
	 * Login-time enforcement
	 * ------------------------------------------------------------------- */

	public static function render_login_code_field() {
		?>
		<p>
			<label for="prvgate_2fa_code"><?php esc_html_e( 'Authenticator code (only if you have 2FA enabled)', 'takumi-private-gate' ); ?></label>
			<input type="text" name="prvgate_2fa_code" id="prvgate_2fa_code" class="input" inputmode="numeric" autocomplete="one-time-code" maxlength="6" />
		</p>
		<?php
	}

	public static function verify_code_on_login( $user, $username, $password ) {
		if ( empty( $username ) || empty( $password ) ) {
			return $user;
		}
		if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) ) {
			return $user;
		}
		if ( ! self::is_enabled( $user->ID ) ) {
			return $user;
		}

		$secret = get_user_meta( $user->ID, self::SECRET_META_KEY, true );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- core wp_authenticate login form has no nonce field to check here.
		$code = isset( $_POST['prvgate_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['prvgate_2fa_code'] ) ) : '';

		if ( '' === $secret || ! self::verify_totp( $secret, $code ) ) {
			return new WP_Error(
				'prvgate_2fa_failed',
				__( '<strong>Error</strong>: The authenticator code is incorrect.', 'takumi-private-gate' )
			);
		}

		return $user;
	}

	/* ---------------------------------------------------------------------
	 * Profile screen: enroll / disable
	 * ------------------------------------------------------------------- */

	public static function render_profile_section( $profile_user ) {
		$is_own_profile = ( get_current_user_id() === (int) $profile_user->ID );
		if ( ! $is_own_profile && ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$enabled = self::is_enabled( $profile_user->ID );
		?>
		<h2><?php esc_html_e( 'Takumi Private Gate: Two-Factor Authentication (2FA)', 'takumi-private-gate' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Status', 'takumi-private-gate' ); ?></th>
				<td>
					<?php wp_nonce_field( 'prvgate_2fa_profile_' . $profile_user->ID, 'prvgate_2fa_nonce' ); ?>
					<?php if ( $enabled ) : ?>
						<p><strong><?php esc_html_e( 'Enabled', 'takumi-private-gate' ); ?></strong></p>
						<p>
							<label for="prvgate_2fa_disable">
								<input type="checkbox" name="prvgate_2fa_disable" id="prvgate_2fa_disable" value="1" />
								<?php esc_html_e( 'Turn off two-factor authentication for this account', 'takumi-private-gate' ); ?>
							</label>
						</p>
						<p class="description"><?php esc_html_e( 'Tick the box above, then click "Update Profile" at the bottom of this page. The stored key is deleted, so re-enabling later means enrolling again.', 'takumi-private-gate' ); ?></p>
					<?php elseif ( $is_own_profile ) : ?>
						<?php
						$secret = get_user_meta( $profile_user->ID, self::SECRET_META_KEY, true );
						if ( '' === $secret ) {
							$secret = self::generate_secret();
							update_user_meta( $profile_user->ID, self::SECRET_META_KEY, $secret );
						}
						$otpauth_uri = self::get_otpauth_uri( $secret, $profile_user->user_login );
						?>
						<p><?php esc_html_e( 'Not enabled yet. Add the key below manually to an authenticator app (such as Google Authenticator, Authy, or 1Password), then enter the 6-digit code it shows to activate.', 'takumi-private-gate' ); ?></p>
						<p><code style="font-size:1.1em;"><?php echo esc_html( self::format_secret_for_display( $secret ) ); ?></code></p>
						<p><small><?php esc_html_e( 'Setup URI (to paste directly into a compatible app):', 'takumi-private-gate' ); ?> <code><?php echo esc_html( $otpauth_uri ); ?></code></small></p>
						<p>
							<label for="prvgate_2fa_confirm_code"><?php esc_html_e( 'Confirmation code:', 'takumi-private-gate' ); ?></label>
							<input type="text" name="prvgate_2fa_confirm_code" id="prvgate_2fa_confirm_code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" class="small-text" />
						</p>
						<p class="description"><?php esc_html_e( 'Enter the 6-digit code, then click "Update Profile" at the bottom of this page to activate.', 'takumi-private-gate' ); ?></p>
					<?php else : ?>
						<p><?php esc_html_e( 'Disabled', 'takumi-private-gate' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Applies the 2FA section of the profile screen. Runs from
	 * personal_options_update / edit_user_profile_update, i.e. inside core's
	 * own "Update Profile" submission, which core has already nonce-checked
	 * with update-user_{id}; the plugin's own nonce is verified here as well.
	 */
	public static function handle_profile_update( $user_id ) {
		$user_id = (int) $user_id;
		if ( ! $user_id ) {
			return;
		}

		// Absent when another plugin (or a programmatic call) triggers the
		// hook without our section having been rendered.
		if ( ! isset( $_POST['prvgate_2fa_nonce'] ) ) {
			return;
		}

		$nonce = sanitize_text_field( wp_unslash( $_POST['prvgate_2fa_nonce'] ) );
		if ( ! wp_verify_nonce( $nonce, 'prvgate_2fa_profile_' . $user_id ) ) {
			return;
		}

		$is_own_profile = ( get_current_user_id() === $user_id );
		if ( ! $is_own_profile && ! current_user_can( 'edit_user', $user_id ) ) {
			return;
		}

		if ( ! empty( $_POST['prvgate_2fa_disable'] ) ) {
			delete_user_meta( $user_id, self::ENABLED_META_KEY );
			delete_user_meta( $user_id, self::SECRET_META_KEY );
			self::set_notice( 'disabled' );
			return;
		}

		// Enrolment only ever happens on the user's own profile, because the
		// secret is generated (and shown) only there.
		if ( ! $is_own_profile || self::is_enabled( $user_id ) ) {
			return;
		}

		$code = isset( $_POST['prvgate_2fa_confirm_code'] ) ? sanitize_text_field( wp_unslash( $_POST['prvgate_2fa_confirm_code'] ) ) : '';
		if ( '' === $code ) {
			return;
		}

		$secret = get_user_meta( $user_id, self::SECRET_META_KEY, true );
		if ( '' !== $secret && self::verify_totp( $secret, $code ) ) {
			update_user_meta( $user_id, self::ENABLED_META_KEY, true );
			self::set_notice( 'enabled' );
			return;
		}

		self::set_notice( 'enable_failed' );
	}

	/**
	 * Queues a one-shot notice for the user performing the change. Core
	 * redirects to ?updated=true after saving a profile, so the outcome has
	 * to survive one request without adding a query argument of our own.
	 */
	private static function set_notice( $status ) {
		$acting_user = get_current_user_id();
		if ( $acting_user ) {
			set_transient( self::NOTICE_TRANSIENT_PREFIX . $acting_user, $status, MINUTE_IN_SECONDS );
		}
	}

	public static function render_notice() {
		$acting_user = get_current_user_id();
		if ( ! $acting_user ) {
			return;
		}

		$key    = self::NOTICE_TRANSIENT_PREFIX . $acting_user;
		$status = get_transient( $key );
		if ( ! $status ) {
			return;
		}
		delete_transient( $key );

		$messages = array(
			'enabled'       => array( 'success', __( 'Two-factor authentication has been enabled.', 'takumi-private-gate' ) ),
			'enable_failed' => array( 'error', __( 'The confirmation code was incorrect, so two-factor authentication could not be enabled.', 'takumi-private-gate' ) ),
			'disabled'      => array( 'success', __( 'Two-factor authentication has been disabled.', 'takumi-private-gate' ) ),
		);

		if ( ! isset( $messages[ $status ] ) ) {
			return;
		}

		list( $type, $text ) = $messages[ $status ];
		printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $type ), esc_html( $text ) );
	}

	/* ---------------------------------------------------------------------
	 * TOTP (RFC 6238) primitives — SHA1, 6 digits, 30s step.
	 * ------------------------------------------------------------------- */

	private static function generate_secret( $bytes = 20 ) {
		return self::base32_encode( random_bytes( $bytes ) );
	}

	private static function format_secret_for_display( $secret ) {
		return trim( chunk_split( $secret, 4, ' ' ) );
	}

	private static function get_otpauth_uri( $secret, $user_login ) {
		$site_name = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		$label     = rawurlencode( $site_name . ':' . $user_login );
		$issuer    = rawurlencode( $site_name );

		return "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}&algorithm=SHA1&digits=6&period=30";
	}

	private static function verify_totp( $secret, $code, $window = 1 ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( ! preg_match( '/^\d{6}$/', $code ) ) {
			return false;
		}

		$timeslice = (int) floor( time() / 30 );

		for ( $offset = -$window; $offset <= $window; $offset++ ) {
			if ( hash_equals( self::totp_at( $secret, $timeslice + $offset ), $code ) ) {
				return true;
			}
		}
		return false;
	}

	private static function totp_at( $secret, $timeslice ) {
		$key    = self::base32_decode( $secret );
		$time   = pack( 'N*', 0 ) . pack( 'N*', $timeslice );
		$hash   = hash_hmac( 'sha1', $time, $key, true );
		$offset = ord( substr( $hash, -1 ) ) & 0x0F;

		$truncated = (
			( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 ) |
			( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 ) |
			( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 ) |
			( ord( $hash[ $offset + 3 ] ) & 0xFF )
		);

		return str_pad( (string) ( $truncated % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	private static function base32_encode( $data ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$bits     = '';
		foreach ( str_split( $data ) as $byte ) {
			$bits .= str_pad( decbin( ord( $byte ) ), 8, '0', STR_PAD_LEFT );
		}

		$output = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$chunk   = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$output .= $alphabet[ bindec( $chunk ) ];
		}
		return $output;
	}

	private static function base32_decode( $secret ) {
		$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
		$secret   = strtoupper( preg_replace( '/[^A-Z2-7]/i', '', (string) $secret ) );

		$bits = '';
		foreach ( str_split( $secret ) as $char ) {
			$pos = strpos( $alphabet, $char );
			if ( false === $pos ) {
				continue;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}

		$bytes = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 !== strlen( $byte ) ) {
				continue;
			}
			$bytes .= chr( bindec( $byte ) );
		}
		return $bytes;
	}
}
