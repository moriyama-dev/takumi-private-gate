<?php
/**
 * Redirects unauthenticated visitors away from every front-end page.
 */

defined( 'ABSPATH' ) || exit;

class PrvGate_Access_Control {

	public static function init() {
		add_action( 'template_redirect', array( __CLASS__, 'maybe_redirect_to_login' ) );
	}

	public static function maybe_redirect_to_login() {
		if ( ! is_user_logged_in() && ! PrvGate_Ip_Whitelist::is_whitelisted() ) {
			auth_redirect();
		}
	}
}
