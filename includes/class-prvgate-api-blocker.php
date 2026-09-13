<?php
/**
 * Blocks unauthenticated access to the REST API and disables XML-RPC entirely.
 */

defined( 'ABSPATH' ) || exit;

class PrvGate_Api_Blocker {

	public static function init() {
		add_filter( 'rest_authentication_errors', array( __CLASS__, 'block_unauthenticated_rest_requests' ) );
		add_filter( 'xmlrpc_enabled', '__return_false' );
	}

	public static function block_unauthenticated_rest_requests( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}

		if ( ! is_user_logged_in() && ! PrvGate_Ip_Whitelist::is_whitelisted() ) {
			return new WP_Error(
				'prvgate_rest_forbidden',
				__( 'Authentication required.', 'takumi-private-gate' ),
				array( 'status' => 401 )
			);
		}

		return $result;
	}
}
