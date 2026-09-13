<?php
/**
 * Lets trusted IP addresses (single IPs or CIDR ranges) bypass both the
 * site-wide lockdown and the failed-login lockout entirely. Intended for an
 * admin's own home/office connection so they can never be locked out of
 * their own private site.
 */

defined( 'ABSPATH' ) || exit;

class PrvGate_Ip_Whitelist {

	public static function get_client_ip() {
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	/**
	 * Parses the newline/comma separated whitelist option into a flat array
	 * of trimmed, non-empty entries (single IPs or CIDR ranges).
	 */
	public static function get_entries() {
		$raw = (string) get_option( 'prvgate_ip_whitelist', '' );
		$raw = str_replace( ',', "\n", $raw );

		$entries = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) as $line ) {
			$line = trim( $line );
			if ( '' !== $line ) {
				$entries[] = $line;
			}
		}
		return $entries;
	}

	public static function is_whitelisted( $ip = null ) {
		if ( null === $ip ) {
			$ip = self::get_client_ip();
		}
		if ( '' === $ip ) {
			return false;
		}

		foreach ( self::get_entries() as $entry ) {
			if ( self::ip_matches( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	private static function ip_matches( $ip, $entry ) {
		if ( false === strpos( $entry, '/' ) ) {
			return hash_equals( $entry, $ip );
		}
		return self::cidr_matches( $ip, $entry );
	}

	/**
	 * Supports IPv4 and IPv6 CIDR ranges (e.g. 203.0.113.0/24, 2001:db8::/32).
	 */
	private static function cidr_matches( $ip, $cidr ) {
		list( $subnet, $bits ) = array_pad( explode( '/', $cidr, 2 ), 2, null );
		if ( null === $bits || ! is_numeric( $bits ) ) {
			return false;
		}

		$ip_bin     = @inet_pton( $ip );
		$subnet_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$bits      = (int) $bits;
		$max_bits  = strlen( $ip_bin ) * 8;
		if ( $bits < 0 || $bits > $max_bits ) {
			return false;
		}

		$bytes_full = intdiv( $bits, 8 );
		$bits_rem   = $bits % 8;

		if ( $bytes_full > 0 && substr( $ip_bin, 0, $bytes_full ) !== substr( $subnet_bin, 0, $bytes_full ) ) {
			return false;
		}

		if ( 0 === $bits_rem ) {
			return true;
		}

		$mask = chr( ( 0xFF << ( 8 - $bits_rem ) ) & 0xFF );
		return ( $ip_bin[ $bytes_full ] & $mask ) === ( $subnet_bin[ $bytes_full ] & $mask );
	}
}
