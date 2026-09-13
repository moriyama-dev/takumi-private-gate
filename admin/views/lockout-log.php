<?php
/**
 * Lockout list + login attempt log. Rendered by PrvGate_Admin::render_settings_page()
 * right after the settings form, so everything lives on one screen.
 */

defined( 'ABSPATH' ) || exit;

$prvgate_active_lockouts = PrvGate_Lockout::get_active_lockouts();
$prvgate_recent_entries  = PrvGate_Login_Logger::get_recent_entries( 100 );

$prvgate_result_labels = array(
	'success' => __( 'Success', 'takumi-private-gate' ),
	'failure' => __( 'Failure', 'takumi-private-gate' ),
	'lockout' => __( 'Lockout', 'takumi-private-gate' ),
);
?>
<hr />

<h2><?php esc_html_e( 'Currently locked-out IPs', 'takumi-private-gate' ); ?></h2>

<?php if ( empty( $prvgate_active_lockouts ) ) : ?>
	<p><?php esc_html_e( 'There are no currently locked-out IP addresses.', 'takumi-private-gate' ); ?></p>
<?php else : ?>
	<table class="widefat striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'IP address', 'takumi-private-gate' ); ?></th>
				<th><?php esc_html_e( 'Scheduled unlock time', 'takumi-private-gate' ); ?></th>
				<th><?php esc_html_e( 'Action', 'takumi-private-gate' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $prvgate_active_lockouts as $prvgate_lockout ) : ?>
			<tr>
				<td><?php echo esc_html( $prvgate_lockout['ip'] ); ?></td>
				<td>
					<?php
					echo esc_html(
						wp_date(
							get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
							$prvgate_lockout['until']
						)
					);
					?>
				</td>
				<td>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="prvgate_unlock_ip" />
						<input type="hidden" name="prvgate_option_name" value="<?php echo esc_attr( $prvgate_lockout['option_name'] ); ?>" />
						<?php wp_nonce_field( 'prvgate_unlock_ip_' . $prvgate_lockout['option_name'], 'prvgate_unlock_nonce' ); ?>
						<button type="submit" class="button">
							<?php esc_html_e( 'Unlock', 'takumi-private-gate' ); ?>
						</button>
					</form>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>

<h2><?php esc_html_e( 'Login attempt log (last 100)', 'takumi-private-gate' ); ?></h2>

<?php if ( empty( $prvgate_recent_entries ) ) : ?>
	<p><?php esc_html_e( 'There are no login attempts recorded yet.', 'takumi-private-gate' ); ?></p>
<?php else : ?>
	<table class="widefat striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'Date/time', 'takumi-private-gate' ); ?></th>
				<th><?php esc_html_e( 'IP address', 'takumi-private-gate' ); ?></th>
				<th><?php esc_html_e( 'Username', 'takumi-private-gate' ); ?></th>
				<th><?php esc_html_e( 'Result', 'takumi-private-gate' ); ?></th>
			</tr>
		</thead>
		<tbody>
		<?php foreach ( $prvgate_recent_entries as $prvgate_entry ) : ?>
			<tr>
				<td><?php echo esc_html( $prvgate_entry->attempted_at ); ?></td>
				<td><?php echo esc_html( $prvgate_entry->ip_address ); ?></td>
				<td><?php echo esc_html( $prvgate_entry->username ); ?></td>
				<td>
					<?php
					echo isset( $prvgate_result_labels[ $prvgate_entry->result ] )
						? esc_html( $prvgate_result_labels[ $prvgate_entry->result ] )
						: esc_html( $prvgate_entry->result );
					?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
<?php endif; ?>
