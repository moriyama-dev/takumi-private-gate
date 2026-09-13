<?php
/**
 * Settings screen markup. Rendered by PrvGate_Admin::render_settings_page().
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap prvgate-settings">
	<h1><?php esc_html_e( 'Private Gate', 'takumi-private-gate' ); ?></h1>
	<p><?php esc_html_e( 'Blocks site-wide access for logged-out visitors and disables the REST API and XML-RPC. You can change the allowed number of failed logins and the lockout duration here.', 'takumi-private-gate' ); ?></p>

	<form method="post" action="options.php">
		<?php
		settings_fields( PrvGate_Admin::OPTION_GROUP );
		do_settings_sections( PrvGate_Admin::PAGE_SLUG );
		submit_button();
		?>
	</form>
</div>
