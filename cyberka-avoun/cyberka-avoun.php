<?php
/**
 * Plugin Name: Cyberka Avoun
 * Plugin URI: https://cyberka.com
 * Description: SSO Keycloak pour l'administration WordPress (wp-admin). Authentification via le serveur Cyberka.
 * Version: 1.0.0
 * Author: Cyberka
 * Author URI: https://cyberka.com
 * License: GPL v2 or later
 * Text Domain: cyberka-avoun
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Configuration Keycloak embarquée (serveur et realm).
 * Client ID et Client Secret sont configurés dans Réglages → Cyberka Avoun.
 */
define( 'CYBERKA_AVOUN_KEYCLOAK_BASE', 'https://ori.cyberka.com/auth' );
define( 'CYBERKA_AVOUN_REALM', 'cyberka' );

/** Option name pour les réglages (client_id + client_secret). */
define( 'CYBERKA_AVOUN_OPTION', 'cyberka_avoun_settings' );

/**
 * Retourne le Client ID (saisi dans le backoffice).
 */
function cyberka_avoun_get_client_id() {
	$opts = get_option( CYBERKA_AVOUN_OPTION, array() );
	return isset( $opts['client_id'] ) ? (string) $opts['client_id'] : '';
}

/**
 * Retourne le Client Secret (saisi dans le backoffice).
 */
function cyberka_avoun_get_client_secret() {
	$opts = get_option( CYBERKA_AVOUN_OPTION, array() );
	return isset( $opts['client_secret'] ) ? (string) $opts['client_secret'] : '';
}

/**
 * Retourne l'URL de redirection OAuth (callback).
 */
function cyberka_avoun_get_redirect_uri() {
	return add_query_arg(
		array( 'action' => 'cyberka_avoun_callback' ),
		wp_login_url()
	);
}

/**
 * URLs des endpoints Keycloak pour le realm configuré.
 */
function cyberka_avoun_get_endpoints() {
	$base = rtrim( CYBERKA_AVOUN_KEYCLOAK_BASE, '/' );
	$realm = CYBERKA_AVOUN_REALM;
	return array(
		'authorization' => $base . '/realms/' . $realm . '/protocol/openid-connect/auth',
		'token'         => $base . '/realms/' . $realm . '/protocol/openid-connect/token',
		'userinfo'      => $base . '/realms/' . $realm . '/protocol/openid-connect/userinfo',
		'logout'        => $base . '/realms/' . $realm . '/protocol/openid-connect/logout',
	);
}

/**
 * Rediriger vers Keycloak pour la connexion (écran de login WordPress).
 */
add_action( 'login_init', 'cyberka_avoun_login_init', 20 );

function cyberka_avoun_login_init() {
	$action = isset( $_GET['action'] ) ? $_GET['action'] : 'login';

	// Ne pas intercepter le callback ni la déconnexion
	if ( $action === 'cyberka_avoun_callback' || $action === 'logout' ) {
		return;
	}

	// Si déjà connecté et qu'il demande le formulaire de login, rediriger vers l'admin
	if ( is_user_logged_in() ) {
		wp_safe_redirect( admin_url() );
		exit;
	}

	// SSO désactivé si Client ID non configuré
	if ( cyberka_avoun_get_client_id() === '' ) {
		return;
	}

	// Démarrer le flux SSO : redirection vers Keycloak
	// State alphanumérique uniquement pour éviter les soucis d'encodage URL (+, %, etc.)
	$state = wp_generate_password( 32, false, false );
	set_transient( 'cyberka_avoun_state_' . $state, array( 'time' => time() ), 900 );
	$endpoints = cyberka_avoun_get_endpoints();
	$params = array(
		'response_type' => 'code',
		'client_id'     => cyberka_avoun_get_client_id(),
		'redirect_uri'  => cyberka_avoun_get_redirect_uri(),
		'scope'         => 'openid email profile',
		'state'         => $state,
	);
	$url = add_query_arg( $params, $endpoints['authorization'] );
	wp_redirect( $url );
	exit;
}

/**
 * Traiter le retour Keycloak (callback).
 */
add_action( 'login_form_cyberka_avoun_callback', 'cyberka_avoun_handle_callback' );

function cyberka_avoun_handle_callback() {
	$code  = isset( $_GET['code'] ) ? sanitize_text_field( wp_unslash( $_GET['code'] ) ) : '';
	$state = isset( $_GET['state'] ) ? sanitize_text_field( wp_unslash( $_GET['state'] ) ) : '';
	$error = isset( $_GET['error'] ) ? sanitize_text_field( wp_unslash( $_GET['error'] ) ) : '';

	if ( $error ) {
		$error_desc = isset( $_GET['error_description'] ) ? sanitize_text_field( wp_unslash( $_GET['error_description'] ) ) : $error;
		wp_die(
			esc_html( $error_desc ),
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 403 )
		);
	}

	if ( ! $code || ! $state ) {
		wp_die(
			__( 'Paramètres de retour Keycloak manquants.', 'cyberka-avoun' ),
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 400 )
		);
	}

	$stored = get_transient( 'cyberka_avoun_state_' . $state );
	delete_transient( 'cyberka_avoun_state_' . $state );
	if ( ! $stored ) {
		$login_url = wp_login_url();
		wp_die(
			__( 'Session invalide ou expirée. Veuillez réessayer.', 'cyberka-avoun' )
			. '<br><br><a href="' . esc_url( $login_url ) . '">' . esc_html__( 'Réessayer la connexion', 'cyberka-avoun' ) . '</a>'
			. '<br><br><em>' . esc_html__( 'Si le problème persiste, vérifiez que l’URL de redirection dans Keycloak correspond exactement à celle indiquée dans Réglages → Cyberka Avoun (même domaine, avec ou sans www).', 'cyberka-avoun' ) . '</em>',
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 400 )
		);
	}

	$endpoints = cyberka_avoun_get_endpoints();
	$body = array(
		'grant_type'    => 'authorization_code',
		'code'          => $code,
		'redirect_uri'  => cyberka_avoun_get_redirect_uri(),
		'client_id'     => cyberka_avoun_get_client_id(),
	);
	$secret = cyberka_avoun_get_client_secret();
	if ( $secret !== '' ) {
		$body['client_secret'] = $secret;
	}

	$response = wp_remote_post(
		$endpoints['token'],
		array(
			'body'    => $body,
			'timeout' => 15,
			'headers' => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
		)
	);

	if ( is_wp_error( $response ) ) {
		wp_die(
			$response->get_error_message(),
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 502 )
		);
	}

	$code_http = wp_remote_retrieve_response_code( $response );
	$body_res  = json_decode( wp_remote_retrieve_body( $response ), true );

	if ( $code_http !== 200 || empty( $body_res['access_token'] ) ) {
		$msg = isset( $body_res['error_description'] ) ? $body_res['error_description'] : __( 'Impossible d\'obtenir le jeton Keycloak.', 'cyberka-avoun' );
		wp_die(
			esc_html( $msg ),
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 502 )
		);
	}

	$userinfo_response = wp_remote_get(
		$endpoints['userinfo'],
		array(
			'timeout' => 10,
			'headers' => array(
				'Authorization' => 'Bearer ' . $body_res['access_token'],
			),
		)
	);

	if ( is_wp_error( $userinfo_response ) || wp_remote_retrieve_response_code( $userinfo_response ) !== 200 ) {
		wp_die(
			__( 'Impossible de récupérer les informations utilisateur Keycloak.', 'cyberka-avoun' ),
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 502 )
		);
	}

	$userinfo = json_decode( wp_remote_retrieve_body( $userinfo_response ), true );
	if ( empty( $userinfo['sub'] ) ) {
		wp_die(
			__( 'Réponse Keycloak invalide (identifiant utilisateur manquant).', 'cyberka-avoun' ),
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 502 )
		);
	}

	$wp_user = cyberka_avoun_get_or_create_user( $userinfo );
	if ( is_wp_error( $wp_user ) ) {
		wp_die(
			$wp_user->get_error_message(),
			__( 'Erreur d\'authentification', 'cyberka-avoun' ),
			array( 'response' => 403 )
		);
	}

	wp_clear_auth_cookie();
	wp_set_current_user( $wp_user->ID );
	wp_set_auth_cookie( $wp_user->ID, true );
	do_action( 'wp_login', $wp_user->user_login, $wp_user );

	wp_safe_redirect( admin_url() );
	exit;
}

/**
 * Trouve un utilisateur WordPress par email ou sub Keycloak, ou en crée un.
 */
function cyberka_avoun_get_or_create_user( $userinfo ) {
	$email = isset( $userinfo['email'] ) ? sanitize_email( $userinfo['email'] ) : '';
	$sub   = isset( $userinfo['sub'] ) ? sanitize_text_field( $userinfo['sub'] ) : '';
	$name  = isset( $userinfo['name'] ) ? sanitize_text_field( $userinfo['name'] ) : '';
	$preferred = isset( $userinfo['preferred_username'] ) ? sanitize_user( $userinfo['preferred_username'], true ) : '';

	if ( empty( $sub ) ) {
		return new WP_Error( 'cyberka_avoun_no_sub', __( 'Identifiant Keycloak manquant.', 'cyberka-avoun' ) );
	}

	$meta_key = 'cyberka_avoun_keycloak_sub';
	$existing = get_users( array(
		'meta_key'   => $meta_key,
		'meta_value' => $sub,
		'number'     => 1,
	) );

	if ( ! empty( $existing ) ) {
		return $existing[0];
	}

	if ( $email ) {
		$by_email = get_user_by( 'email', $email );
		if ( $by_email ) {
			update_user_meta( $by_email->ID, $meta_key, $sub );
			return $by_email;
		}
	}

	// Créer un nouvel utilisateur (réservé à l’admin : premier utilisateur ou rôles existants)
	$login = $preferred ?: sanitize_user( str_replace( array( ' ', '@' ), array( '_', '_' ), $name ), true );
	if ( empty( $login ) ) {
		$login = 'keycloak_' . preg_replace( '/[^a-z0-9_]/i', '_', substr( $sub, 0, 32 ) );
	}
	$login = cyberka_avoun_unique_login( $login );

	if ( empty( $email ) ) {
		$email = $login . '@cyberka-avoun.local';
	}

	$user_id = wp_insert_user( array(
		'user_login'   => $login,
		'user_email'   => $email,
		'user_pass'    => wp_generate_password( 32, true, true ),
		'display_name' => $name ?: $login,
		'first_name'   => isset( $userinfo['given_name'] ) ? sanitize_text_field( $userinfo['given_name'] ) : '',
		'last_name'    => isset( $userinfo['family_name'] ) ? sanitize_text_field( $userinfo['family_name'] ) : '',
		'role'         => 'administrator',
	) );

	if ( is_wp_error( $user_id ) ) {
		return $user_id;
	}

	update_user_meta( $user_id, $meta_key, $sub );
	return get_userdata( $user_id );
}

function cyberka_avoun_unique_login( $login ) {
	$base = $login;
	$i = 0;
	while ( get_user_by( 'login', $login ) ) {
		$i++;
		$login = $base . '_' . $i;
	}
	return $login;
}

/**
 * Déconnexion : rediriger vers Keycloak pour une déconnexion globale (optionnel).
 */
add_action( 'wp_logout', 'cyberka_avoun_logout_redirect', 1 );

function cyberka_avoun_logout_redirect() {
	$endpoints = cyberka_avoun_get_endpoints();
	$redirect  = admin_url( 'wp-login.php?loggedout=1' );
	$url = add_query_arg(
		array(
			'post_logout_redirect_uri' => $redirect,
			'client_id'               => cyberka_avoun_get_client_id(),
		),
		$endpoints['logout']
	);
	wp_safe_redirect( $url );
	exit;
}

/**
 * Page de réglages Cyberka Avoun (Client ID et Client Secret).
 */
add_action( 'admin_menu', 'cyberka_avoun_admin_menu' );
add_action( 'admin_init', 'cyberka_avoun_register_settings' );
add_action( 'admin_notices', 'cyberka_avoun_admin_notice' );
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), 'cyberka_avoun_plugin_action_links' );

function cyberka_avoun_plugin_action_links( $links ) {
	$url = admin_url( 'options-general.php?page=cyberka-avoun' );
	$links[] = '<a href="' . esc_url( $url ) . '">' . esc_html__( 'Réglages', 'cyberka-avoun' ) . '</a>';
	return $links;
}

function cyberka_avoun_admin_notice() {
	$screen = get_current_screen();
	if ( ! $screen || $screen->id === 'settings_page_cyberka-avoun' ) {
		return;
	}
	if ( cyberka_avoun_get_client_id() !== '' ) {
		return;
	}
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$url = admin_url( 'options-general.php?page=cyberka-avoun' );
	printf(
		'<div class="notice notice-warning is-dismissible"><p>%s <a href="%s">%s</a>.</p></div>',
		esc_html__( 'Cyberka Avoun : configurez le Client ID pour activer le SSO Keycloak.', 'cyberka-avoun' ),
		esc_url( $url ),
		esc_html__( 'Configurer', 'cyberka-avoun' )
	);
}

function cyberka_avoun_admin_menu() {
	add_options_page(
		__( 'Cyberka Avoun', 'cyberka-avoun' ),
		__( 'Cyberka Avoun', 'cyberka-avoun' ),
		'manage_options',
		'cyberka-avoun',
		'cyberka_avoun_settings_page'
	);
}

function cyberka_avoun_register_settings() {
	register_setting(
		'cyberka_avoun_settings_group',
		CYBERKA_AVOUN_OPTION,
		array(
			'type'              => 'array',
			'sanitize_callback' => 'cyberka_avoun_sanitize_settings',
		)
	);
}

function cyberka_avoun_sanitize_settings( $input ) {
	$out = array(
		'client_id'     => '',
		'client_secret' => '',
	);
	if ( ! is_array( $input ) ) {
		return $out;
	}
	if ( isset( $input['client_id'] ) && is_string( $input['client_id'] ) ) {
		$out['client_id'] = sanitize_text_field( $input['client_id'] );
	}
	if ( isset( $input['client_secret'] ) && is_string( $input['client_secret'] ) ) {
		$out['client_secret'] = $input['client_secret']; // Garder tel quel (peut contenir caractères spéciaux)
	}
	return $out;
}

function cyberka_avoun_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$opts = get_option( CYBERKA_AVOUN_OPTION, array() );
	$client_id     = isset( $opts['client_id'] ) ? $opts['client_id'] : '';
	$client_secret = isset( $opts['client_secret'] ) ? $opts['client_secret'] : '';
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<p><?php esc_html_e( 'Configurez les identifiants du client Keycloak pour le SSO du backoffice. Sans Client ID, la connexion WordPress classique reste disponible.', 'cyberka-avoun' ); ?></p>

		<form action="options.php" method="post">
			<?php settings_fields( 'cyberka_avoun_settings_group' ); ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row">
						<label for="cyberka_avoun_client_id"><?php esc_html_e( 'Client ID', 'cyberka-avoun' ); ?></label>
					</th>
					<td>
						<input type="text" name="<?php echo esc_attr( CYBERKA_AVOUN_OPTION ); ?>[client_id]" id="cyberka_avoun_client_id" value="<?php echo esc_attr( $client_id ); ?>" class="regular-text" autocomplete="off" />
						<p class="description"><?php printf( esc_html__( 'Identifiant du client configuré dans Keycloak (realm : %s).', 'cyberka-avoun' ), '<code>' . esc_html( CYBERKA_AVOUN_REALM ) . '</code>' ); ?></p>
					</td>
				</tr>
				<tr>
					<th scope="row">
						<label for="cyberka_avoun_client_secret"><?php esc_html_e( 'Client Secret', 'cyberka-avoun' ); ?></label>
					</th>
					<td>
						<input type="password" name="<?php echo esc_attr( CYBERKA_AVOUN_OPTION ); ?>[client_secret]" id="cyberka_avoun_client_secret" value="<?php echo esc_attr( $client_secret ); ?>" class="regular-text" autocomplete="off" />
						<p class="description"><?php esc_html_e( 'Secret du client (laisser vide si le client Keycloak est en mode public).', 'cyberka-avoun' ); ?></p>
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Enregistrer les réglages', 'cyberka-avoun' ) ); ?>
		</form>

		<hr />
		<p class="description">
			<?php
			printf(
				/* translators: %s: URL de callback */
				esc_html__( 'URL de redirection à déclarer dans Keycloak (Valid Redirect URIs) : %s', 'cyberka-avoun' ),
				'<code>' . esc_html( cyberka_avoun_get_redirect_uri() ) . '</code>'
			);
			?>
		</p>
	</div>
	<?php
}
