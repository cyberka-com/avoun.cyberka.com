# Cyberka Avoun — SSO Keycloak pour wp-admin

Plugin WordPress qui active le SSO sur le backoffice (wp-admin) via le serveur Keycloak Cyberka (`avoun.cyberka.com/auth`). Aucune configuration dans WordPress : installer et activer le plugin pour que le SSO fonctionne.

## Installation

1. Copier le dossier `cyberka-avoun` dans `wp-content/plugins/`.
2. Dans **Tableau de bord → Extensions**, activer **Cyberka Avoun**.

Après activation, toute tentative d’accès à la page de connexion WordPress (`wp-login.php`) redirige vers Keycloak pour l’authentification.

## Configuration Keycloak (côté serveur)

Pour que le flux fonctionne, le client doit exister dans Keycloak avec les paramètres suivants (ou adapter les constantes en tête de `cyberka-avoun.php`) :

| Paramètre | Valeur par défaut dans le plugin |
|-----------|-----------------------------------|
| Serveur   | `https://avoun.cyberka.com/auth` |
| Realm     | `avoun` |
| Client ID | `wordpress-avoun` |
| Client Secret | Vide (client public) ou à renseigner dans le plugin |

Dans l’admin Keycloak pour le client `wordpress-avoun` :

- **Valid Redirect URIs** : ajouter l’URL de callback WordPress, par ex.  
  `https://VOTRE-SITE.com/wp-login.php?action=cyberka_avoun_callback`
- **Web Origins** : ajouter l’origine du site (ex. `https://VOTRE-SITE.com`) si nécessaire.
- **Access Type** : `public` si vous laissez `CYBERKA_AVOUN_CLIENT_SECRET` vide, sinon `confidential`.

## Comportement

- **Connexion** : accès à `wp-login.php` ou à `wp-admin` sans être connecté → redirection vers Keycloak → après authentification, création ou liaison du compte WordPress (par email ou `sub` Keycloak) puis redirection vers le tableau de bord.
- **Déconnexion** : déconnexion WordPress → redirection vers la déconnexion Keycloak puis retour sur la page de login WordPress.

## Personnalisation (optionnel)

Les paramètres Keycloak sont définis en tête de `cyberka-avoun.php` :

- `CYBERKA_AVOUN_KEYCLOAK_BASE` : URL de base du serveur Keycloak
- `CYBERKA_AVOUN_REALM` : nom du realm
- `CYBERKA_AVOUN_CLIENT_ID` : identifiant du client
- `CYBERKA_AVOUN_CLIENT_SECRET` : secret client (vide pour un client public)

Modifier ces constantes si votre realm ou client Keycloak diffère ; aucune interface de réglage n’est nécessaire dans WordPress.
